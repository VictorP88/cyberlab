"""
Agente de geração de cenário em múltiplas etapas, construído sobre
LangChain:

  1. CLASSIFICAR   — qual vulnerabilidade a descrição do usuário pede,
                       E qual VARIANTE de template usar — a primeira
                       decisão técnica de verdade do agente, não só de
                       texto (ex: SQLi de login+privesc vs SQLi de
                       busca, uma fase só)
  2. RECUPERAR      — busca exemplos validados por SIMILARIDADE
                       SEMÂNTICA (RAG vetorial via pgvector) com a
                       descrição do usuário, mais uma lista curada de
                       lições aprendidas nesse ambiente
  3. RASCUNHAR      — gera nome/dificuldade/dicas usando esse contexto
  4. AUTOCRITICAR   — revisa o próprio rascunho contra uma checklist
                       antes de devolver o resultado final

A infraestrutura e o código da aplicação vulnerável continuam
determinísticos (não vêm da LLM) — o agente decide QUAL template
determinístico usar (passo 1) e a "camada de narrativa" (passos 3-4).
"""
from __future__ import annotations

import json
import logging

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.db_ops import get_similar_knowledge_examples

logger = logging.getLogger("cyberlab.deep_agent")

SUPPORTED_VULNERABILITY_TYPES = ["sqli", "command_injection"]
SQLI_VARIANTS = ["login_bypass", "search_exfiltration"]
COMMAND_INJECTION_VARIANTS = ["network_tool", "log_viewer"]

LESSONS_LEARNED = """
Lições já aprendidas nesse ambiente (pra manter consistência de estilo):
- Variante "login_bypass" de sqli: tela de login PHP + MySQL, contorna
  autenticação com SQL Injection, com uma segunda fase de escalonamento
  de privilégio via SSH + sudo mal configurado. Mais completo, duas
  flags.
- Variante "search_exfiltration" de sqli: busca de produtos vulnerável
  a SQLi via parâmetro GET na URL, uma fase só, sem privesc. Mais
  direto, uma flag.
- Cenários de "command_injection" variante "network_tool": ferramenta de
  diagnóstico de rede (ping) em PHP, injeção via campo de formulário
  (POST), privesc via sudoers mal configurado.
- Cenários de "command_injection" variante "log_viewer": visualizador de
  logs em PHP, injeção via parâmetro na URL (GET), privesc via bit SUID
  mal configurado — mecanismo diferente do sudoers.
- As dicas devem guiar o raciocínio sem entregar a flag literal — nunca
  inclua o valor exato da flag ou senha nas dicas.
"""


class ScenarioFlavor(BaseModel):
    name: str
    difficulty: str = Field(pattern="^(easy|medium|hard)$")
    hints: list[str]


def _get_llm() -> ChatOllama:
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        temperature=0.3,
        format="json",
    )


async def _classify_scenario(description: str) -> tuple[str, str]:
    """
    Passo 1: decide o tipo de vulnerabilidade E, se for sqli, qual
    VARIANTE de template determinístico usar. Essa é a primeira decisão
    técnica de verdade do agente — escolhe entre infraestruturas
    diferentes, não só palavras diferentes.
    """
    system = (
        "Você classifica pedidos de cenário de cibersegurança. Responda "
        "APENAS com JSON: "
        '{"vulnerability_type": "sqli"|"command_injection", "variant": "..."}\n\n'
        "Tipos de vulnerabilidade:\n"
        "- sqli: login, autenticação, banco de dados, SQL, busca, filtro\n"
        "- command_injection: execução de comandos, ping, RCE, shell, "
        "diagnóstico de rede\n\n"
        "Se vulnerability_type for 'sqli', escolha variant entre:\n"
        "- 'login_bypass': cenário com tela de login E escalonamento de "
        "privilégio depois (duas fases, mais completo e avançado)\n"
        "- 'search_exfiltration': cenário mais simples e direto, SQLi "
        "numa busca/filtro de produtos, sem fase de privesc (uma fase "
        "só, melhor pra iniciante)\n"
        "Use 'search_exfiltration' se o pedido mencionar busca, "
        "pesquisa, filtro, catálogo, ou pedir algo simples/iniciante/"
        "rápido. Caso contrário, ou se não tiver certeza, use "
        "'login_bypass' (é o padrão mais completo).\n\n"
        "Se vulnerability_type for 'command_injection', escolha variant "
        "entre:\n"
        "- 'network_tool': ferramenta de diagnóstico de rede (ping), "
        "injeção via formulário (POST)\n"
        "- 'log_viewer': visualizador de logs, injeção via parâmetro na "
        "URL (GET)\n"
        "Use 'log_viewer' se o pedido mencionar log, arquivo, URL, "
        "parâmetro GET, ou visualização/consulta. Caso contrário, use "
        "'network_tool' (é o padrão)."
    )
    llm = _get_llm()
    response = await llm.ainvoke([("system", system), ("human", description)])
    try:
        data = json.loads(response.content)
        vuln_type = data.get("vulnerability_type", "sqli")
        variant = data.get("variant", "login_bypass")
    except (json.JSONDecodeError, AttributeError):
        vuln_type, variant = "sqli", "login_bypass"

    if vuln_type not in SUPPORTED_VULNERABILITY_TYPES:
        vuln_type = "sqli"
    if vuln_type == "sqli" and variant not in SQLI_VARIANTS:
        variant = "login_bypass"
    if vuln_type == "command_injection" and variant not in COMMAND_INJECTION_VARIANTS:
        variant = "network_tool"

    return vuln_type, variant


async def _retrieve_context(description: str, vulnerability_type: str) -> str:
    """Passo 2 (RAG vetorial): busca exemplos validados por SIMILARIDADE
    SEMÂNTICA com a descrição do usuário, não só por tipo+data. Se ainda
    não houver exemplos (ou o embedding falhar), a função já cai pro
    fallback sozinha — aqui só formatamos o resultado."""
    examples = await get_similar_knowledge_examples(description, vulnerability_type, limit=3)
    if not examples:
        examples_text = "(ainda não há exemplos validados por usuários pra esse tipo — sem problema, use seu melhor julgamento)"
    else:
        lines = []
        for ex in examples:
            hints_preview = "; ".join(ex["hints"][:2])
            lines.append(f"- \"{ex['description']}\" (dificuldade: {ex['difficulty']}) — dicas usadas: {hints_preview}")
        examples_text = "\n".join(lines)

    return f"{LESSONS_LEARNED}\n\nExemplos parecidos já resolvidos por usuários de verdade:\n{examples_text}"


async def _draft_flavor(description: str, vulnerability_type: str, variant: str, context: str) -> ScenarioFlavor:
    """Passo 3: rascunha nome/dificuldade/dicas usando o contexto recuperado."""
    system = (
        "Você cria a 'narrativa' de um cenário de treinamento em "
        "cibersegurança. A infraestrutura e o código vulnerável JÁ ESTÃO "
        "PRONTOS e são fixos — sua única tarefa é escolher um nome curto, "
        "uma dificuldade (easy/medium/hard) e até 3 dicas progressivas. "
        f"O tipo de vulnerabilidade já foi decidido como '{vulnerability_type}' "
        f"(variante '{variant}').\n\n"
        f"{context}\n\n"
        "IMPORTANTE: escreva o nome e as dicas em PORTUGUÊS DO BRASIL, "
        "sempre — nunca em inglês, mesmo que os exemplos acima estejam "
        "em outro idioma.\n\n"
        "Responda APENAS com JSON: "
        '{"name": "...", "difficulty": "easy|medium|hard", "hints": ["...", "...", "..."]}'
    )
    llm = _get_llm()
    response = await llm.ainvoke([("system", system), ("human", description)])
    data = json.loads(response.content)
    return ScenarioFlavor(**data)


async def _self_critique(flavor: ScenarioFlavor, vulnerability_type: str) -> ScenarioFlavor:
    """Passo 4: o agente revisa o próprio rascunho contra uma checklist
    antes de finalizar."""
    system = (
        "Revise este rascunho de cenário contra a checklist:\n"
        "1. As dicas NÃO podem conter senha, flag, ou qualquer valor "
        "literal secreto — só orientação de raciocínio.\n"
        "2. O nome deve ser curto (até 4 palavras).\n"
        "3. A dificuldade deve fazer sentido pro tipo de vulnerabilidade "
        f"'{vulnerability_type}'.\n"
        "4. Nome e dicas precisam estar em PORTUGUÊS DO BRASIL — se "
        "algo estiver em inglês, traduz antes de devolver.\n"
        "Se o rascunho já está bom, devolva ele exatamente igual. Se "
        "achar problema, corrija. Responda APENAS com o mesmo formato "
        'JSON: {"name": "...", "difficulty": "...", "hints": [...]}'
    )
    draft_json = flavor.model_dump_json()
    llm = _get_llm()
    try:
        response = await llm.ainvoke([("system", system), ("human", draft_json)])
        data = json.loads(response.content)
        return ScenarioFlavor(**data)
    except Exception:  # noqa: BLE001
        logger.warning("Autocrítica do agente falhou, mantendo rascunho original")
        return flavor


async def generate_scenario_with_agent(description: str) -> dict:
    """Orquestra as 4 etapas e devolve o resultado final."""
    vulnerability_type, variant = await _classify_scenario(description)
    context = await _retrieve_context(description, vulnerability_type)
    draft = await _draft_flavor(description, vulnerability_type, variant, context)
    final = await _self_critique(draft, vulnerability_type)

    return {
        "vulnerability_type": vulnerability_type,
        "variant": variant,
        "name": final.name,
        "difficulty": final.difficulty,
        "hints": final.hints,
    }
