"""
Agente de geração de cenário em múltiplas etapas, construído sobre
LangChain:

  1. CLASSIFICAR   — tipo de vulnerabilidade + VARIANTE + DIFICULDADE,
                       todos decididos juntos aqui. São escolhas
                       técnicas de verdade (templates determinísticos
                       diferentes), não rótulos que a LLM inventa depois
                       sem relação com o cenário real.
  2. RECUPERAR      — busca exemplos validados por SIMILARIDADE
                       SEMÂNTICA (RAG vetorial via pgvector)
  3. RASCUNHAR      — gera nome e dicas usando esse contexto (a
                       dificuldade já está decidida, só orienta o tom
                       das dicas)
  4. AUTOCRITICAR   — revisa o próprio rascunho contra uma checklist

A infraestrutura e o código da aplicação vulnerável continuam
determinísticos (não vêm da LLM) — o agente decide QUAL template
determinístico usar (tipo + variante + dificuldade, no passo 1) e a
"camada de narrativa" (nome + dicas, nos passos 3-4).
"""
from __future__ import annotations

import json
import logging

from langchain_ollama import ChatOllama
from pydantic import BaseModel

from app.core.config import settings
from app.core.db_ops import get_similar_knowledge_examples

logger = logging.getLogger("cyberlab.deep_agent")

SUPPORTED_VULNERABILITY_TYPES = ["sqli", "command_injection"]
SQLI_VARIANTS = ["login_bypass", "search_exfiltration"]
COMMAND_INJECTION_VARIANTS = ["network_tool", "log_viewer"]
DIFFICULTIES = ["easy", "medium", "hard"]

LESSONS_LEARNED = """
Lições já aprendidas nesse ambiente (pra manter consistência de estilo):
- Cenários de "sqli" variante "login_bypass": tela de login PHP + MySQL,
  com segunda fase de escalonamento de privilégio via SSH + sudo mal
  configurado.
- Cenários de "sqli" variante "search_exfiltration": busca de produtos
  vulnerável via parâmetro GET, uma fase só.
- Cenários de "command_injection" variante "network_tool": ferramenta de
  diagnóstico de rede (ping), injeção via formulário (POST), privesc via
  sudoers.
- Cenários de "command_injection" variante "log_viewer": visualizador de
  logs, injeção via parâmetro na URL (GET), privesc via SUID.
- Dificuldade "easy": erro/saída do comando sempre visível na tela —
  guia direto a exploração.
- Dificuldade "medium": sem erro/saída direta, mas ainda com algum sinal
  (dado extraído via UNION, ou tempo de resposta perceptível).
- Dificuldade "hard": totalmente cego — só um oráculo booleano (SQLi) ou
  execução assíncrona que força exfiltração fora de banda (Command
  Injection). Exige técnica mais avançada (ex: sqlmap com
  --technique=B, ou um listener `nc` esperando conexão de saída).
- As dicas devem guiar o raciocínio sem entregar a flag literal — nunca
  inclua o valor exato da flag ou senha nas dicas.
"""


class ScenarioFlavor(BaseModel):
    name: str
    hints: list[str]


def _get_llm() -> ChatOllama:
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        temperature=0.3,
        format="json",
    )


async def _classify_scenario(description: str) -> tuple[str, str, str]:
    """
    Passo 1: decide tipo de vulnerabilidade, variante E dificuldade —
    as três decisões técnicas de verdade do agente, escolhendo entre
    infraestruturas/comportamentos diferentes, não só palavras.
    """
    system = (
        "Você classifica pedidos de cenário de cibersegurança. Responda "
        "APENAS com JSON: "
        '{"vulnerability_type": "sqli"|"command_injection", '
        '"variant": "...", "difficulty": "easy"|"medium"|"hard"}\n\n'
        "Tipos de vulnerabilidade:\n"
        "- sqli: login, autenticação, banco de dados, SQL, busca, filtro\n"
        "- command_injection: execução de comandos, ping, RCE, shell, "
        "log, diagnóstico de rede\n\n"
        "Se vulnerability_type for 'sqli', escolha variant entre:\n"
        "- 'login_bypass': tela de login + escalonamento de privilégio "
        "(mais completo)\n"
        "- 'search_exfiltration': busca/filtro de produtos, uma fase só "
        "(mais direto)\n"
        "Use 'search_exfiltration' se mencionar busca, pesquisa, filtro, "
        "catálogo. Caso contrário, 'login_bypass'.\n\n"
        "Se vulnerability_type for 'command_injection', escolha variant "
        "entre:\n"
        "- 'network_tool': diagnóstico de rede (ping), formulário POST\n"
        "- 'log_viewer': visualizador de logs, parâmetro na URL (GET)\n"
        "Use 'log_viewer' se mencionar log, arquivo, URL, parâmetro GET. "
        "Caso contrário, 'network_tool'.\n\n"
        "Escolha difficulty com base no pedido:\n"
        "- 'easy': se mencionar iniciante, fácil, básico, primeira vez, "
        "aprendendo\n"
        "- 'hard': se mencionar avançado, difícil, blind, cego, "
        "especialista, desafiador\n"
        "- 'medium': caso contrário, ou se não tiver certeza (é o "
        "padrão)."
    )
    llm = _get_llm()
    response = await llm.ainvoke([("system", system), ("human", description)])
    try:
        data = json.loads(response.content)
        vuln_type = data.get("vulnerability_type", "sqli")
        variant = data.get("variant", "login_bypass")
        difficulty = data.get("difficulty", "medium")
    except (json.JSONDecodeError, AttributeError):
        vuln_type, variant, difficulty = "sqli", "login_bypass", "medium"

    if vuln_type not in SUPPORTED_VULNERABILITY_TYPES:
        vuln_type = "sqli"
    if vuln_type == "sqli" and variant not in SQLI_VARIANTS:
        variant = "login_bypass"
    if vuln_type == "command_injection" and variant not in COMMAND_INJECTION_VARIANTS:
        variant = "network_tool"
    if difficulty not in DIFFICULTIES:
        difficulty = "medium"

    return vuln_type, variant, difficulty


async def _retrieve_context(description: str, vulnerability_type: str) -> str:
    """Passo 2 (RAG vetorial): busca exemplos validados por SIMILARIDADE
    SEMÂNTICA com a descrição do usuário."""
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


async def _draft_flavor(
    description: str, vulnerability_type: str, variant: str, difficulty: str, context: str
) -> ScenarioFlavor:
    """Passo 3: rascunha nome e dicas usando o contexto recuperado. A
    dificuldade já foi decidida no passo 1 — aqui só orienta o TOM das
    dicas (mais diretas em easy, mais conceituais em hard)."""
    system = (
        "Você cria a 'narrativa' de um cenário de treinamento em "
        "cibersegurança. A infraestrutura e o código vulnerável JÁ ESTÃO "
        "PRONTOS e são fixos — sua única tarefa é escolher um nome curto "
        "e até 3 dicas progressivas. "
        f"Tipo: '{vulnerability_type}', variante '{variant}', "
        f"dificuldade '{difficulty}' (já decidida, não mude).\n\n"
        f"Nas dicas: se dificuldade for 'easy', pode ser bem direto. Se "
        f"'medium', mais conceitual. Se 'hard', só aponte a categoria da "
        f"técnica (ex: 'isso é cego, sem retorno direto') sem detalhar "
        f"o passo a passo.\n\n"
        f"{context}\n\n"
        "IMPORTANTE: escreva o nome e as dicas em PORTUGUÊS DO BRASIL, "
        "sempre — nunca em inglês.\n\n"
        "Responda APENAS com JSON: "
        '{"name": "...", "hints": ["...", "...", "..."]}'
    )
    llm = _get_llm()
    response = await llm.ainvoke([("system", system), ("human", description)])
    data = json.loads(response.content)
    return ScenarioFlavor(**data)


async def _self_critique(flavor: ScenarioFlavor, vulnerability_type: str) -> ScenarioFlavor:
    """Passo 4: o agente revisa o próprio rascunho contra uma checklist."""
    system = (
        "Revise este rascunho de cenário contra a checklist:\n"
        "1. As dicas NÃO podem conter senha, flag, ou qualquer valor "
        "literal secreto — só orientação de raciocínio.\n"
        "2. O nome deve ser curto (até 4 palavras).\n"
        "3. Nome e dicas precisam estar em PORTUGUÊS DO BRASIL — se "
        "algo estiver em inglês, traduz antes de devolver.\n"
        "Se o rascunho já está bom, devolva ele exatamente igual. Se "
        "achar problema, corrija. Responda APENAS com o mesmo formato "
        'JSON: {"name": "...", "hints": [...]}'
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
    vulnerability_type, variant, difficulty = await _classify_scenario(description)
    context = await _retrieve_context(description, vulnerability_type)
    draft = await _draft_flavor(description, vulnerability_type, variant, difficulty, context)
    final = await _self_critique(draft, vulnerability_type)

    return {
        "vulnerability_type": vulnerability_type,
        "variant": variant,
        "difficulty": difficulty,
        "name": final.name,
        "hints": final.hints,
    }
