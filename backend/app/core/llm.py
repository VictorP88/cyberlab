"""
Ponte com a LLM local (Mistral via Ollama, através do LangChain).

Fase 1 (MVP): a LLM recebe uma descrição em linguagem natural do cenário
desejado e retorna um JSON estruturado (ScenarioSpec) que o orquestrador
usa para decidir qual imagem Docker subir e com quais parâmetros.

Fase 2 (futuro, já prevista no roadmap): RAG indexando CVEs/writeups reais
para enriquecer a geração. Fase 3: fine-tuning num modelo menor com dados
sintéticos de domínio.
"""
from __future__ import annotations

import json

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.spec_validator import validate_and_repair

SYSTEM_PROMPT = """Você é um gerador de cenários de treinamento em cibersegurança.
Dada uma descrição em linguagem natural, responda APENAS com um JSON válido,
sem markdown, sem texto adicional, no seguinte formato:

{
  "name": "nome curto do cenário",
  "base_image": "imagem docker base sugerida (ex: python:3.12-slim, node:20-alpine)",
  "vulnerability_type": "categoria (ex: sqli, priv_esc, ssrf, misconfig)",
  "difficulty": "easy | medium | hard",
  "setup_commands": ["lista de comandos shell para configurar a vulnerabilidade"],
  "flag_location": "caminho onde a flag deve ficar",
  "hints": ["lista de até 3 dicas progressivas"]
}

REGRA IMPORTANTE sobre base_image: use APENAS imagens base ativamente
mantidas, com repositórios de pacotes funcionais. Prefira:
- debian:12-slim ou debian:bookworm-slim (NÃO debian:10/buster, EOL)
- ubuntu:22.04 ou ubuntu:24.04 (NÃO ubuntu:18.04 ou anteriores)
- alpine:latest ou alpine:3.20
- python:3.12-slim, node:20-slim (quando o cenário for de aplicação web)
Nunca sugira uma imagem cujo codinome de distro já tenha atingido EOL.

REGRA IMPORTANTE sobre setup_commands e serviços: os comandos rodam dentro
de um container Docker, que NÃO tem systemd/init rodando. Instalar um
pacote (apt-get install) NUNCA inicia o serviço automaticamente, ao
contrário de uma VM tradicional. Portanto:
- Se o cenário precisa de um banco de dados, instale o pacote SERVIDOR
  completo (ex: "mysql-server" ou "mariadb-server", nunca só o "-client")
  e inclua um comando explícito para iniciar o serviço em background,
  por exemplo: "service mysql start" ou "service mariadb start".
- Da mesma forma, para Apache: inclua "service apache2 start" após a
  instalação, já que ele também não inicia sozinho.
- Sempre coloque os comandos de start DEPOIS da instalação e ANTES de
  qualquer comando que dependa do serviço (ex: antes de rodar "mysql -e").

REGRA IMPORTANTE sobre acesso remoto ao banco de dados: o alvo e o
atacante são containers DIFERENTES na mesma rede — "acessível" significa
acessível PELA REDE, não só localmente dentro do próprio container. Por
padrão, MySQL/MariaDB só escuta em 127.0.0.1 e o usuário root só aceita
conexão de 'localhost', então mesmo com o serviço rodando, uma conexão de
outro container é recusada. Sempre que o cenário envolver acesso a um
banco de dados via rede, inclua nos setup_commands, NESTA ORDEM, depois
de instalar e iniciar o serviço:
  1. "sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf"
  2. "service mysql restart"
  3. um comando "mysql -e" criando um usuário que aceita conexão remota,
     por exemplo: "mysql -e \"CREATE USER 'root'@'%' IDENTIFIED BY 'SENHA'; GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'; FLUSH PRIVILEGES;\""
     (escolha uma senha simples e inclua nas hints, já que isso faz parte
     do exercício de descoberta do usuário/senha).

REGRA IMPORTANTE sobre phpMyAdmin: o pacote "phpmyadmin" pergunta, via
debconf, qual servidor web configurar automaticamente. Em modo
não-interativo essa pergunta nunca é respondida, então o Apache NUNCA
fica ciente do phpMyAdmin sozinho — a instalação "funciona" mas a URL
/phpmyadmin/ retorna 404. Sempre que instalar "phpmyadmin", inclua
DEPOIS da instalação e do "service apache2 start":
  "ln -sf /etc/phpmyadmin/apache.conf /etc/apache2/conf-available/phpmyadmin.conf"
  "a2enconf phpmyadmin"
  "service apache2 reload"
"""


class ScenarioSpec(BaseModel):
    name: str
    base_image: str
    vulnerability_type: str
    difficulty: str = Field(pattern="^(easy|medium|hard)$")
    setup_commands: list[str]
    flag_location: str
    hints: list[str]


def _get_llm() -> ChatOllama:
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        temperature=0.2,
        format="json",
    )


async def generate_scenario_spec(description: str) -> ScenarioSpec:
    llm = _get_llm()
    messages = [
        ("system", SYSTEM_PROMPT),
        ("human", description),
    ]
    response = await llm.ainvoke(messages)
    raw = response.content

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM retornou JSON inválido: {raw!r}") from exc

    spec = ScenarioSpec(**data)

    # Configura o proxy de cache do APT como PRIMEIRO comando, antes de
    # qualquer apt-get. Instalações repetidas do mesmo pacote passam a
    # vir do cache local em vez de rebaixar da internet toda vez.
    proxy_cmd = (
        'echo \'Acquire::http::Proxy "http://'
        f"{settings.apt_cache_host}:{settings.apt_cache_port}"
        '";\' > /etc/apt/apt.conf.d/01proxy'
    )
    has_apt = any(
        "apt-get" in c.lower() or "apt install" in c.lower() for c in spec.setup_commands
    )
    if has_apt:
        spec.setup_commands = [proxy_cmd] + spec.setup_commands

    spec.setup_commands, _repair_notes = validate_and_repair(spec.setup_commands)
    return spec
