# CyberLab

Plataforma de treinamento em cibersegurança no estilo "Hack The Box": você
descreve um cenário em linguagem natural, e a plataforma monta
automaticamente um ambiente vulnerável real e isolado — uma máquina alvo
vulnerável e uma máquina atacante equipada com ferramentas de pentest,
acessível por um terminal no navegador.

A geração de cada cenário é feita por um agente construído sobre
**LangChain**, rodando um modelo de linguagem **local** (Mistral 7B via
Ollama — sem nenhuma API externa paga).

## Stack

- **Backend**: FastAPI (Python 3.12), SQLAlchemy async, PostgreSQL +
  pgvector, Valkey, Docker SDK, LangChain
- **LLM**: Mistral 7B (narrativa) + nomic-embed-text (embeddings pro RAG),
  ambos via Ollama local
- **Frontend**: Next.js 14, xterm.js, identidade visual 8-bit
- **Orquestração**: Docker Engine nativo (WSL2/Linux), sem Docker Desktop

## Cenários disponíveis

- **SQL Injection** — duas variantes:
  - `login_bypass`: bypass de autenticação + escalonamento de privilégio
    (SSH + sudoers mal configurado)
  - `search_exfiltration`: exfiltração via busca vulnerável (GET), uma
    fase só
- **Command Injection** — ferramenta de diagnóstico de rede vulnerável,
  com fase de escalonamento de privilégio via `sudo` mal configurado

## Arquitetura do agente (geração de cenário)

Cada cenário passa por uma cadeia de 4 etapas, não uma chamada única de LLM:

1. **Classificar** — tipo de vulnerabilidade + variante de template
2. **Recuperar (RAG vetorial)** — busca exemplos já resolvidos por
   usuários reais, por similaridade semântica (pgvector)
3. **Rascunhar** — nome, dificuldade, dicas
4. **Autocriticar** — revisão contra checklist antes de finalizar

A infraestrutura e o código da aplicação vulnerável em si **nunca** são
gerados pela LLM — são templates determinísticos em Python. Essa separação
é deliberada: deixar o modelo gerar comandos de shell livremente causou,
historicamente, uma classe inteira de bugs de confiabilidade.

## Rodando localmente

```bash
docker compose up -d --build
```

Primeira vez: baixa os modelos do Ollama e prepara a imagem da máquina
atacante:

```bash
docker exec cyberlab-ollama ollama pull mistral
docker exec cyberlab-ollama ollama pull nomic-embed-text
docker build -t cyberlab-attacker:latest ./attacker
```

A senha do usuário `admin` é gerada aleatoriamente na primeira subida e
aparece nos logs do backend uma única vez:

```bash
docker compose logs backend | grep -A2 "USUÁRIO ADMIN"
```

Acesse `http://localhost:3000`.

## Comandos úteis

```bash
# Recriar o banco do zero (quando o schema muda)
docker compose down
docker volume rm cyberlab-mvp_pg_data
docker compose up -d --build

# Limpar containers de cenário órfãos
docker container prune -f && docker network prune -f
```

## Roadmap

- Mais tipos de vulnerabilidade (XSS, Path Traversal/LFI)
- Multiusuário completo
- Painel de analytics como sinal de feedback automático pro agente
- **Cuca**: variante do gerador voltada a alimentar exercícios no
  Proxmox, para uso com o SACI
