# Cuca

Geração de VMs via IA pra alimentar exercícios cibernéticos no
**SACI**, usando **Proxmox VE** como infraestrutura de virtualização.

É a segunda vertente do projeto CyberLab — a primeira (`backend/` +
`frontend/`, na raiz do repositório) é a plataforma de treinamento
individual (estilo Hack The Box, containers Docker). O Cuca resolve um
problema diferente: gerar **VMs prontas**, via API, pra alimentar
exercícios já existentes no SACI/Proxmox — hoje montados manualmente
por um operador.

## Como funciona

Mesma filosofia do CyberLab: a LLM decide a "narrativa" (tipo de
cenário, dificuldade), a infraestrutura é sempre determinística — só
que aqui, em vez de `docker exec` + templates PHP, o mecanismo é
**cloud-init** + a API do Proxmox.

```
Imagem cloud oficial (baixada via API do Proxmox)
  → VM criada do zero via API
  → Disco importado
  → Drive de cloud-init anexado
  → Marcada como TEMPLATE
  → Clonada sob demanda
  → Configuração (usuário/senha/comandos) injetada via cloud-init
  → VM pronta, nome/tag reconhecíveis pro SACI usar
```

## Pré-requisitos

- Acesso VPN ao ambiente SACI (perfil `.ovpn`, fora deste repositório
  — nunca versionar arquivos de VPN nem credenciais)
- Usuário Proxmox com permissão de administração (`Victor@pve` ou
  equivalente)
- Python 3.10+ com `requests` instalado

## Peculiaridades da API do Proxmox (validadas contra o cluster real)

Documentadas em detalhe nos comentários de `proxmox_orchestrator.py`,
resumo rápido:

- Usar `requests` com `data=`/`params=` (nunca montar query string à
  mão) — evita o erro "duplicate key in comma-separated list property"
- Disco por **ID de volume** (`storage:caminho`), nunca caminho físico
  absoluto (`/mnt/pve/...`) — só `root@pam` pode usar caminho absoluto
- `net0` precisa do nome do modelo como **chave**:
  `virtio=MAC,bridge=vmbr0` — não `virtio,bridge=...` nem
  `model=virtio,...`
- Rede pode exigir **tag de VLAN** (`tag=N`) dependendo do ambiente —
  sem isso a interface fica "not attached to any bridge" mesmo com a
  bridge existindo
- `agent=1` precisa estar explícito na config pro guest agent responder
- **`DELETE` não aceita corpo** — parâmetros de exclusão vão na query
  string (`params=`), não no corpo (`data=`)

## Template validado

`cuca-template-debian13` (vmid `9000`, nó `pve-01-cige`, storage
`Storage`) — Debian 13 cloud image oficial, cloud-init configurado,
testado com clonagem + injeção de usuário/senha + boot completo.

## Uso

**Nunca** hardcode credenciais em arquivo versionado. Usa variáveis de
ambiente:

```bash
export PROXMOX_URL="https://172.16.2.211:8006"
export PROXMOX_NODE="pve-01-cige"
export PROXMOX_USER="Victor@pve"
export PROXMOX_PASSWORD="sua-senha-aqui"
```

```python
import os
from proxmox_orchestrator import ProxmoxOrchestrator

orch = ProxmoxOrchestrator(
    base_url=os.environ["PROXMOX_URL"],
    node=os.environ["PROXMOX_NODE"],
    username=os.environ["PROXMOX_USER"],
    password=os.environ["PROXMOX_PASSWORD"],
    storage="Storage",
    bridge="vmbr0",
    vlan_tag=40,
)

orch.spawn_configured_vm(
    template_vmid=9000,
    new_vmid=9010,
    name="cuca-exercicio-01",
    ciuser="aluno",
    cipassword="senha-gerada-na-hora",
    mac="BC:24:11:00:00:10",
)
```

## Roadmap

- [ ] Reaproveitar `deep_agent.py` do CyberLab pra decidir tipo de
      cenário e dificuldade
- [ ] Templates determinísticos de vulnerabilidade via cloud-init
      (equivalente ao `webapp_template.py`)
- [ ] Convenção final de nome/tag pra reconhecimento automático pelo SACI
- [ ] API própria (FastAPI) expondo geração sob demanda
