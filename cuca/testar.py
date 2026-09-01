"""
Script de teste manual do orquestrador — lê credenciais de variáveis de
ambiente, nunca hardcoded. Exemplo de uso:

    export PROXMOX_URL="https://172.16.2.211:8006"
    export PROXMOX_NODE="pve-01-cige"
    export PROXMOX_USER="Victor@pve"
    export PROXMOX_PASSWORD="sua-senha-aqui"
    python3 testar.py
"""
import logging
import os
import sys

logging.basicConfig(level=logging.INFO)

from proxmox_orchestrator import ProxmoxOrchestrator

REQUIRED_ENV_VARS = ["PROXMOX_URL", "PROXMOX_NODE", "PROXMOX_USER", "PROXMOX_PASSWORD"]
missing = [v for v in REQUIRED_ENV_VARS if v not in os.environ]
if missing:
    print(f"Faltam variáveis de ambiente: {', '.join(missing)}")
    print("Veja o README.md do Cuca pra instruções de configuração.")
    sys.exit(1)

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
    new_vmid=9002,
    name="cuca-teste-orchestrator",
    ciuser="cuca",
    cipassword=os.environ.get("CUCA_TEST_VM_PASSWORD", "TrocarEssaSenha2026!"),
    mac="BC:24:11:00:00:02",
)
print("VM 9002 criada e configurada com sucesso!")
