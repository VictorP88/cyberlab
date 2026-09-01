"""
proxmox_orchestrator.py — camada de orquestração do Cuca, espelhando a
interface do orchestrator.py (Docker) do CyberLab, mas criando/clonando
VMs reais no Proxmox em vez de containers.

Peculiaridades da API do Proxmox descobertas e VALIDADAS numa sessão
real de testes contra o cluster SACI (não suposição):

  - Usar `requests` com `data=dict` (não montar a query string à mão)
    — isso urlencode os valores automaticamente, evitando o erro
    "duplicate key in comma-separated list property" que aparece
    quando um valor com ':' '/' '=' vai sem codificação.
  - scsi/disco por ID DE VOLUME (`storage:caminho`), nunca caminho
    físico absoluto — só root@pam pode usar caminho absoluto
    ("Only root can pass arbitrary filesystem paths").
  - net0 precisa do nome do modelo como CHAVE, ex: `virtio=MAC,bridge=...`
    — nem `virtio,bridge=...` nem `model=virtio,...` funcionam nessa
    versão da API.
  - Interfaces de rede podem exigir tag de VLAN (`tag=N`) dependendo do
    ambiente — sem isso a interface fica "not attached to any bridge"
    mesmo com a bridge existindo e ativa.
  - `agent=1` precisa estar explícito na config pra guest agent
    responder (sem isso: "No QEMU guest agent configured").
  - Import de disco: `scsi0=STORAGE:0,import-from=STORAGE:caminho/arquivo`
    (0 = tamanho placeholder, o import-from define o conteúdo real).
  - Algumas chamadas PUT simples devolvem `{"data": null}` de forma
    SÍNCRONA (sem UPID) — não é erro, só não tem tarefa assíncrona pra
    acompanhar.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore[import]

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]

logger = logging.getLogger("cuca.proxmox_orchestrator")


class ProxmoxAPIError(RuntimeError):
    """Erro vindo da API do Proxmox — guarda a resposta crua pra debug."""

    def __init__(self, message: str, response_data: dict | None = None):
        super().__init__(message)
        self.response_data = response_data


@dataclass
class TaskResult:
    upid: str
    exitstatus: str | None
    log: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exitstatus == "OK"


class ProxmoxOrchestrator:
    """
    Uma instância por (cluster, credenciais). Reautentica sozinha se o
    ticket expirar no meio de uma sessão longa.
    """

    def __init__(
        self,
        base_url: str,
        node: str,
        username: str,
        password: str,
        storage: str = "Storage",
        bridge: str = "vmbr0",
        vlan_tag: int | None = None,
        verify_ssl: bool = False,
        request_timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.node = node
        self.username = username
        self.password = password
        self.storage = storage
        self.bridge = bridge
        self.vlan_tag = vlan_tag
        self.verify_ssl = verify_ssl
        self.request_timeout = request_timeout

        self._ticket: str | None = None
        self._csrf: str | None = None

    # ------------------------------------------------------------------
    # Autenticação
    # ------------------------------------------------------------------

    def _authenticate(self) -> None:
        resp = requests.post(
            f"{self.base_url}/api2/json/access/ticket",
            data={"username": self.username, "password": self.password},
            verify=self.verify_ssl,
            timeout=self.request_timeout,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        self._ticket = data["ticket"]
        self._csrf = data["CSRFPreventionToken"]
        logger.info("Autenticado no Proxmox como %s", self.username)

    def _ensure_authenticated(self) -> None:
        if self._ticket is None:
            self._authenticate()

    def _request(self, method: str, path: str, data: dict | None = None, retry_auth: bool = True) -> dict:
        self._ensure_authenticated()
        url = f"{self.base_url}/api2/json{path}"
        cookies = {"PVEAuthCookie": self._ticket}
        headers = {"CSRFPreventionToken": self._csrf} if method in ("POST", "PUT", "DELETE") else {}

        # GET e DELETE: parâmetros vão na query string. A API do Proxmox
        # rejeita corpo em requisições DELETE ("Unexpected content for
        # method 'DELETE'") — descoberto testando contra o cluster real.
        if method in ("GET", "DELETE"):
            resp = requests.request(
                method, url, params=data, cookies=cookies, headers=headers,
                verify=self.verify_ssl, timeout=self.request_timeout,
            )
        else:
            resp = requests.request(
                method, url, data=data, cookies=cookies, headers=headers,
                verify=self.verify_ssl, timeout=self.request_timeout,
            )

        # Ticket expirado no meio de uma sessão longa — reautentica uma
        # vez e tenta de novo, sem propagar o erro pro chamador.
        if resp.status_code == 401 and retry_auth:
            logger.warning("Ticket expirado, reautenticando")
            self._ticket = None
            self._authenticate()
            return self._request(method, path, data=data, retry_auth=False)

        try:
            payload = resp.json()
        except ValueError as exc:
            raise ProxmoxAPIError(f"Resposta não-JSON da API: {resp.text[:300]}") from exc

        if resp.status_code >= 400 or payload.get("errors"):
            raise ProxmoxAPIError(
                payload.get("message", f"Erro HTTP {resp.status_code}"), response_data=payload
            )

        return payload

    # ------------------------------------------------------------------
    # Tarefas assíncronas (UPID)
    # ------------------------------------------------------------------

    def wait_for_task(self, upid: str, timeout: int = 300, poll_interval: int = 3) -> TaskResult:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self._request("GET", f"/nodes/{self.node}/tasks/{upid}/status")["data"]
            if status.get("status") == "stopped":
                log_data = self._request("GET", f"/nodes/{self.node}/tasks/{upid}/log")["data"]
                log_lines = [entry["t"] for entry in log_data]
                return TaskResult(upid=upid, exitstatus=status.get("exitstatus"), log=log_lines)
            time.sleep(poll_interval)
        raise ProxmoxAPIError(f"Tarefa {upid} não terminou em {timeout}s (timeout)")

    # ------------------------------------------------------------------
    # Download de imagem pro storage
    # ------------------------------------------------------------------

    def download_image_to_storage(self, storage: str, url: str, filename: str) -> TaskResult:
        result = self._request(
            "POST",
            f"/nodes/{self.node}/storage/{storage}/download-url",
            data={"content": "import", "filename": filename, "url": url},
        )
        upid = result["data"]
        logger.info("Download de %s disparado (UPID %s)", filename, upid)
        return self.wait_for_task(upid, timeout=600)

    # ------------------------------------------------------------------
    # Ciclo de vida de VM — primitivas de baixo nível
    # ------------------------------------------------------------------

    def create_vm(self, vmid: int, name: str, memory: int = 2048, cores: int = 2, ostype: str = "l26") -> TaskResult:
        result = self._request(
            "POST",
            f"/nodes/{self.node}/qemu",
            data={
                "vmid": vmid, "name": name, "memory": memory, "cores": cores,
                "scsihw": "virtio-scsi-single", "ostype": ostype,
            },
        )
        return self.wait_for_task(result["data"])

    def set_network(self, vmid: int, mac: str, bridge: str | None = None, tag: int | None = None) -> None:
        bridge = bridge or self.bridge
        tag = tag if tag is not None else self.vlan_tag
        net_value = f"virtio={mac},bridge={bridge}"
        if tag is not None:
            net_value += f",tag={tag}"
        self._request("PUT", f"/nodes/{self.node}/qemu/{vmid}/config", data={"net0": net_value})

    def import_disk(self, vmid: int, source_volume: str, disk_slot: str = "scsi0") -> TaskResult:
        """source_volume: ID de volume Proxmox (ex: 'cephfs:import/arquivo.qcow2'),
        NUNCA um caminho físico absoluto."""
        result = self._request(
            "PUT",
            f"/nodes/{self.node}/qemu/{vmid}/config",
            data={disk_slot: f"{self.storage}:0,import-from={source_volume}"},
        )
        # Pode devolver UPID (assíncrono) ou {"data": null} (síncrono) —
        # trata os dois casos.
        upid = result.get("data")
        if upid:
            return self.wait_for_task(upid, timeout=300)
        return TaskResult(upid="", exitstatus="OK")

    def attach_cloudinit_drive(self, vmid: int, disk_slot: str = "ide2") -> None:
        self._request(
            "PUT", f"/nodes/{self.node}/qemu/{vmid}/config",
            data={disk_slot: f"{self.storage}:cloudinit"},
        )

    def set_boot_order(self, vmid: int, order: str = "scsi0") -> None:
        self._request("PUT", f"/nodes/{self.node}/qemu/{vmid}/config", data={"boot": f"order={order}"})

    def enable_guest_agent(self, vmid: int) -> None:
        self._request("PUT", f"/nodes/{self.node}/qemu/{vmid}/config", data={"agent": 1})

    def mark_as_template(self, vmid: int) -> TaskResult:
        result = self._request("POST", f"/nodes/{self.node}/qemu/{vmid}/template")
        return self.wait_for_task(result["data"])

    def clone_vm(self, source_vmid: int, new_vmid: int, name: str, full: bool = True) -> TaskResult:
        result = self._request(
            "POST",
            f"/nodes/{self.node}/qemu/{source_vmid}/clone",
            data={"newid": new_vmid, "name": name, "full": 1 if full else 0},
        )
        return self.wait_for_task(result["data"], timeout=600)

    def configure_cloudinit(
        self, vmid: int, ciuser: str | None = None, cipassword: str | None = None,
        ipconfig0: str = "ip=dhcp", sshkeys: str | None = None,
    ) -> None:
        data: dict = {"ipconfig0": ipconfig0}
        if ciuser:
            data["ciuser"] = ciuser
        if cipassword:
            data["cipassword"] = cipassword
        if sshkeys:
            data["sshkeys"] = sshkeys
        self._request("PUT", f"/nodes/{self.node}/qemu/{vmid}/config", data=data)

    def start_vm(self, vmid: int) -> TaskResult:
        result = self._request("POST", f"/nodes/{self.node}/qemu/{vmid}/status/start")
        return self.wait_for_task(result["data"])

    def stop_vm(self, vmid: int) -> TaskResult:
        result = self._request("POST", f"/nodes/{self.node}/qemu/{vmid}/status/stop")
        return self.wait_for_task(result["data"])

    def get_vm_config(self, vmid: int) -> dict:
        return self._request("GET", f"/nodes/{self.node}/qemu/{vmid}/config")["data"]

    def get_vm_status(self, vmid: int) -> dict:
        return self._request("GET", f"/nodes/{self.node}/qemu/{vmid}/status/current")["data"]

    def get_vm_ip_via_agent(self, vmid: int) -> str | None:
        """Só funciona se a imagem tiver qemu-guest-agent instalado E
        agent=1 estar habilitado na config. Retorna None em vez de
        lançar erro se o agente não estiver disponível — chamador
        decide se quer outro método de descobrir o IP."""
        try:
            data = self._request("GET", f"/nodes/{self.node}/qemu/{vmid}/agent/network-get-interfaces")["data"]
        except ProxmoxAPIError:
            return None
        for iface in data.get("result", []):
            if iface.get("name") == "lo":
                continue
            for addr in iface.get("ip-addresses", []):
                if addr.get("ip-address-type") == "ipv4":
                    return addr["ip-address"]
        return None

    def destroy_vm(self, vmid: int, purge: bool = True) -> TaskResult:
        result = self._request(
            "DELETE", f"/nodes/{self.node}/qemu/{vmid}", data={"purge": 1 if purge else 0}
        )
        return self.wait_for_task(result["data"])

    # ------------------------------------------------------------------
    # Operações de alto nível — combinam as primitivas acima, no MESMO
    # padrão validado manualmente contra o cluster SACI
    # ------------------------------------------------------------------

    def build_template_from_cloud_image(
        self, vmid: int, name: str, image_url: str, image_filename: str,
        memory: int = 2048, cores: int = 2, mac: str = "BC:24:11:00:00:01",
    ) -> None:
        """Cria uma VM-template do zero a partir de uma imagem cloud
        oficial — o mesmo processo que validamos manualmente pra criar
        o cuca-template-debian13 (vmid 9000)."""
        logger.info("Baixando imagem %s", image_filename)
        self.download_image_to_storage("cephfs", image_url, image_filename)

        logger.info("Criando VM %s", vmid)
        self.create_vm(vmid, name, memory=memory, cores=cores)
        self.set_network(vmid, mac=mac)

        logger.info("Importando disco")
        self.import_disk(vmid, f"cephfs:import/{image_filename}")
        self.attach_cloudinit_drive(vmid)
        self.set_boot_order(vmid, "scsi0")
        self.enable_guest_agent(vmid)

        logger.info("Marcando como template")
        self.mark_as_template(vmid)

    def spawn_configured_vm(
        self, template_vmid: int, new_vmid: int, name: str,
        ciuser: str, cipassword: str, mac: str,
        start: bool = True,
    ) -> None:
        """Clona um template já pronto e injeta configuração — o
        equivalente ao spawn_pair() + write_file() + run_setup_commands()
        do orchestrator.py do Docker, só que via cloud-init em vez de
        docker exec."""
        logger.info("Clonando template %s -> %s (%s)", template_vmid, new_vmid, name)
        self.clone_vm(template_vmid, new_vmid, name, full=True)

        # A tag de VLAN precisa ser reaplicada explicitamente — o clone
        # herda o net0 do template, mas sem a tag pode ficar sem rede
        # (erro "not attached to any bridge" que vimos no teste manual).
        self.set_network(new_vmid, mac=mac)
        self.configure_cloudinit(new_vmid, ciuser=ciuser, cipassword=cipassword)

        if start:
            logger.info("Ligando VM %s", new_vmid)
            self.start_vm(new_vmid)
