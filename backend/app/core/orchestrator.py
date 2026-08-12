"""
Orquestrador Docker.

Cada "instância" de cenário agora é um PAR de containers, isolados numa
rede Docker própria:
  - "target"   : a máquina vulnerável (gerada a partir do spec da LLM)
  - "attacker" : máquina com ferramentas de pentest (sqlmap, nmap, curl...),
                 pré-construída (ver /attacker/Dockerfile), sem apt-get no
                 caminho crítico do spawn.

O usuário só recebe shell no "attacker" — o "target" só é alcançável pela
rede, reproduzindo o modelo HTB/CTF em vez de dar acesso root direto.
"""
from __future__ import annotations

import io
import tarfile
import time
import uuid
from dataclasses import dataclass

import docker
from docker.errors import NotFound

from app.core.config import settings

ATTACKER_IMAGE = "cyberlab-attacker:latest"


@dataclass
class InstancePair:
    instance_id: str
    network_name: str
    target_container_name: str
    attacker_container_name: str
    target_host_port: int | None


class Orchestrator:
    def __init__(self) -> None:
        self.client = docker.from_env()

    def spawn_pair(
        self,
        target_image: str,
        target_port: int = 80,
        labels: dict | None = None,
        target_env: dict | None = None,
    ) -> InstancePair:
        instance_id = str(uuid.uuid4())[:8]
        network_name = f"cyberlab-net-{instance_id}"
        target_name = f"cyberlab-target-{instance_id}"
        attacker_name = f"cyberlab-attacker-{instance_id}"
        base_labels = {"cyberlab.instance_id": instance_id, **(labels or {})}

        # Rede isolada por instância: target e attacker se enxergam entre si
        # pelo nome, mas ficam invisíveis para outras instâncias.
        self.client.networks.create(network_name, driver="bridge")

        target = self.client.containers.run(
            image=target_image,
            name=target_name,
            hostname="target",
            detach=True,
            network=network_name,
            ports={f"{target_port}/tcp": None},  # publica em porta aleatória do host
            labels={**base_labels, "cyberlab.role": "target"},
            environment=target_env or {},
            tty=True,
            stdin_open=True,
        )

        attacker = self.client.containers.run(
            image=ATTACKER_IMAGE,
            name=attacker_name,
            hostname="attacker",
            detach=True,
            network=network_name,
            labels={**base_labels, "cyberlab.role": "attacker"},
            tty=True,
            stdin_open=True,
        )

        # Lê a porta publicada via client.api.port() (consulta direta ao
        # daemon). No Docker Desktop rodando sobre WSL2, existe uma camada
        # EXTRA de encaminhamento de porta entre o Windows e o daemon
        # dentro do WSL2 — essa camada pode levar vários segundos pra
        # assentar de vez, bem mais que uma condição de corrida comum.
        # Por isso exigimos TRÊS leituras consecutivas iguais, com janela
        # de espera de até 15 segundos no total.
        host_port = None
        previous_port = None
        stable_count = 0
        for attempt in range(50):
            port_bindings = self.client.api.port(target.id, target_port)
            current_port = int(port_bindings[0]["HostPort"]) if port_bindings else None
            if current_port is not None and current_port == previous_port:
                stable_count += 1
                if stable_count >= 3:
                    host_port = current_port
                    break
            else:
                stable_count = 0
            previous_port = current_port
            time.sleep(0.3)

        # Não precisa de alias custom: em redes Docker user-defined, os
        # containers já se resolvem automaticamente pelo próprio nome
        # (target_name / attacker_name) via DNS embutido do Docker.

        # Conecta o target TAMBÉM à rede compartilhada onde vive o proxy
        # de cache de pacotes APT, além da rede isolada da instância. Se
        # o cache não existir por algum motivo, segue sem ele — só fica
        # mais lento, não quebra o spawn.
        try:
            apt_cache_net = self.client.networks.get(settings.apt_cache_network)
            apt_cache_net.connect(target)
        except Exception:  # noqa: BLE001
            pass

        return InstancePair(
            instance_id=instance_id,
            network_name=network_name,
            target_container_name=target_name,
            attacker_container_name=attacker_name,
            target_host_port=host_port,
        )

    def destroy_pair(self, instance_id: str) -> bool:
        found = False
        for role in ("target", "attacker"):
            container = self._find_container(instance_id, role)
            if container is not None:
                container.remove(force=True)
                found = True
        try:
            network = self.client.networks.get(f"cyberlab-net-{instance_id}")
            network.remove()
        except NotFound:
            pass
        return found

    def status(self, instance_id: str, role: str = "target") -> str | None:
        container = self._find_container(instance_id, role)
        if container is None:
            return None
        container.reload()
        return container.status

    def exec_shell_stream(self, instance_id: str, role: str = "attacker", cmd: str = "/bin/bash"):
        """Attach de shell interativo — por padrão no container ATTACKER."""
        container = self._find_container(instance_id, role)
        if container is None:
            raise NotFound(f"Instância {instance_id} ({role}) não encontrada")

        exec_id = self.client.api.exec_create(
            container.id, cmd, stdin=True, tty=True, stdout=True, stderr=True
        )
        sock = self.client.api.exec_start(exec_id, tty=True, socket=True)
        return sock

    def run_setup_commands(
        self, instance_id: str, commands: list[str], role: str = "target", timeout_seconds: int = 240
    ) -> list[dict]:
        container = self._find_container(instance_id, role)
        if container is None:
            raise NotFound(f"Instância {instance_id} ({role}) não encontrada")

        results = []
        for cmd in commands:
            exit_code, output = container.exec_run(
                cmd=["timeout", str(timeout_seconds), "/bin/sh", "-c", cmd],
                environment={"DEBIAN_FRONTEND": "noninteractive"},
                demux=False,
            )
            results.append(
                {
                    "command": cmd,
                    "exit_code": exit_code,
                    "timed_out": exit_code == 124,
                    "output": output.decode(errors="replace") if output else "",
                }
            )
        return results

    def check_flag_exists(self, instance_id: str, flag_path: str, role: str = "target") -> bool:
        container = self._find_container(instance_id, role)
        if container is None:
            raise NotFound(f"Instância {instance_id} ({role}) não encontrada")
        exit_code, _ = container.exec_run(cmd=["/bin/sh", "-c", f"test -f {flag_path}"])
        return exit_code == 0

    def destroy_all(self) -> dict:
        """
        Varredura completa: remove TODOS os containers target/attacker e
        redes de instância, independente de estarem rastreados no banco.
        Usado pelo botão "Encerrar cenário" para limpar também qualquer
        sobra de tentativas anteriores que não foram encerradas.
        """
        removed_containers = 0
        for prefix in ("cyberlab-target-", "cyberlab-attacker-"):
            containers = self.client.containers.list(all=True, filters={"name": prefix})
            for container in containers:
                try:
                    container.remove(force=True)
                    removed_containers += 1
                except Exception:  # noqa: BLE001
                    pass

        removed_networks = 0
        for network in self.client.networks.list(filters={"name": "cyberlab-net-"}):
            try:
                network.remove()
                removed_networks += 1
            except Exception:  # noqa: BLE001
                pass

        return {"removed_containers": removed_containers, "removed_networks": removed_networks}

    def write_file(self, instance_id: str, path: str, content: str, role: str = "target") -> None:
        """
        Escreve um arquivo dentro do container via put_archive (a mesma
        API por trás do `docker cp`). Não passa por shell nenhum, então
        não tem risco de aspas/escaping quebrando o conteúdo — diferente
        de tentar gerar o arquivo via `echo` dentro de um exec_run.
        """
        container = self._find_container(instance_id, role)
        if container is None:
            raise NotFound(f"Instância {instance_id} ({role}) não encontrada")

        directory, _, filename = path.rpartition("/")
        directory = directory or "/"

        data = content.encode("utf-8")
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar_stream.seek(0)

        container.put_archive(directory, tar_stream)

    def get_target_host_port(self, instance_id: str, target_port: int = 80) -> int | None:
        """Reconsulta a porta publicada agora — útil pra confirmar/corrigir
        o valor no final do setup, quando já deu tempo de sobra pra
        qualquer camada extra de encaminhamento de porta (Docker Desktop
        no Windows/WSL2) assentar de vez."""
        container = self._find_container(instance_id, "target")
        if container is None:
            return None
        port_bindings = self.client.api.port(container.id, target_port)
        if not port_bindings:
            return None
        return int(port_bindings[0]["HostPort"])

    def _find_container(self, instance_id: str, role: str):
        containers = self.client.containers.list(
            all=True,
            filters={
                "label": [
                    f"cyberlab.instance_id={instance_id}",
                    f"cyberlab.role={role}",
                ]
            },
        )
        return containers[0] if containers else None


orchestrator = Orchestrator()
