import asyncio
import hashlib
import secrets
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from app.core.auth_deps import get_current_username
from app.core.db_ops import (
    create_instance,
    create_scenario,
    get_user_by_username,
    update_instance_port,
    update_instance_result,
)
from app.core.deep_agent import generate_scenario_with_agent
from app.core.jobs import create_job_async, get_job_async, update_job_async
from app.core.llm import ScenarioSpec
from app.core.orchestrator import orchestrator
from app.core.webapp_template import (
    build_about_php,
    build_command_injection_php,
    build_command_injection_post_app_commands,
    build_command_injection_pre_app_commands,
    build_landing_php,
    build_log_viewer_php,
    build_log_viewer_post_app_commands,
    build_log_viewer_pre_app_commands,
    build_login_php,
    build_robots_txt,
    build_search_landing_php,
    build_search_php,
    build_search_post_app_commands,
    build_search_pre_app_commands,
    build_sqli_post_app_commands,
    build_sqli_pre_app_commands,
)

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


class ScenarioRequest(BaseModel):
    description: str


class SpawnAccepted(BaseModel):
    job_id: str
    instance_id: str
    container_name: str
    attacker_container_name: str
    target_host_port: int | None
    spec: ScenarioSpec
    status: str = "pending"


async def _run_setup_job(
    job_id: str,
    instance_id: str,
    pre_app_commands: list[str],
    app_files: dict[str, str],
    post_app_commands: list[str],
    flag_location: str,
) -> None:
    """
    Roda no event loop principal; chamadas bloqueantes do Docker SDK vão
    para uma thread via asyncio.to_thread. Fluxo em 3 fases:
      1. infraestrutura (apt-get, mysql se aplicável) — determinístico
      2. injeção dos arquivos da aplicação via write_file (put_archive,
         sem shell) — pode ser mais de um arquivo (site com várias páginas)
      3. seed/permissões + start do Apache + fase 2 (privesc, se houver)
    """
    await update_job_async(job_id, status="running")
    await update_instance_result(instance_id, status="running")
    pre_results: list[dict] = []
    try:
        pre_results = await asyncio.to_thread(
            orchestrator.run_setup_commands, instance_id, pre_app_commands, "target"
        )

        # Proteção extra: garante que o diretório existe antes de tentar
        # escrever os arquivos.
        await asyncio.to_thread(
            orchestrator.run_setup_commands, instance_id, ["mkdir -p /var/www/html"], "target"
        )

        for path, content in app_files.items():
            await asyncio.to_thread(orchestrator.write_file, instance_id, path, content, "target")

        post_results = await asyncio.to_thread(
            orchestrator.run_setup_commands, instance_id, post_app_commands, "target"
        )

        setup_results = pre_results + post_results
        flag_placed = await asyncio.to_thread(
            orchestrator.check_flag_exists, instance_id, flag_location, "target"
        )
        setup_success = all(r["exit_code"] == 0 for r in setup_results)

        confirmed_port = await asyncio.to_thread(orchestrator.get_target_host_port, instance_id)
        if confirmed_port is not None:
            await update_instance_port(instance_id, confirmed_port)

        await update_job_async(
            job_id,
            status="done",
            setup_results=setup_results,
            setup_success=setup_success,
            flag_placed=flag_placed,
            target_host_port=confirmed_port,
        )
        await update_instance_result(
            instance_id, status="done", setup_success=setup_success, flag_placed=flag_placed
        )
    except Exception as exc:  # noqa: BLE001
        await update_job_async(
            job_id, status="error", error=str(exc), setup_results=pre_results
        )
        await update_instance_result(instance_id, status="error", error=str(exc))


@router.post("/generate-and-spawn", response_model=SpawnAccepted, status_code=202)
async def generate_and_spawn(
    req: ScenarioRequest,
    background_tasks: BackgroundTasks,
    current_username: str = Depends(get_current_username),
) -> SpawnAccepted:
    """
    O agente (LangChain, múltiplas etapas) classifica o tipo de
    vulnerabilidade E a VARIANTE de template pedidos, busca exemplos
    validados (RAG vetorial), rascunha nome/dificuldade/dicas e se
    autocritica. A infraestrutura e o código da aplicação vulnerável em
    si são SEMPRE determinísticos por (tipo, variante).

    Variantes de sqli:
      - login_bypass: 2 fases (bypass de login + privesc SSH/sudo)
      - search_exfiltration: 1 fase (SQLi via busca GET, sem privesc)
    """
    user = await get_user_by_username(current_username)
    user_id = user.id if user else None

    agent_result = await generate_scenario_with_agent(req.description)
    vulnerability_type = agent_result["vulnerability_type"]
    variant = agent_result["variant"]

    job_id = str(uuid.uuid4())[:8]
    scenario_id = str(uuid.uuid4())
    flag_value = f"CYBERLAB{{{secrets.token_hex(8)}}}"
    flag_hash = hashlib.sha256(flag_value.encode()).hexdigest()
    root_flag_hash: str | None = None

    if vulnerability_type == "command_injection" and variant == "log_viewer":
        flag_location = "/opt/flag.txt"
        root_flag_value = f"CYBERLAB{{{secrets.token_hex(8)}}}"
        root_flag_hash = hashlib.sha256(root_flag_value.encode()).hexdigest()

        pre_app_commands = build_log_viewer_pre_app_commands()
        app_files = {"/var/www/html/index.php": build_log_viewer_php()}
        post_app_commands = build_log_viewer_post_app_commands(
            flag_value, flag_location, root_flag_value
        )
        extra_hint = (
            "Fase 1: o campo de arquivo vai direto pro comando de "
            "sistema via parâmetro da URL (GET), sem sanitização — "
            "encadeia outro comando junto do nome do log (ex: usando ; "
            "ou &&) pra ler a primeira flag. Fase 2: procura por "
            "binários com bit SUID mal configurado (ex: injeta `find / "
            "-perm -4000 2>/dev/null`), e usa o que encontrar pra ler a "
            "segunda flag numa única injeção."
        )

    elif vulnerability_type == "command_injection":
        flag_location = "/opt/flag.txt"
        root_flag_value = f"CYBERLAB{{{secrets.token_hex(8)}}}"
        root_flag_hash = hashlib.sha256(root_flag_value.encode()).hexdigest()

        pre_app_commands = build_command_injection_pre_app_commands()
        app_files = {"/var/www/html/index.php": build_command_injection_php()}
        post_app_commands = build_command_injection_post_app_commands(
            flag_value, flag_location, root_flag_value
        )
        extra_hint = (
            "Fase 1: o campo de host vai direto pro comando de sistema, "
            "sem sanitização — encadeia outro comando junto do ping (ex: "
            "usando ; ou &&) pra ler a primeira flag. Fase 2: você já tem "
            "execução de código como www-data — testa `sudo -l` na "
            "própria injeção (ex: ; sudo -l) pra ver o que dá pra "
            "executar como root sem senha, e usa isso pra ler a segunda "
            "flag numa única injeção. (Alternativa mais realista, se "
            "quiser: abrir uma reverse shell de volta pro seu atacante "
            "com um `nc -lvnp PORTA` esperando do lado atacante — mas "
            "lembra que a conexão do terminal pode cair e reiniciar a "
            "sessão nesse meio-tempo, então o caminho direto é mais "
            "confiável.)"
        )

    elif variant == "search_exfiltration":
        flag_location = "/root/flag.txt"
        db_password = secrets.token_hex(4)
        pre_app_commands = build_search_pre_app_commands(db_password)
        app_files = {
            "/var/www/html/index.php": build_search_landing_php(),
            "/var/www/html/search.php": build_search_php(db_password),
        }
        post_app_commands = build_search_post_app_commands(flag_value, flag_location)
        extra_hint = (
            "A busca de produtos usa o texto digitado direto numa query "
            "SQL, sem sanitização — tenta uma injeção UNION pra puxar "
            "dados de outra tabela através dos resultados da busca."
        )

    else:  # login_bypass (padrão)
        flag_location = "/root/flag.txt"
        db_password = secrets.token_hex(4)
        admin_password = secrets.token_hex(4)
        webadmin_password = admin_password  # reuso de senha proposital — parte do exercício
        root_flag_value = f"CYBERLAB{{{secrets.token_hex(8)}}}"
        root_flag_hash = hashlib.sha256(root_flag_value.encode()).hexdigest()

        pre_app_commands = build_sqli_pre_app_commands(db_password)
        app_files = {
            "/var/www/html/index.php": build_landing_php(),
            "/var/www/html/about.php": build_about_php(),
            "/var/www/html/login.php": build_login_php(db_password),
            "/var/www/html/robots.txt": build_robots_txt(),
        }
        post_app_commands = build_sqli_post_app_commands(
            admin_password, flag_value, flag_location, webadmin_password, root_flag_value
        )
        extra_hint = (
            "Fase 1: o login (procura o link certo no site) é vulnerável a "
            "SQL Injection — contorna a autenticação pra achar a primeira "
            "flag. Fase 2: a senha que você descobrir também abre uma "
            "sessão SSH — de lá, um `sudo -l` mostra o que dá pra rodar "
            "como root sem senha."
        )

    spec = ScenarioSpec(
        name=agent_result["name"],
        base_image="ubuntu:22.04",
        vulnerability_type=vulnerability_type,
        difficulty=agent_result["difficulty"],
        setup_commands=pre_app_commands + list(app_files.keys()) + post_app_commands,
        flag_location=flag_location,
        hints=list(agent_result["hints"]) + [extra_hint],
    )

    pair = orchestrator.spawn_pair(
        target_image=spec.base_image,
        labels={"cyberlab.scenario": spec.name, "cyberlab.vulnerability": spec.vulnerability_type},
    )

    await create_scenario(scenario_id, req.description, spec.model_dump(), variant=variant)
    await create_instance(
        pair.instance_id,
        scenario_id,
        job_id,
        pair.target_container_name,
        pair.attacker_container_name,
        pair.network_name,
        pair.target_host_port,
        flag_hash,
        user_id=user_id,
        root_flag_hash=root_flag_hash,
    )

    await create_job_async(
        job_id,
        {
            "status": "pending",
            "instance_id": pair.instance_id,
            "container_name": pair.target_container_name,
            "attacker_container_name": pair.attacker_container_name,
            "target_host_port": pair.target_host_port,
            "spec": spec.model_dump(),
            "flag_value_debug": flag_value,
        },
    )

    background_tasks.add_task(
        _run_setup_job,
        job_id,
        pair.instance_id,
        pre_app_commands,
        app_files,
        post_app_commands,
        flag_location,
    )

    return SpawnAccepted(
        job_id=job_id,
        instance_id=pair.instance_id,
        container_name=pair.target_container_name,
        attacker_container_name=pair.attacker_container_name,
        target_host_port=pair.target_host_port,
        spec=spec,
    )


@router.get("/jobs/{job_id}")
async def get_job(job_id: str, current_username: str = Depends(get_current_username)) -> dict:
    job = await get_job_async(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job não encontrado (ou expirou, TTL de 1h)")
    return job
