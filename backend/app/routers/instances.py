import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.core.auth_deps import get_current_username
from app.core.db_ops import (
    get_analytics_summary,
    get_user_by_username,
    list_recent_instances,
    mark_all_instances_destroyed,
    mark_instance_destroyed,
    submit_flag,
)
from app.core.orchestrator import orchestrator
from app.core.security import decode_access_token

router = APIRouter(prefix="/instances", tags=["instances"])


@router.get("/history")
async def instance_history(
    limit: int = 20,
    mine_only: bool = False,
    current_username: str = Depends(get_current_username),
) -> list[dict]:
    user_id = None
    if mine_only:
        user = await get_user_by_username(current_username)
        user_id = user.id if user else None
    return await list_recent_instances(limit, user_id=user_id)


@router.get("/analytics")
async def instance_analytics(current_username: str = Depends(get_current_username)) -> list[dict]:
    """Painel de analytics: taxa de conclusão, tempo médio, tentativas
    erradas — agregado por (tipo de vulnerabilidade, variante, dificuldade)."""
    return await get_analytics_summary()


@router.delete("")
async def destroy_all_instances(current_username: str = Depends(get_current_username)):
    """Limpeza total: remove TODOS os containers/redes de cenário, mesmo
    os de tentativas anteriores que não foram encerrados corretamente."""
    docker_result = orchestrator.destroy_all()
    marked = await mark_all_instances_destroyed()
    return {**docker_result, "marked_destroyed_in_db": marked}


@router.delete("/{instance_id}")
async def destroy_instance(instance_id: str, current_username: str = Depends(get_current_username)):
    ok = orchestrator.destroy_pair(instance_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Instância não encontrada")
    await mark_instance_destroyed(instance_id)
    return {"destroyed": instance_id}


@router.get("/{instance_id}/status")
def instance_status(
    instance_id: str, role: str = "target", current_username: str = Depends(get_current_username)
):
    status = orchestrator.status(instance_id, role)
    if status is None:
        raise HTTPException(status_code=404, detail="Instância não encontrada")
    return {"instance_id": instance_id, "role": role, "status": status}


class SubmitFlagRequest(BaseModel):
    flag: str


@router.post("/{instance_id}/submit-flag")
async def submit_flag_endpoint(
    instance_id: str,
    req: SubmitFlagRequest,
    current_username: str = Depends(get_current_username),
) -> dict:
    result = await submit_flag(instance_id, req.flag)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.websocket("/{instance_id}/terminal")
async def terminal_ws(websocket: WebSocket, instance_id: str, token: str | None = Query(default=None)):
    """
    Proxy BIDIRECIONAL entre o WebSocket do navegador (Xterm.js) e o exec
    attach do container ATTACKER. O navegador não manda header
    Authorization em WebSocket nativo, então o token vem via query string
    (?token=...) e é validado ANTES de aceitar a conexão.
    """
    username = decode_access_token(token) if token else None
    if not username:
        await websocket.close(code=4401, reason="Não autenticado")
        return

    await websocket.accept()
    try:
        sock = orchestrator.exec_shell_stream(instance_id, role="attacker")
    except Exception as exc:  # noqa: BLE001
        await websocket.close(code=1011, reason=str(exc))
        return

    raw_sock = sock._sock
    loop = asyncio.get_event_loop()

    async def read_from_container() -> None:
        try:
            while True:
                data = await loop.run_in_executor(None, raw_sock.recv, 4096)
                if not data:
                    break
                await websocket.send_text(data.decode(errors="replace"))
        except Exception:  # noqa: BLE001
            pass

    async def read_from_browser() -> None:
        try:
            while True:
                data = await websocket.receive_text()
                raw_sock.send(data.encode())
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001
            pass

    async def heartbeat() -> None:
        try:
            while True:
                await asyncio.sleep(60)
                raw_sock.send(b"\x00")
        except Exception:  # noqa: BLE001
            pass

    reader_task = asyncio.create_task(read_from_container())
    writer_task = asyncio.create_task(read_from_browser())
    heartbeat_task = asyncio.create_task(heartbeat())

    done, pending = await asyncio.wait(
        [reader_task, writer_task, heartbeat_task], return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    raw_sock.close()
