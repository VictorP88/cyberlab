from __future__ import annotations

from fastapi import Header, HTTPException, Query

from app.core.security import decode_access_token


async def get_current_username(authorization: str | None = Header(default=None)) -> str:
    """Dependência pra rotas HTTP normais — lê o header Authorization."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Não autenticado")
    token = authorization.removeprefix("Bearer ").strip()
    username = decode_access_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    return username


async def get_username_from_ws_token(token: str | None = Query(default=None)) -> str | None:
    """Pra WebSocket: o token vem via query string (?token=...)."""
    if not token:
        return None
    return decode_access_token(token)
