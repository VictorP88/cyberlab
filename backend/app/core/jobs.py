"""
Rastreamento de jobs assíncronos (setup de cenário rodando em background)
usando Valkey como armazenamento de estado.
"""
from __future__ import annotations

import json

import redis
import redis.asyncio as aioredis

from app.core.config import settings

JOB_TTL_SECONDS = 3600
JOB_KEY_PREFIX = "cyberlab:job:"

_async_redis = aioredis.from_url(settings.valkey_url, decode_responses=True)
_sync_redis = redis.from_url(settings.valkey_url, decode_responses=True)


def _key(job_id: str) -> str:
    return f"{JOB_KEY_PREFIX}{job_id}"


async def create_job_async(job_id: str, data: dict) -> None:
    await _async_redis.set(_key(job_id), json.dumps(data), ex=JOB_TTL_SECONDS)


async def get_job_async(job_id: str) -> dict | None:
    raw = await _async_redis.get(_key(job_id))
    return json.loads(raw) if raw else None


def update_job_sync(job_id: str, **fields) -> None:
    raw = _sync_redis.get(_key(job_id))
    data = json.loads(raw) if raw else {}
    data.update(fields)
    _sync_redis.set(_key(job_id), json.dumps(data), ex=JOB_TTL_SECONDS)


async def update_job_async(job_id: str, **fields) -> None:
    raw = await _async_redis.get(_key(job_id))
    data = json.loads(raw) if raw else {}
    data.update(fields)
    await _async_redis.set(_key(job_id), json.dumps(data), ex=JOB_TTL_SECONDS)
