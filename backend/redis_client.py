"""Redis connection + session / pub-sub helpers.

Uses redis.asyncio (the async client shipped with redis-py; the old standalone
`aioredis` package was merged into redis-py and is deprecated).
"""
import json
from typing import Optional

import redis.asyncio as redis

from config import settings

_redis: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(settings.REDIS_URL, decode_responses=False)
    return _redis


# ---- session storage (30-min TTL, no database) ----
async def set_session(session_id: str, data: dict, ttl: int = settings.SESSION_TTL_SECONDS) -> None:
    r = await get_redis()
    await r.set(f"session:{session_id}", json.dumps(data), ex=ttl)


async def get_session(session_id: str) -> Optional[dict]:
    r = await get_redis()
    raw = await r.get(f"session:{session_id}")
    return json.loads(raw) if raw else None


async def delete_session(session_id: str) -> None:
    r = await get_redis()
    await r.delete(f"session:{session_id}")


# ---- pub/sub for live module streaming ----
async def publish(session_id: str, message: dict) -> None:
    r = await get_redis()
    await r.publish(f"audit:{session_id}", json.dumps(message))


# ---- generic short-lived KV (OTP codes, etc.) ----
async def kv_set(key: str, value: str, ttl: int) -> None:
    r = await get_redis()
    await r.set(key, value, ex=ttl)


async def kv_get(key: str) -> Optional[str]:
    r = await get_redis()
    raw = await r.get(key)
    return raw.decode() if isinstance(raw, (bytes, bytearray)) else raw


async def kv_delete(key: str) -> None:
    r = await get_redis()
    await r.delete(key)
