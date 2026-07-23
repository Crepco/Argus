"""Redis connection + session / pub-sub helpers.

Uses redis.asyncio (the async client shipped with redis-py; the old standalone
`aioredis` package was merged into redis-py and is deprecated).
"""
import json
import logging
from typing import Optional

import redis.asyncio as redis

from config import settings

logger = logging.getLogger(__name__)

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


# ---- durable event log + pub/sub notification for live module streaming ----
# Events are appended to a list (so nothing is lost if a subscriber connects
# late) and pub/sub is used only to wake up any websocket currently waiting.
#
# publish() is best-effort by design: it only affects the *live* progress
# view. A transient Redis blip here must never take down run_audit() — the
# audit keeps computing regardless, and the final report still lands via
# set_session(). Swallowing the error means that one module's update may not
# reach an already-open browser tab, which is a strictly better failure mode
# than losing the whole audit to a single flaky connection.
async def publish(session_id: str, message: dict) -> None:
    try:
        r = await get_redis()
        key = f"auditlog:{session_id}"
        await r.rpush(key, json.dumps(message))
        await r.expire(key, settings.SESSION_TTL_SECONDS)
        await r.publish(f"audit:{session_id}", "new")
    except Exception:
        logger.warning("publish() failed for session %s — live update dropped", session_id, exc_info=True)


async def get_events(session_id: str, start: int = 0) -> list[dict]:
    r = await get_redis()
    raw = await r.lrange(f"auditlog:{session_id}", start, -1)
    return [json.loads(x) for x in raw]


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
