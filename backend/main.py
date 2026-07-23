"""FastAPI app: verification endpoints, audit start, WebSocket stream, report."""
import asyncio
import json
import secrets
import uuid

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import verification as vf
from config import settings
from models import (
    AuditRequest,
    AuditStartResponse,
    DomainVerifyConfirm,
    DomainVerifyRequest,
)
from orchestrator import run_audit
from redis_client import delete_session, get_session, get_redis, kv_get, kv_set, set_session

app = FastAPI(title="OSINT Privacy Auditor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return HTMLResponse("Rate limit exceeded. Try again later.", status_code=429)


# ===========================================================================
# Ownership verification — GitHub and domain proofs, when those optional
# fields are filled in. Email needs no proof (see verification.py).
# ===========================================================================
@app.post("/api/verify/domain/request")
@limiter.limit("10/hour")
async def verify_domain_request(request: Request, body: DomainVerifyRequest):
    return (await vf.start_domain_verification(body.domain)).model_dump()


@app.post("/api/verify/domain/confirm")
@limiter.limit("20/hour")
async def verify_domain_confirm(request: Request, body: DomainVerifyConfirm):
    try:
        return (await vf.confirm_domain_verification(body.domain)).model_dump()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/verify/github/start")
async def verify_github_start():
    state = secrets.token_urlsafe(24)
    await kv_set(f"ghstate:{state}", "1", ttl=settings.CHALLENGE_TTL_SECONDS)
    return {"authorize_url": vf.github_authorize_url(state)}


@app.get("/api/verify/github/callback")
async def verify_github_callback(code: str = "", state: str = ""):
    if not state or not await kv_get(f"ghstate:{state}"):
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state.")
    try:
        result = await vf.github_exchange_code(code)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # Hand the token back to the opener window, then close the popup.
    payload = json.dumps(result.model_dump())
    return HTMLResponse(
        f"""<!doctype html><meta charset=utf-8><body>
<script>
  const data = {payload};
  if (window.opener) window.opener.postMessage({{source:"osint-github-verify", data}}, "{settings.FRONTEND_URL}");
  document.write("GitHub verified as " + data.value + ". You can close this window.");
  window.close();
</script></body>"""
    )


# ===========================================================================
# Audit
# ===========================================================================
@app.post("/api/audit/start", response_model=AuditStartResponse)
@limiter.limit("3/hour")
async def start_audit(request: Request, body: AuditRequest):
    if not body.consent:
        raise HTTPException(status_code=400, detail="Consent required.")

    # The gate: every scanned identifier must be backed by a valid ownership proof.
    try:
        vf.validate_audit_tokens(body)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    session_id = str(uuid.uuid4())
    await set_session(session_id, {"status": "running", "report": None})
    asyncio.create_task(run_audit(session_id, body))
    return {"session_id": session_id}


@app.websocket("/ws/audit/{session_id}")
async def audit_websocket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    r = await get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(f"audit:{session_id}")
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = message["data"]
            text = data.decode() if isinstance(data, (bytes, bytearray)) else data
            await websocket.send_text(text)
            if json.loads(text).get("type") == "synthesis_complete":
                break
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(f"audit:{session_id}")
        await pubsub.aclose()


@app.get("/api/audit/report/{session_id}")
async def get_report(session_id: str):
    report = await get_session(session_id)
    if not report:
        raise HTTPException(status_code=404, detail="Session not found or expired.")
    return report


@app.delete("/api/audit/report/{session_id}")
async def delete_report(session_id: str):
    await delete_session(session_id)
    return {"deleted": True}


@app.get("/api/health")
async def health():
    return {"status": "ok"}
