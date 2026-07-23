"""Ownership verification for the identifiers that support it.

    github  -> OAuth login as that account
    domain  -> DNS TXT challenge record

Email is taken as given (it's a required field on every audit — no proof
step). GitHub and domain proofs, when the caller fills those optional
fields, must be valid before the identifier is scanned.

Proofs are short-lived signed tokens (itsdangerous), so the browser can hold
them between the verify step and the audit-start step without us keeping
server-side session state for them.
"""
import asyncio
import secrets
from typing import Optional

import dns.resolver
import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from config import settings
from models import VerificationChallenge, VerificationToken
from redis_client import kv_delete, kv_get, kv_set

_serializer = URLSafeTimedSerializer(settings.VERIFICATION_SECRET, salt="ownership-proof")


# ---------------------------------------------------------------------------
# Token issue / check
# ---------------------------------------------------------------------------
def issue_token(kind: str, value: str) -> str:
    return _serializer.dumps({"type": kind, "value": value.lower().strip()})


def read_token(token: str) -> Optional[dict]:
    """Return {'type', 'value'} if the token is valid and unexpired, else None."""
    try:
        return _serializer.loads(token, max_age=settings.VERIFICATION_TTL_SECONDS)
    except (BadSignature, SignatureExpired):
        return None


def _norm(value: str) -> str:
    return value.lower().strip()


def validate_audit_tokens(body) -> None:
    """Raise ValueError if the request tries to scan an unverified identifier.

    `body` is an AuditRequest. GitHub and domain, when provided, must each be
    covered by a valid proof token. Email needs no proof — it's a required
    field and treated as given.
    """
    proven: dict[str, set[str]] = {}
    for raw in body.verification_tokens:
        data = read_token(raw)
        if data:
            proven.setdefault(data["type"], set()).add(data["value"])

    def is_proven(kind: str, value: str) -> bool:
        return value is not None and _norm(value) in proven.get(kind, set())

    if body.github_username and not is_proven("github", body.github_username):
        raise ValueError("GitHub ownership not verified. Sign in with that GitHub account first.")

    if body.domain and not is_proven("domain", body.domain):
        raise ValueError("Domain ownership not verified. Add the DNS TXT record first.")


# ---------------------------------------------------------------------------
# Domain DNS TXT challenge
# ---------------------------------------------------------------------------
def _domain_key(domain: str) -> str:
    return f"domainchallenge:{_norm(domain)}"


async def start_domain_verification(domain: str) -> VerificationChallenge:
    nonce = secrets.token_hex(16)
    record = f"osint-auditor-verify={nonce}"
    await kv_set(_domain_key(domain), nonce, ttl=settings.CHALLENGE_TTL_SECONDS)
    return VerificationChallenge(
        type="domain",
        value=_norm(domain),
        instructions=(
            f"Add a DNS TXT record on {_norm(domain)} with the value below, then "
            f"confirm. It proves you control the domain."
        ),
        detail={"record_type": "TXT", "host": "@", "value": record},
    )


async def confirm_domain_verification(domain: str) -> VerificationToken:
    expected = await kv_get(_domain_key(domain))
    if not expected:
        raise ValueError("No pending challenge for this domain (or it expired). Start again.")
    target = f"osint-auditor-verify={expected}"

    def _lookup() -> list[str]:
        values: list[str] = []
        try:
            for rdata in dns.resolver.resolve(_norm(domain), "TXT"):
                values.append(b"".join(rdata.strings).decode(errors="ignore"))
        except Exception:  # NXDOMAIN, no TXT, timeout, etc.
            pass
        return values

    records = await asyncio.to_thread(_lookup)
    if target not in records:
        raise ValueError("TXT record not found yet. DNS can take a few minutes to propagate.")

    await kv_delete(_domain_key(domain))
    return VerificationToken(type="domain", value=_norm(domain), token=issue_token("domain", domain))


# ---------------------------------------------------------------------------
# GitHub OAuth
# ---------------------------------------------------------------------------
def github_authorize_url(state: str) -> str:
    if not settings.GITHUB_OAUTH_CLIENT_ID:
        raise RuntimeError("GITHUB_OAUTH_CLIENT_ID is not configured")
    redirect = f"{settings.BACKEND_URL}/api/verify/github/callback"
    return (
        "https://github.com/login/oauth/authorize"
        f"?client_id={settings.GITHUB_OAUTH_CLIENT_ID}"
        f"&redirect_uri={redirect}"
        f"&scope=read:user"
        f"&state={state}"
    )


async def github_exchange_code(code: str) -> VerificationToken:
    async with httpx.AsyncClient(timeout=20) as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
                "client_secret": settings.GITHUB_OAUTH_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{settings.BACKEND_URL}/api/verify/github/callback",
            },
        )
        access_token = token_resp.json().get("access_token")
        if not access_token:
            raise ValueError("GitHub did not return an access token.")

        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.github+json"},
        )
        login = user_resp.json().get("login")
        if not login:
            raise ValueError("Could not read GitHub account login.")

    return VerificationToken(type="github", value=_norm(login), token=issue_token("github", login))
