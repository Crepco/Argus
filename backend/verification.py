"""Ownership verification — the gate that keeps this a *self*-audit tool.

No identifier is ever scanned unless the caller has proven they control it:

    email   -> one-time code sent to that inbox
    github  -> OAuth login as that account
    domain  -> DNS TXT challenge record

Usernames / LinkedIn are only accepted once at least one *primary* identifier
(email, github, or domain) has been verified in the same request. A consent
checkbox alone is never sufficient.

Proofs are short-lived signed tokens (itsdangerous), so the browser can hold
them between the verify step and the audit-start step without us keeping
server-side session state for them.
"""
import asyncio
import hashlib
import hmac
import secrets
import smtplib
from email.message import EmailMessage
from typing import Optional

import dns.resolver
import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from config import settings
from models import VerificationChallenge, VerificationToken
from redis_client import kv_delete, kv_get, kv_set

PRIMARY_TYPES = {"email", "github", "domain"}

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

    `body` is an AuditRequest. Enforces:
      * every scanned identifier is covered by a valid token
      * usernames / linkedin require at least one verified primary identifier
    """
    proven: dict[str, set[str]] = {}
    for raw in body.verification_tokens:
        data = read_token(raw)
        if data:
            proven.setdefault(data["type"], set()).add(data["value"])

    def is_proven(kind: str, value: str) -> bool:
        return value is not None and _norm(value) in proven.get(kind, set())

    # Primary identifiers must each be individually proven.
    if not is_proven("email", body.email):
        raise ValueError("Email ownership not verified. Confirm the code sent to that inbox first.")

    if body.github_username and not is_proven("github", body.github_username):
        raise ValueError("GitHub ownership not verified. Sign in with that GitHub account first.")

    if body.domain and not is_proven("domain", body.domain):
        raise ValueError("Domain ownership not verified. Add the DNS TXT record first.")

    # Secondary identifiers: allowed only once a primary is proven.
    has_primary = any(proven.get(t) for t in PRIMARY_TYPES)
    if (body.usernames or body.linkedin_url) and not has_primary:
        raise ValueError(
            "Usernames and LinkedIn can only be audited after you verify a primary "
            "identifier (email, GitHub, or domain)."
        )


# ---------------------------------------------------------------------------
# Email one-time code
# ---------------------------------------------------------------------------
def _otp_key(email: str) -> str:
    return f"otp:email:{_norm(email)}"


def _hash_code(email: str, code: str) -> str:
    return hmac.new(
        settings.VERIFICATION_SECRET.encode(), f"{_norm(email)}:{code}".encode(), hashlib.sha256
    ).hexdigest()


async def start_email_verification(email: str) -> None:
    code = f"{secrets.randbelow(1_000_000):06d}"
    await kv_set(_otp_key(email), _hash_code(email, code), ttl=settings.OTP_TTL_SECONDS)
    await _send_code(email, code)


async def confirm_email_verification(email: str, code: str) -> VerificationToken:
    stored = await kv_get(_otp_key(email))
    if not stored or not hmac.compare_digest(stored, _hash_code(email, code)):
        raise ValueError("Invalid or expired code.")
    await kv_delete(_otp_key(email))
    return VerificationToken(type="email", value=_norm(email), token=issue_token("email", email))


async def _send_code(email: str, code: str) -> None:
    body = (
        f"Your OSINT Privacy Auditor verification code is: {code}\n\n"
        f"It expires in {settings.OTP_TTL_SECONDS // 60} minutes. If you did not "
        f"request an audit of this address, ignore this email."
    )
    if not settings.SMTP_HOST:
        # Dev fallback: no SMTP configured — print to console.
        print(f"\n[email-verification] code for {email}: {code}\n", flush=True)
        return

    msg = EmailMessage()
    msg["Subject"] = "Your privacy-audit verification code"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = email
    msg.set_content(body)

    def _send() -> None:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as s:
            s.starttls()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.send_message(msg)

    await asyncio.to_thread(_send)


# ---------------------------------------------------------------------------
# Domain DNS TXT challenge
# ---------------------------------------------------------------------------
def _domain_key(domain: str) -> str:
    return f"domainchallenge:{_norm(domain)}"


async def start_domain_verification(domain: str) -> VerificationChallenge:
    nonce = secrets.token_hex(16)
    record = f"osint-auditor-verify={nonce}"
    await kv_set(_domain_key(domain), nonce, ttl=settings.OTP_TTL_SECONDS)
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
