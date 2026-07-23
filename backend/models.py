"""Pydantic request/response models."""
from typing import Optional

from pydantic import BaseModel, EmailStr


# ---------------------------------------------------------------------------
# Ownership verification
# ---------------------------------------------------------------------------
class DomainVerifyRequest(BaseModel):
    domain: str


class DomainVerifyConfirm(BaseModel):
    domain: str


class VerificationToken(BaseModel):
    """Returned to the client once an identifier is proven. Opaque + signed."""
    type: str            # "github" | "domain"
    value: str           # the verified identifier
    token: str           # signed, short-lived proof to attach to /audit/start


class VerificationChallenge(BaseModel):
    """Instructions the user must satisfy (e.g. the DNS TXT record to add)."""
    type: str
    value: str
    instructions: str
    detail: dict = {}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
class AuditRequest(BaseModel):
    name: str
    email: EmailStr
    github_username: Optional[str] = None
    linkedin_url: Optional[str] = None
    domain: Optional[str] = None
    usernames: list[str] = []
    consent: bool

    # Ownership proofs for github_username / domain, if those are set.
    verification_tokens: list[str] = []


class AuditStartResponse(BaseModel):
    session_id: str


class ModuleResult(BaseModel):
    module: str
    status: str           # complete | error | clean
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW | CLEAN
    findings: list[dict] = []
    sources: list[str] = []
    error: Optional[str] = None
