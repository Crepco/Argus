"""Shared base for all OSINT modules.

Every module returns the same standardized shape so the orchestrator, WebSocket
stream, and frontend can treat them uniformly:

    {"module", "status", "severity", "findings": [...], "sources": [...]}
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional

import httpx

from config import settings

SEVERITY_ORDER = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Domain-scoped modules (WHOIS, crt.sh, Wayback...) receive `body.domain or
# email_domain`. If the user only gave an email, that can resolve to a
# freemail provider — scanning gmail.com's own WHOIS/DNS would surface
# Google's infrastructure, not the person's, so those modules skip it.
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "icloud.com", "me.com", "protonmail.com", "proton.me",
    "aol.com", "gmx.com", "zoho.com", "mail.com", "yandex.com",
}


class BaseModule:
    #: Stable machine name used by the frontend progress grid.
    name: str = "base_module"

    async def run(self) -> dict:  # pragma: no cover - overridden
        raise NotImplementedError

    # ---- helpers ----
    def result(
        self,
        severity: str,
        findings: list[dict],
        sources: list[str],
        status: str = "complete",
    ) -> dict:
        if not findings and status == "complete":
            status = "clean"
        return {
            "module": self.name,
            "status": status,
            "severity": severity,
            "findings": findings,
            "sources": sources,
        }

    def clean(self) -> dict:
        return self.result("CLEAN", [], [], status="clean")

    @staticmethod
    def worst(severities: list[str]) -> str:
        if not severities:
            return "CLEAN"
        return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


class DomainRateLimiter:
    """Enforces >= settings.CRAWL_DELAY_SECONDS between hits to the same host."""

    def __init__(self) -> None:
        self._last: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, host: str) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last.get(host, 0.0)
            if elapsed < settings.CRAWL_DELAY_SECONDS:
                await asyncio.sleep(settings.CRAWL_DELAY_SECONDS - elapsed)
            self._last[host] = time.monotonic()


# All 6+ base modules run concurrently via asyncio.gather, and several of
# them (dork/email_hunter/phone via serpapi_search, github's repo scan,
# username's per-platform sweep) each fan out their OWN internal batch of
# requests too. Left unbounded, a single audit can momentarily try to open
# 60-90+ simultaneous outbound connections from one process, which some
# local firewalls/endpoint-security agents throttle by silently dropping
# connections rather than erroring — manifesting as the whole audit hanging.
# Capping each client's own connection pool keeps any one module's burst
# bounded; capping SerpAPI specifically (shared by 3 query-heavy modules)
# bounds the largest single contributor.
_DEFAULT_LIMITS = httpx.Limits(max_connections=10, max_keepalive_connections=5)
_SERPAPI_SEMAPHORE = asyncio.Semaphore(8)


def make_client(timeout: float = 15.0, follow_redirects: bool = True) -> httpx.AsyncClient:
    """httpx client pre-configured with the required User-Agent and a bounded connection pool."""
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers={"User-Agent": settings.USER_AGENT},
        limits=_DEFAULT_LIMITS,
    )


async def serpapi_search(query: str, num: int = 10) -> list[dict]:
    """Run one Google query through SerpAPI. Returns [] if no key configured."""
    if not settings.SERPAPI_KEY:
        return []
    async with _SERPAPI_SEMAPHORE:
        async with make_client(timeout=20) as client:
            resp = await client.get(
                "https://serpapi.com/search.json",
                params={"q": query, "engine": "google", "num": num, "api_key": settings.SERPAPI_KEY},
            )
            if resp.status_code != 200:
                return []
            return resp.json().get("organic_results", []) or []
