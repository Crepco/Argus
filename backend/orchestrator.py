"""Fans out all modules in parallel, streams each result over Redis pub/sub,
then runs URL-dependent modules and finally synthesis."""
from __future__ import annotations

import asyncio
import re

from models import AuditRequest
from redis_client import publish, set_session
from synthesizer import synthesize
from modules.base import BaseModule
from modules.github_module import GithubModule
from modules.email_hunter_module import EmailHunterModule
from modules.dns_module import DnsModule
from modules.dork_module import DorkModule
from modules.metadata_module import MetadataModule
from modules.wayback_module import WaybackModule
from modules.username_module import UsernameModule
from modules.social_content_module import SocialContentModule

DOC_EXT_RE = re.compile(r"\.(pdf|docx?|jpe?g|png|tiff?)(\?|$)", re.IGNORECASE)
SOCIAL_HOSTS = (
    "reddit.com", "twitter.com", "x.com", "nitter.", "medium.com", "dev.to",
    "hacker-news", "news.ycombinator.com", "gravatar.com", "mastodon", "bsky.",
)


async def run_module(module: BaseModule, session_id: str) -> dict:
    try:
        result = await module.run()
    except Exception as e:  # a broken module must never sink the audit
        result = {
            "module": getattr(module, "name", module.__class__.__name__),
            "status": "error",
            "severity": "CLEAN",
            "findings": [],
            "sources": [],
            "error": str(e),
        }
    await publish(session_id, {"type": "module_result", "data": result})
    return result


async def run_audit(session_id: str, body: AuditRequest) -> None:
    email_domain = body.email.split("@")[1] if "@" in body.email else None
    domain = body.domain or email_domain

    # Base modules — everything that can run from the raw input.
    base_modules: list[BaseModule] = [
        GithubModule(body.github_username, body.email),
        EmailHunterModule(body.email),
        DnsModule(domain),
        DorkModule(body.name, body.email, body.domain),
        WaybackModule(domain),
        UsernameModule(body.github_username, body.usernames, body.email),
    ]

    results = await asyncio.gather(*[run_module(m, session_id) for m in base_modules])

    # Dependent modules — fed by URLs/handles the base pass discovered.
    doc_urls = _extract_doc_urls(results)
    social_urls = _extract_social_urls(results)
    discovered_usernames = _extract_usernames(results, body)

    dep_modules: list[BaseModule] = []
    if doc_urls:
        dep_modules.append(MetadataModule(doc_urls))
    if social_urls:
        dep_modules.append(SocialContentModule(social_urls, body.email))
    if discovered_usernames:
        dep_modules.append(UsernameModule(None, discovered_usernames, body.email))

    dep_results = await asyncio.gather(*[run_module(m, session_id) for m in dep_modules]) if dep_modules else []

    all_results = list(results) + list(dep_results)

    # Synthesis (falls back gracefully if OpenRouter is unavailable).
    try:
        report = await synthesize(all_results)
    except Exception as e:
        report = _fallback_report(all_results, error=str(e))

    await publish(session_id, {"type": "synthesis_complete", "data": report})
    await set_session(session_id, {"status": "complete", "report": report, "modules": all_results})


# ---------------------------------------------------------------------------
def _iter_sources(results: list[dict]):
    for r in results:
        for s in r.get("sources", []) or []:
            yield s
        for f in r.get("findings", []) or []:
            if isinstance(f, dict) and f.get("source"):
                yield f["source"]


def _extract_doc_urls(results: list[dict]) -> list[str]:
    return _dedupe(s for s in _iter_sources(results) if isinstance(s, str) and DOC_EXT_RE.search(s))


def _extract_social_urls(results: list[dict]) -> list[str]:
    return _dedupe(
        s for s in _iter_sources(results)
        if isinstance(s, str) and any(h in s for h in SOCIAL_HOSTS)
    )


def _extract_usernames(results: list[dict], body: AuditRequest) -> list[str]:
    names: list[str] = []
    for r in results:
        for f in r.get("findings", []) or []:
            if isinstance(f, dict):
                for p in f.get("platforms", []) or []:
                    if isinstance(p, str):
                        names.append(p)
    return _dedupe(n for n in names if n)


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        key = it.lower()
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def _fallback_report(all_results: list[dict], error: str) -> dict:
    exposed = [r["module"] for r in all_results if r.get("findings")]
    return {
        "overall_severity": "LOW",
        "digital_footprint_score": {"score": 0, "explanation": "Synthesis unavailable."},
        "executive_summary": (
            "Module scan completed but LLM synthesis was unavailable "
            f"({error}). Raw per-module findings are still shown below."
        ),
        "attacker_simulation": "",
        "platforms_exposed": [],
        "data_categories_exposed": [],
        "cross_linked_findings": [],
        "remediation_plan": {"critical": [], "medium": [], "low": []},
        "modules_with_findings": exposed,
    }
