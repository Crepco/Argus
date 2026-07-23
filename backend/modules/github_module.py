"""GitHub exposure module.

Scans a *verified* GitHub account's public surface for leaked secrets and
secondary-account leakage:

  * repos -> commit authorship emails that differ from the target (work/alt
    accounts leaking through git history)
  * gists -> raw content scanned for API keys, .env lines, phone numbers, etc.
  * cross-platform presence on npm / PyPI / Docker Hub

Secret *values* are never returned — only the category and the source URL.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from config import settings
from modules.base import BaseModule, make_client

GITHUB_API = "https://api.github.com"

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s-]?){10,13}(?!\d)")
PRIVATE_IP_RE = re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
ENV_LINE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=\S+", re.MULTILINE)

# Category name -> detector. Values are NEVER captured, only the fact of a match.
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "AWS secret key": re.compile(r"aws_secret_access_key\s*=\s*\S+", re.IGNORECASE),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "GitHub token": re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic bearer/secret": re.compile(
        r"(?:api[_-]?key|secret|token|bearer|passwd|password)\s*[:=]\s*['\"]?[A-Za-z0-9/\+_\-]{12,}",
        re.IGNORECASE,
    ),
}


class GithubModule(BaseModule):
    name = "github_module"

    def __init__(self, username: Optional[str], target_email: str) -> None:
        self.username = username
        self.target_email = (target_email or "").lower()

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "User-Agent": settings.USER_AGENT}
        if settings.GITHUB_TOKEN:
            h["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
        return h

    async def run(self) -> dict:
        if not self.username:
            return self.clean()

        findings: list[dict] = []
        sources: list[str] = []

        async with make_client(timeout=20) as client:
            client.headers.update(self._headers())

            leaked_emails = await self._scan_commit_emails(client, findings, sources)
            secret_hit = await self._scan_gists(client, findings, sources)
            packages = await self._cross_platform(client, findings, sources)

        # Severity ranking per the spec.
        if secret_hit:
            severity = "CRITICAL"
        elif leaked_emails:
            severity = "HIGH"
        elif packages:
            severity = "MEDIUM"
        else:
            severity = "LOW" if sources else "CLEAN"

        return self.result(severity, findings, sources)

    # ------------------------------------------------------------------
    async def _scan_commit_emails(self, client, findings, sources) -> set[str]:
        leaked: set[str] = set()
        try:
            repos_resp = await client.get(
                f"{GITHUB_API}/users/{self.username}/repos", params={"per_page": 100, "sort": "pushed"}
            )
            repos = repos_resp.json() if repos_resp.status_code == 200 else []
        except Exception:
            repos = []

        async def commits_for(repo: dict) -> None:
            full = repo.get("full_name")
            if not full:
                return
            try:
                resp = await client.get(f"{GITHUB_API}/repos/{full}/commits", params={"per_page": 30})
                commits = resp.json() if resp.status_code == 200 else []
            except Exception:
                return
            for c in commits if isinstance(commits, list) else []:
                commit = c.get("commit", {}) or {}
                for role in ("author", "committer"):
                    email = ((commit.get(role) or {}).get("email") or "").lower()
                    if (
                        email
                        and email != self.target_email
                        and not email.endswith("noreply.github.com")
                        and "@" in email
                    ):
                        leaked.add(email)

        # Scan the 15 most recently pushed repos to stay within rate limits.
        await asyncio.gather(*[commits_for(r) for r in repos[:15]])

        if leaked:
            findings.append(
                {
                    "type": "secondary_email_in_commits",
                    "category": "secondary/work email leaked via git history",
                    "detail": f"{len(leaked)} email address(es) other than the audited one appear as commit authors.",
                    "emails": sorted(leaked),
                    "source": f"https://github.com/{self.username}",
                }
            )
            sources.append(f"https://github.com/{self.username}")
        return leaked

    async def _scan_gists(self, client, findings, sources) -> bool:
        try:
            resp = await client.get(f"{GITHUB_API}/users/{self.username}/gists", params={"per_page": 100})
            gists = resp.json() if resp.status_code == 200 else []
        except Exception:
            gists = []

        secret_found = False
        for gist in gists if isinstance(gists, list) else []:
            html_url = gist.get("html_url", "")
            for fname, meta in (gist.get("files") or {}).items():
                raw_url = meta.get("raw_url")
                if not raw_url:
                    continue
                try:
                    raw = await client.get(raw_url)
                    if raw.status_code != 200 or len(raw.content) > 2_000_000:
                        continue
                    text = raw.text
                except Exception:
                    continue

                categories: list[str] = []
                for label, pat in SECRET_PATTERNS.items():
                    if pat.search(text):
                        categories.append(label)
                if ENV_LINE_RE.search(text):
                    categories.append(".env KEY=VALUE lines")
                if PHONE_RE.search(text):
                    categories.append("phone number")
                if PRIVATE_IP_RE.search(text):
                    categories.append("private IP address")
                other_emails = sorted(
                    {e.lower() for e in EMAIL_RE.findall(text) if e.lower() != self.target_email}
                )[:5]
                if other_emails:
                    categories.append("email address(es)")

                if categories:
                    if any(
                        c in categories
                        for c in list(SECRET_PATTERNS.keys()) + [".env KEY=VALUE lines"]
                    ):
                        secret_found = True
                    findings.append(
                        {
                            "type": "gist_sensitive_content",
                            "category": "secrets/PII in public gist",
                            "detail": f"'{fname}' contains: {', '.join(categories)}. (categories only — values not stored)",
                            "categories": categories,
                            "source": html_url,
                        }
                    )
                    sources.append(html_url)
        return secret_found

    async def _cross_platform(self, client, findings, sources) -> list[str]:
        u = self.username
        checks = {
            "npm": f"https://registry.npmjs.org/-/user/org.couchdb.user:{u}",
            "PyPI": f"https://pypi.org/user/{u}/",
            "Docker Hub": f"https://hub.docker.com/v2/users/{u}/",
        }
        public_urls = {
            "npm": f"https://www.npmjs.com/~{u}",
            "PyPI": f"https://pypi.org/user/{u}/",
            "Docker Hub": f"https://hub.docker.com/u/{u}",
        }
        found: list[str] = []

        async def check(platform: str, url: str) -> None:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    found.append(platform)
                    sources.append(public_urls[platform])
            except Exception:
                pass

        await asyncio.gather(*[check(p, url) for p, url in checks.items()])

        if found:
            findings.append(
                {
                    "type": "cross_platform_presence",
                    "category": "same handle published on package registries",
                    "detail": f"Account name reused on: {', '.join(found)}.",
                    "platforms": found,
                    "source": f"https://github.com/{u}",
                }
            )
        return found
