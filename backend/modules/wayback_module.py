"""Wayback Machine module (build-order step 9).

Input: a *verified* domain. Pulls archived snapshots via the CDX API and scans
priority pages (/about, /contact, /resume, /cv, /, /team) for PII that may have
been removed from the live site but survives in the archive.

Enforces a 1-second delay between fetches to the same host (base.DomainRateLimiter).
"""
from __future__ import annotations

import re

from modules.base import BaseModule, FREEMAIL_DOMAINS, DomainRateLimiter, make_client

PRIORITY_PATHS = {"/about", "/contact", "/resume", "/cv", "/", "/index.html", "/team", "/people"}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s.-]?){10,13}(?!\d)")
ADDRESS_RE = re.compile(r"\b\d{1,5}\s+\w+(\s\w+){0,3}\s+(street|st|ave|avenue|road|rd|blvd|drive|dr)\b", re.IGNORECASE)
EMPLOYER_RE = re.compile(r"\b(works at|employed at|employee of|works for)\b", re.IGNORECASE)
RELATIONSHIP_RE = re.compile(r"\b(wife|husband|spouse|married to|fianc[eé]e?|partner of)\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")


class WaybackModule(BaseModule):
    name = "wayback_module"

    def __init__(self, domain: str) -> None:
        self.domain = (domain or "").lower().strip()
        self.limiter = DomainRateLimiter()

    async def run(self) -> dict:
        if not self.domain or self.domain in FREEMAIL_DOMAINS:
            return self.clean()

        snapshots = await self._priority_snapshots()
        if not snapshots:
            return self.clean()

        findings: list[dict] = []
        sources: list[str] = []

        async with make_client(timeout=15) as client:
            for original, timestamp in snapshots:
                await self.limiter.wait("web.archive.org")
                archive_url = f"http://web.archive.org/web/{timestamp}/{original}"
                try:
                    resp = await client.get(archive_url)
                    if resp.status_code != 200:
                        continue
                    text = TAG_RE.sub(" ", resp.text)
                except Exception:
                    continue

                categories = self._categorize(text)
                if categories:
                    findings.append(
                        {
                            "type": "archived_pii",
                            "category": "PII found in archived snapshot",
                            "detail": f"Archived {timestamp} version of {original} exposes: {', '.join(categories)}.",
                            "categories": categories,
                            "timestamp": timestamp,
                            "source": archive_url,
                        }
                    )
                    sources.append(archive_url)

        severity = self._severity(findings)
        return self.result(severity, findings, sources)

    async def _priority_snapshots(self) -> list[tuple[str, str]]:
        try:
            async with make_client(timeout=15) as client:
                resp = await client.get(
                    "http://web.archive.org/cdx/search/cdx",
                    params={
                        "url": f"{self.domain}/*",
                        "output": "json",
                        "limit": 100,
                        "fl": "original,timestamp",
                    },
                )
                if resp.status_code != 200:
                    return []
                rows = resp.json()
        except Exception:
            return []

        if not rows or len(rows) < 2:
            return []

        latest: dict[str, str] = {}
        for original, timestamp in rows[1:]:
            path = self._path_of(original)
            if path in PRIORITY_PATHS:
                if path not in latest or timestamp > latest[path][1]:
                    latest[path] = (original, timestamp)

        return [v for v in latest.values()]

    @staticmethod
    def _path_of(url: str) -> str:
        m = re.match(r"^https?://[^/]+(/.*)?$", url)
        path = (m.group(1) if m and m.group(1) else "/")
        return path.split("?")[0].rstrip("/") or "/"

    def _categorize(self, text: str) -> list[str]:
        categories = []
        if PHONE_RE.search(text):
            categories.append("phone number")
        if ADDRESS_RE.search(text):
            categories.append("physical address")
        other_emails = {e.lower() for e in EMAIL_RE.findall(text)}
        if other_emails:
            categories.append("email address")
        if EMPLOYER_RE.search(text):
            categories.append("employer mention")
        if RELATIONSHIP_RE.search(text):
            categories.append("personal relationship mention")
        return categories

    @staticmethod
    def _severity(findings: list[dict]) -> str:
        all_cats = {c for f in findings for c in f["categories"]}
        if {"phone number", "physical address", "email address"} & all_cats:
            return "HIGH"
        if {"employer mention", "personal relationship mention"} & all_cats:
            return "MEDIUM"
        return "LOW" if findings else "CLEAN"
