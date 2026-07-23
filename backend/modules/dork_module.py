"""Google-dork exposure module (build-order step 10).

Input: verified name / email / domain. Runs the SerpAPI dork set, classifies
each hit (document_exposure, social_profile, unexpected_mention,
cached_sensitive_page) and hands document URLs to metadata_module and social
URLs to social_content_module via the orchestrator (both keyed off `sources`).
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from modules.base import BaseModule, serpapi_search

DOC_EXT_RE = re.compile(r"\.(pdf|docx?)(\?|$)", re.IGNORECASE)
SOCIAL_HOST_RE = re.compile(
    r"linkedin\.com|reddit\.com|twitter\.com|x\.com|medium\.com|dev\.to|quora\.com",
    re.IGNORECASE,
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s.-]?){10,13}(?!\d)")
ADDRESS_RE = re.compile(r"\b\d{1,5}\s+\w+(\s\w+){0,3}\s+(street|st|ave|avenue|road|rd|blvd|drive|dr)\b", re.IGNORECASE)
FINANCIAL_RE = re.compile(r"\b(bank account|routing number|iban|credit card|swift code)\b", re.IGNORECASE)

TEMPLATES = [
    '"{name}" filetype:pdf',
    '"{name}" filetype:doc OR filetype:docx',
    '"{email}" -site:github.com -site:linkedin.com -site:twitter.com',
    '"{name}" "phone" OR "mobile" OR "contact"',
    '"{name}" "resume" OR "CV" OR "curriculum vitae"',
    'site:linkedin.com "{name}"',
    '"{name}" site:reddit.com',
    '"{name}" site:twitter.com OR site:x.com',
    '"{name}" site:medium.com',
    '"{name}" site:dev.to',
    '"{name}" site:quora.com',
    '"{name}" "date of birth" OR "born in" OR "age"',
    '"{name}" "works at" OR "employed at" OR "engineer at"',
]
DOMAIN_TEMPLATE = '"{domain}" "admin" OR "login" OR "dashboard"'


class DorkModule(BaseModule):
    name = "dork_module"

    def __init__(self, name: str, email: str, domain: Optional[str]) -> None:
        self.full_name = name or ""
        self.email = email or ""
        self.domain = domain or ""

    async def run(self) -> dict:
        if not self.full_name:
            return self.clean()

        queries = [t.format(name=self.full_name, email=self.email) for t in TEMPLATES]
        if self.domain:
            queries.append(DOMAIN_TEMPLATE.format(domain=self.domain))

        findings: list[dict] = []
        sources: list[str] = []
        seen: set[str] = set()

        results = await asyncio.gather(*[serpapi_search(q, num=10) for q in queries])

        for q, hits in zip(queries, results):
            for r in hits:
                url = r.get("link")
                if not url or url in seen:
                    continue
                seen.add(url)
                title = r.get("title", "")
                snippet = r.get("snippet", "")

                classification = self._classify(url, title, snippet)
                sensitive = self._flag_sensitive(snippet)

                findings.append(
                    {
                        "type": "dork_hit",
                        "category": classification,
                        "detail": f"{title} — {snippet}"[:300],
                        "sensitive_fields": sensitive,
                        "query": q,
                        "source": url,
                    }
                )
                sources.append(url)

        severity = self._severity(findings)
        return self.result(severity, findings, sources)

    @staticmethod
    def _classify(url: str, title: str, snippet: str) -> str:
        if DOC_EXT_RE.search(url):
            return "document_exposure"
        if SOCIAL_HOST_RE.search(url):
            return "social_profile"
        blob = f"{title} {snippet} {url}".lower()
        if any(k in blob for k in ("admin", "login", "dashboard")):
            return "cached_sensitive_page"
        return "unexpected_mention"

    @staticmethod
    def _flag_sensitive(snippet: str) -> list[str]:
        flags = []
        if PHONE_RE.search(snippet):
            flags.append("phone number")
        if ADDRESS_RE.search(snippet):
            flags.append("physical address")
        if FINANCIAL_RE.search(snippet):
            flags.append("financial info")
        return flags

    @staticmethod
    def _severity(findings: list[dict]) -> str:
        if any(f["sensitive_fields"] for f in findings):
            return "HIGH"
        if any(f["category"] == "cached_sensitive_page" for f in findings):
            return "HIGH"
        if len(findings) >= 3:
            return "MEDIUM"
        return "LOW" if findings else "CLEAN"
