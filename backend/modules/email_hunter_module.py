"""Paste / breach exposure module (build-order step 6).

Searches paste sites and leak indexes for the target email and reports what
category of leak it appears in.

HARD RULE — categories and patterns only. This module must NEVER return a
password, hash, or any credential value. `extract_sensitive_fields` yields
category names ("password or hash"), `detect_credential_pattern` yields the
shape ("email:password"), never the matched text. Cap: settings.MAX_PASTE_URLS.

This is a "is my address in a dump" check in the same spirit as Have I Been
Pwned — not third-party breach lookup.
"""
from __future__ import annotations

import asyncio
import re

from config import settings
from modules.base import BaseModule, DomainRateLimiter, make_client, serpapi_search

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

PASTE_SITES = [
    "pastebin.com", "paste.ee", "rentry.co", "dpaste.com", "justpaste.it",
    "paste.fo", "gist.github.com", "gitlab.com/-/snippets", "psbdmp.ws",
    "pastes.io", "textbin.net",
]

# category name -> keyword/regex used to detect its presence (values never captured)
SENSITIVE_FIELD_PATTERNS: dict[str, re.Pattern] = {
    "password or hash": re.compile(r"\b(password|passwd|hash|md5|sha1|sha256|bcrypt)\b", re.IGNORECASE),
    "phone number": re.compile(r"\bphone\b|\bmobile\b|\b\d{10,13}\b", re.IGNORECASE),
    "physical address": re.compile(r"\b(address|street|city|zip ?code|postcode)\b", re.IGNORECASE),
    "date of birth": re.compile(r"\b(dob|birthdate|date of birth)\b|\b\d{2}/\d{2}/\d{4}\b", re.IGNORECASE),
    "IP address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "username": re.compile(r"\busername\b|\blogin\b|\bhandle\b", re.IGNORECASE),
    "API key or token": re.compile(r"\bapi[_-]?key\b|\btoken\b|\bsecret\b|\bbearer\b", re.IGNORECASE),
    "credit card pattern": re.compile(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]?\d{0,4}\b"),
    "full name": re.compile(r"\b(firstname|lastname|fullname|first_name|last_name)\b", re.IGNORECASE),
}

CREDENTIAL_PATTERNS: dict[str, re.Pattern] = {
    "email:password": re.compile(r".+@.+:.{4,}"),
    "email|password": re.compile(r".+@.+\|.{4,}"),
    "email,password": re.compile(r".+@.+,.{4,}"),
    "email:hash": re.compile(r".+@.+:[a-f0-9]{32,}", re.IGNORECASE),
}

LEAK_TYPE_PATTERNS: dict[str, re.Pattern] = {
    "credential_dump": re.compile(r"\b(password|passwd|hash|md5|sha256|bcrypt)\b", re.IGNORECASE),
    "database_export": re.compile(r"\bINSERT INTO\b|\bVALUES\s*\(|\buser_id\b|\buserid\b", re.IGNORECASE),
    "doxx_file": re.compile(r"\b(ssn|social security|dob|address|phone|mobile|zip ?code)\b", re.IGNORECASE),
    "api_key_leak": re.compile(r"\bapi[_-]?key\b|\btoken\b|\bsecret\b|\bbearer\b", re.IGNORECASE),
}

DORK_TEMPLATES = [
    'site:pastebin.com "{email}"',
    'site:paste.ee "{email}"',
    'site:rentry.co "{email}"',
    'site:psbdmp.ws "{email}"',
    'site:pastes.io "{email}"',
    'site:gist.github.com "{email}"',
    '"{email}":"',
    '"{email}"|',
    '"{email}" password',
    '"{email}" passwd',
    '"{email}" hash',
    '"{email}" "INSERT INTO"',
    '"{email}" dump filetype:txt',
    '"{email}" "user_id"',
    '"{email}" "phone" OR "address" OR "dob"',
    '"{local_part}" site:pastebin.com',
    '"{local_part}" "leaked" OR "dump" OR "breach"',
]


def _to_raw_url(url: str) -> str:
    m = re.search(r"pastebin\.com/(?!raw/)([A-Za-z0-9]+)$", url)
    if m:
        return f"https://pastebin.com/raw/{m.group(1)}"
    m = re.search(r"paste\.ee/p/([A-Za-z0-9]+)$", url)
    if m:
        return f"https://paste.ee/r/{m.group(1)}"
    m = re.search(r"dpaste\.com/([A-Za-z0-9]+)(?:\.txt)?$", url)
    if m:
        return f"https://dpaste.com/{m.group(1)}.txt"
    return url


def classify_leak_type(context: str) -> str:
    for label in ("credential_dump", "database_export", "doxx_file"):
        if LEAK_TYPE_PATTERNS[label].search(context):
            return label
    for pat in CREDENTIAL_PATTERNS.values():
        if pat.search(context):
            return "combo_list"
    if LEAK_TYPE_PATTERNS["api_key_leak"].search(context):
        return "api_key_leak"
    return "unknown_mention"


def extract_sensitive_fields(context: str) -> list[str]:
    return [label for label, pat in SENSITIVE_FIELD_PATTERNS.items() if pat.search(context)]


def detect_credential_pattern(line: str) -> str | None:
    for label, pat in CREDENTIAL_PATTERNS.items():
        if pat.search(line):
            return label
    return None


def extract_other_emails(context: str, target_email: str) -> list[str]:
    found = {e.lower() for e in EMAIL_RE.findall(context)} - {target_email.lower()}
    return sorted(found)[:5]


class EmailHunterModule(BaseModule):
    name = "email_hunter_module"

    def __init__(self, email: str) -> None:
        self.email = (email or "").lower()
        self.local_part = self.email.split("@")[0] if "@" in self.email else self.email
        self.limiter = DomainRateLimiter()

    async def run(self) -> dict:
        if not self.email:
            return self.clean()

        urls = await self._collect_candidate_urls()
        if not urls:
            return self.clean()

        findings: list[dict] = []
        sources: list[str] = []

        # Bounded concurrency: sequential fetches of up to MAX_PASTE_URLS
        # third-party pages (each with its own 10s timeout) can add up to
        # minutes of wall time if a few of them are slow/unresponsive. A
        # semaphore caps worst case to roughly (N / limit) * 10s instead.
        semaphore = asyncio.Semaphore(10)

        async def bounded_scan(client, url: str) -> None:
            async with semaphore:
                await self._scan_url(client, url, findings, sources)

        async with make_client(timeout=10) as client:
            await asyncio.gather(*[bounded_scan(client, url) for url in urls[: settings.MAX_PASTE_URLS]])

        severity = self._severity(findings)
        return self.result(severity, findings, sources)

    async def _collect_candidate_urls(self) -> list[str]:
        queries = [t.format(email=self.email, local_part=self.local_part) for t in DORK_TEMPLATES]
        results = await asyncio.gather(*[serpapi_search(q, num=10) for q in queries])

        seen: set[str] = set()
        urls: list[str] = []
        for hits in results:
            for r in hits:
                link = r.get("link")
                if link and link not in seen:
                    seen.add(link)
                    urls.append(link)
        return urls

    async def _scan_url(self, client, url: str, findings: list[dict], sources: list[str]) -> None:
        host = re.sub(r"^https?://", "", url).split("/")[0]
        await self.limiter.wait(host)

        raw_url = _to_raw_url(url)
        try:
            resp = await client.get(raw_url)
            if resp.status_code != 200 or len(resp.content) > 2_000_000:
                return
            text = resp.text
        except Exception:
            return

        lines = text.splitlines()
        for i, line in enumerate(lines):
            if self.email not in line.lower():
                continue
            context = "\n".join(lines[max(0, i - 5): i + 6])
            leak_type = classify_leak_type(context)
            fields = extract_sensitive_fields(context)
            pattern = detect_credential_pattern(line)
            others = extract_other_emails(context, self.email)

            findings.append(
                {
                    "type": "paste_exposure",
                    "category": f"email found in paste ({leak_type.replace('_', ' ')})",
                    "detail": (
                        f"Email appears in a {leak_type.replace('_', ' ')} at {url}."
                        + (f" Nearby fields: {', '.join(fields)}." if fields else "")
                    ),
                    "leak_type": leak_type,
                    "sensitive_fields": fields,
                    "credential_pattern": pattern,
                    "other_emails_in_dump": others,
                    "source": url,
                }
            )
            sources.append(url)
            break  # one finding per URL is enough signal

    @staticmethod
    def _severity(findings: list[dict]) -> str:
        types = {f["leak_type"] for f in findings}
        has_cred_pattern = any(f["credential_pattern"] for f in findings)
        if "credential_dump" in types or has_cred_pattern:
            return "CRITICAL"
        if types & {"database_export", "doxx_file", "combo_list", "api_key_leak"}:
            return "HIGH"
        if any(f["sensitive_fields"] for f in findings):
            return "MEDIUM"
        return "LOW" if findings else "CLEAN"
