"""Phone-number exposure module.

Input: an optional phone number. Reports two things:

  1. What anyone can infer just from the digits themselves — region, carrier,
     line type — via offline libphonenumber data (no lookup service, no
     network call for this part; this is standard phone-format metadata, the
     same thing any spam caller's phone already shows them).
  2. Whether the number turns up in a public paste-site leak, mirroring
     email_hunter_module's dork search + leak classification (same HARD RULE:
     categories and patterns only, never credential values).
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

import phonenumbers
from phonenumbers import carrier as pn_carrier, geocoder as pn_geocoder

from config import settings
from modules.base import BaseModule, DomainRateLimiter, make_client, serpapi_search
from modules.email_hunter_module import (
    _to_raw_url,
    classify_leak_type,
    detect_credential_pattern,
    extract_other_emails,
    extract_sensitive_fields,
)

NUMBER_TYPE_LABELS = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared cost",
    phonenumbers.PhoneNumberType.VOIP: "VOIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal number",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
}

DORK_TEMPLATES = [
    'site:pastebin.com "{phone}"',
    'site:paste.ee "{phone}"',
    'site:rentry.co "{phone}"',
    'site:psbdmp.ws "{phone}"',
    '"{phone}" leaked OR dump OR breach',
    '"{phone}" resume OR cv OR contact',
    '"{phone}" whatsapp OR telegram',
    '"{phone}" -site:truecaller.com -site:whitepages.com',
]


def _digits_only(s: str) -> str:
    return re.sub(r"\D", "", s or "")


class PhoneModule(BaseModule):
    name = "phone_module"

    def __init__(self, phone: Optional[str]) -> None:
        self.raw = (phone or "").strip()
        self.limiter = DomainRateLimiter()

    async def run(self) -> dict:
        if not self.raw:
            return self.clean()

        try:
            parsed = phonenumbers.parse(self.raw, None)
        except phonenumbers.NumberParseException:
            return self.clean()

        if not phonenumbers.is_valid_number(parsed):
            return self.clean()

        findings: list[dict] = []
        sources: list[str] = []

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        digits = _digits_only(e164)
        national_digits = _digits_only(national)

        self._add_format_finding(parsed, findings)

        urls = await self._collect_candidate_urls(e164)
        if urls:
            # Bounded concurrency: sequential fetches of up to MAX_PASTE_URLS
            # third-party pages (each with its own 10s timeout) can add up to
            # minutes of wall time if a few are slow/unresponsive — phone_module's
            # dork set is less site:-scoped than email_hunter's, so results land
            # on more arbitrary (and occasionally slow) domains.
            semaphore = asyncio.Semaphore(10)

            async def bounded_scan(client, url: str) -> None:
                async with semaphore:
                    await self._scan_url(client, url, digits, national_digits, findings, sources)

            async with make_client(timeout=10) as client:
                await asyncio.gather(*[bounded_scan(client, url) for url in urls[: settings.MAX_PASTE_URLS]])

        severity = self._severity(findings)
        return self.result(severity, findings, sources)

    # ------------------------------------------------------------------
    def _add_format_finding(self, parsed, findings: list[dict]) -> None:
        region = pn_geocoder.description_for_number(parsed, "en")
        carrier_name = pn_carrier.name_for_number(parsed, "en")
        line_type = NUMBER_TYPE_LABELS.get(phonenumbers.number_type(parsed), "unknown")

        parts = [f"line type: {line_type}"]
        if region:
            parts.append(f"region: {region}")
        if carrier_name:
            parts.append(f"carrier: {carrier_name}")

        findings.append(
            {
                "type": "phone_format_info",
                "category": "publicly inferable from the number itself",
                "detail": (
                    f"Anyone with this number can derive: {', '.join(parts)}. "
                    "(No lookup service used — this is standard phone-number-format metadata.)"
                ),
                "region": region or None,
                "carrier": carrier_name or None,
                "line_type": line_type,
                "source": "",
            }
        )

    async def _collect_candidate_urls(self, e164: str) -> list[str]:
        queries = [t.format(phone=e164) for t in DORK_TEMPLATES]
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

    async def _scan_url(
        self, client, url: str, digits: str, national_digits: str, findings: list[dict], sources: list[str]
    ) -> None:
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
            line_digits = _digits_only(line)
            if digits not in line_digits and national_digits not in line_digits:
                continue
            context = "\n".join(lines[max(0, i - 5): i + 6])
            leak_type = classify_leak_type(context)
            fields = extract_sensitive_fields(context)
            pattern = detect_credential_pattern(line)
            other_emails = extract_other_emails(context, "")

            findings.append(
                {
                    "type": "phone_in_paste",
                    "category": f"phone number found in paste ({leak_type.replace('_', ' ')})",
                    "detail": (
                        f"Phone number appears in a {leak_type.replace('_', ' ')} at {url}."
                        + (f" Nearby fields: {', '.join(fields)}." if fields else "")
                    ),
                    "leak_type": leak_type,
                    "sensitive_fields": fields,
                    "credential_pattern": pattern,
                    "other_emails_in_dump": other_emails,
                    "source": url,
                }
            )
            sources.append(url)
            break  # one finding per URL is enough signal

    @staticmethod
    def _severity(findings: list[dict]) -> str:
        paste_hits = [f for f in findings if f["type"] == "phone_in_paste"]
        if not paste_hits:
            return "LOW" if findings else "CLEAN"
        types = {f["leak_type"] for f in paste_hits}
        has_cred_pattern = any(f["credential_pattern"] for f in paste_hits)
        if "credential_dump" in types or has_cred_pattern:
            return "CRITICAL"
        if types & {"database_export", "doxx_file", "combo_list", "api_key_leak"}:
            return "HIGH"
        if any(f["sensitive_fields"] for f in paste_hits):
            return "MEDIUM"
        return "LOW"
