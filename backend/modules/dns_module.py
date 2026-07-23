"""DNS / domain exposure module (build-order step 9).

Input: a *verified* domain. Reports WHOIS registrant leakage, subdomains from
Certificate Transparency (crt.sh), DNS records, and reverse-IP co-hosting.
"""
from __future__ import annotations

import asyncio
import re

import dns.asyncresolver
import dns.resolver
import whois

from modules.base import BaseModule, FREEMAIL_DOMAINS, make_client

SUSPICIOUS_SUBDOMAIN_RE = re.compile(
    r"^(admin|dev|staging|internal|api|mail|vpn|test|beta|git|jenkins|jira)\.", re.IGNORECASE
)


class DnsModule(BaseModule):
    name = "dns_module"

    def __init__(self, domain: str) -> None:
        self.domain = (domain or "").lower().strip()

    async def run(self) -> dict:
        if not self.domain or self.domain in FREEMAIL_DOMAINS:
            return self.clean()

        findings: list[dict] = []
        sources: list[str] = []

        registrant_hit, subdomains, records, cohosted = await asyncio.gather(
            self._whois(findings, sources),
            self._subdomains(findings, sources),
            self._dns_records(findings, sources),
            self._reverse_ip(findings, sources),
        )

        if registrant_hit:
            severity = "HIGH"
        elif any(f["type"] == "suspicious_subdomain" for f in findings) or cohosted:
            severity = "MEDIUM"
        elif findings:
            severity = "LOW"
        else:
            severity = "CLEAN"

        return self.result(severity, findings, sources)

    # ------------------------------------------------------------------
    async def _whois(self, findings, sources) -> bool:
        try:
            w = await asyncio.wait_for(asyncio.to_thread(whois.whois, self.domain), timeout=15)
        except Exception:
            return False

        exposed = {}
        for field in ("name", "emails", "phone", "address", "org"):
            value = getattr(w, field, None) if hasattr(w, field) else w.get(field) if isinstance(w, dict) else None
            if value:
                exposed[field] = value if isinstance(value, str) else ", ".join(str(v) for v in value if v)

        if exposed:
            findings.append(
                {
                    "type": "whois_registrant_exposed",
                    "category": "domain registrant PII not redacted",
                    "detail": f"WHOIS record exposes: {', '.join(exposed.keys())}.",
                    "fields": exposed,
                    "source": f"https://whois.arin.net/rest/{self.domain}",
                }
            )
            sources.append(f"https://whois.arin.net/rest/{self.domain}")
            return True
        return False

    async def _subdomains(self, findings, sources) -> list[str]:
        try:
            async with make_client(timeout=15) as client:
                resp = await client.get(
                    "https://crt.sh/", params={"q": self.domain, "output": "json"}
                )
                if resp.status_code != 200:
                    return []
                entries = resp.json()
        except Exception:
            return []

        names: set[str] = set()
        for entry in entries if isinstance(entries, list) else []:
            for line in (entry.get("name_value") or "").split("\n"):
                line = line.strip().lower().lstrip("*.")
                if line.endswith(self.domain) and line != self.domain:
                    names.add(line)

        suspicious = sorted(n for n in names if SUSPICIOUS_SUBDOMAIN_RE.match(n))
        crt_url = f"https://crt.sh/?q={self.domain}"
        if names:
            findings.append(
                {
                    "type": "subdomains_enumerated",
                    "category": "subdomains discovered via certificate transparency",
                    "detail": f"{len(names)} subdomain(s) have ever been issued a public TLS certificate.",
                    "subdomains": sorted(names)[:50],
                    "source": crt_url,
                }
            )
            sources.append(crt_url)
        if suspicious:
            findings.append(
                {
                    "type": "suspicious_subdomain",
                    "category": "internal-looking subdomain publicly certified",
                    "detail": f"Subdomain name(s) suggest non-public tooling: {', '.join(suspicious)}.",
                    "subdomains": suspicious,
                    "source": crt_url,
                }
            )
            sources.append(crt_url)
        return sorted(names)

    async def _dns_records(self, findings, sources) -> dict:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        out: dict[str, list[str]] = {}

        async def lookup(rtype: str) -> None:
            try:
                answer = await resolver.resolve(self.domain, rtype)
                out[rtype] = [r.to_text() for r in answer]
            except Exception:
                pass

        await asyncio.gather(*[lookup(rt) for rt in ("A", "AAAA", "MX", "TXT", "NS")])

        if out:
            provider = self._mail_provider(out.get("MX", []))
            detail = f"Resolved records: {', '.join(sorted(out.keys()))}."
            if provider:
                detail += f" Mail provider: {provider}."
            findings.append(
                {
                    "type": "dns_records",
                    "category": "public DNS records",
                    "detail": detail,
                    "records": out,
                    "source": f"https://dns.google/query?name={self.domain}",
                }
            )
            sources.append(f"https://dns.google/query?name={self.domain}")
        return out

    @staticmethod
    def _mail_provider(mx_records: list[str]) -> str:
        joined = " ".join(mx_records).lower()
        if "google" in joined or "gmail" in joined:
            return "Google Workspace"
        if "outlook" in joined or "protection.outlook" in joined:
            return "Microsoft 365"
        if "zoho" in joined:
            return "Zoho Mail"
        return ""

    async def _reverse_ip(self, findings, sources) -> list[str]:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout, resolver.lifetime = 5, 5
            answer = await resolver.resolve(self.domain, "A")
            ip = answer[0].to_text()
        except Exception:
            return []

        try:
            async with make_client(timeout=15) as client:
                resp = await client.get(
                    "https://api.hackertarget.com/reverseiplookup/", params={"q": ip}
                )
                text = resp.text if resp.status_code == 200 else ""
        except Exception:
            return []

        if "error" in text.lower() or "API count exceeded" in text:
            return []

        others = sorted({line.strip().lower() for line in text.splitlines() if line.strip() and line.strip().lower() != self.domain})
        if others:
            source = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            findings.append(
                {
                    "type": "reverse_ip_cohosted",
                    "category": "other domains sharing the same IP",
                    "detail": f"{len(others)} other domain(s) are hosted on the same IP ({ip}), possibly revealing other projects.",
                    "domains": others[:25],
                    "source": source,
                }
            )
            sources.append(source)
        return others
