"""Social-profile content module (build-order step 8).

Input: public profile URLs (from username_module + dork_module) and the
verified email. Fetches ONLY publicly visible content — no login, no cookies,
no access-control bypass — across Reddit, dev.to, Gravatar, HackerNews, Medium,
and Nitter (Twitter/X mirror).

ETHICAL SCOPING (differs from a generic OSINT tool):
  * It flags disclosure CATEGORIES: location_disclosed, employer_disclosed,
    contact_info_disclosed, relationship_disclosed.
  * It does NOT extract behavioral routine ("every morning", "my commute",
    daily patterns). That is stalking intelligence, not a self-audit finding,
    and is intentionally excluded — do not add it back.

Severity: HIGH = location + employer both public, MEDIUM = any two categories,
LOW = a single category.
"""
from __future__ import annotations

import hashlib
import re

from modules.base import BaseModule, DomainRateLimiter, make_client

# Disclosure categories this module is allowed to detect. Note the deliberate
# absence of any "routine"/"schedule"/"commute" category.
ALLOWED_CATEGORIES = {
    "location_disclosed",
    "employer_disclosed",
    "contact_info_disclosed",
    "relationship_disclosed",
}

LOCATION_RE = re.compile(r"\bi live in\b|\bi'?m from\b|\bbased in\b", re.IGNORECASE)
EMPLOYER_RE = re.compile(r"\bi work at\b|\bmy job\b|\bmy company\b|\bworks? at\b|\bemployed at\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\s.-]?){10,13}(?!\d)")
RELATIONSHIP_RE = re.compile(r"\b(wife|husband|spouse|married to|fianc[eé]e?|partner of)\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
META_DESC_RE = re.compile(r'<meta[^>]+(?:property|name)="og:description"[^>]+content="([^"]*)"', re.IGNORECASE)

URL_PATTERNS = {
    "Reddit": re.compile(r"reddit\.com/u(?:ser)?/([A-Za-z0-9_-]+)", re.IGNORECASE),
    "Twitter/X": re.compile(r"nitter\.[^/]+/([A-Za-z0-9_]+)", re.IGNORECASE),
    "Medium": re.compile(r"medium\.com/@([A-Za-z0-9_.\-]+)", re.IGNORECASE),
    "dev.to": re.compile(r"dev\.to/(?!api)([A-Za-z0-9_-]+)", re.IGNORECASE),
    "HackerNews": re.compile(r"news\.ycombinator\.com/user\?id=([A-Za-z0-9_-]+)", re.IGNORECASE),
}


def _detect_categories(text: str) -> list[str]:
    found = []
    if LOCATION_RE.search(text):
        found.append("location_disclosed")
    if EMPLOYER_RE.search(text):
        found.append("employer_disclosed")
    if EMAIL_RE.search(text) or PHONE_RE.search(text):
        found.append("contact_info_disclosed")
    if RELATIONSHIP_RE.search(text):
        found.append("relationship_disclosed")
    return [c for c in found if c in ALLOWED_CATEGORIES]


class SocialContentModule(BaseModule):
    name = "social_content_module"

    def __init__(self, profile_urls: list[str], email: str) -> None:
        self.profile_urls = profile_urls or []
        self.email = (email or "").lower()
        self.limiter = DomainRateLimiter()

    async def run(self) -> dict:
        findings: list[dict] = []
        sources: list[str] = []

        async with make_client(timeout=12) as client:
            for platform, username in self._extract_handles():
                handler = getattr(self, f"_check_{platform.lower().replace('/', '').replace('.', '')}", None)
                if handler:
                    await handler(client, username, findings, sources)
            if self.email:
                await self._check_gravatar(client, findings, sources)

        if not findings:
            return self.clean()

        severity = self._severity(findings)
        return self.result(severity, findings, sources)

    def _extract_handles(self) -> list[tuple[str, str]]:
        handles: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for url in self.profile_urls:
            for platform, pat in URL_PATTERNS.items():
                m = pat.search(url)
                if m:
                    key = (platform, m.group(1).lower())
                    if key not in seen:
                        seen.add(key)
                        handles.append((platform, m.group(1)))
                    break
        return handles

    def _record(self, findings, sources, platform, url, categories, detail_extra=""):
        categories = [c for c in categories if c in ALLOWED_CATEGORIES]
        if not categories:
            return
        findings.append(
            {
                "type": "social_profile_disclosure",
                "category": f"public info disclosed on {platform}",
                "detail": f"{platform} profile discloses: {', '.join(categories)}.{detail_extra}",
                "platform": platform,
                "categories_disclosed": categories,
                "source": url,
            }
        )
        sources.append(url)

    # ------------------------------------------------------------------
    async def _check_reddit(self, client, username, findings, sources) -> None:
        await self.limiter.wait("reddit.com")
        profile_url = f"https://www.reddit.com/user/{username}/"
        try:
            about = await client.get(f"https://www.reddit.com/user/{username}/about.json")
            comments = await client.get(f"https://www.reddit.com/user/{username}/comments.json", params={"limit": 100})
        except Exception:
            return
        if about.status_code != 200:
            return

        text_blob = ""
        if comments.status_code == 200:
            try:
                data = comments.json()
                text_blob = " ".join(
                    (c.get("data", {}).get("body") or "") for c in data.get("data", {}).get("children", [])
                )
            except Exception:
                pass

        categories = _detect_categories(text_blob)
        try:
            karma = about.json().get("data", {})
            extra = f" Account karma: {karma.get('link_karma', 0) + karma.get('comment_karma', 0)}."
        except Exception:
            extra = ""
        self._record(findings, sources, "Reddit", profile_url, categories, extra)

    async def _check_twitterx(self, client, username, findings, sources) -> None:
        for mirror in ("nitter.net", "nitter.poast.org"):
            await self.limiter.wait(mirror)
            try:
                resp = await client.get(f"https://{mirror}/{username}")
                if resp.status_code == 200 and "user not found" not in resp.text.lower():
                    bio_match = META_DESC_RE.search(resp.text)
                    bio = bio_match.group(1) if bio_match else TAG_RE.sub(" ", resp.text)
                    categories = _detect_categories(bio)
                    self._record(findings, sources, "Twitter/X", f"https://{mirror}/{username}", categories)
                    return
            except Exception:
                continue

    async def _check_medium(self, client, username, findings, sources) -> None:
        await self.limiter.wait("medium.com")
        url = f"https://medium.com/@{username}"
        try:
            resp = await client.get(url)
        except Exception:
            return
        if resp.status_code != 200:
            return
        bio_match = META_DESC_RE.search(resp.text)
        bio = bio_match.group(1) if bio_match else ""
        self._record(findings, sources, "Medium", url, _detect_categories(bio))

    async def _check_devto(self, client, username, findings, sources) -> None:
        await self.limiter.wait("dev.to")
        try:
            resp = await client.get("https://dev.to/api/users/by_username", params={"url": username})
        except Exception:
            return
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except Exception:
            return
        categories = []
        if data.get("location"):
            categories.append("location_disclosed")
        categories += _detect_categories(data.get("summary") or "")
        self._record(findings, sources, "dev.to", f"https://dev.to/{username}", categories)

    async def _check_hackernews(self, client, username, findings, sources) -> None:
        await self.limiter.wait("hacker-news.firebaseio.com")
        try:
            resp = await client.get(f"https://hacker-news.firebaseio.com/v0/user/{username}.json")
        except Exception:
            return
        if resp.status_code != 200 or resp.text.strip() == "null":
            return
        try:
            about = TAG_RE.sub(" ", (resp.json() or {}).get("about") or "")
        except Exception:
            about = ""
        self._record(
            findings, sources, "HackerNews", f"https://news.ycombinator.com/user?id={username}", _detect_categories(about)
        )

    async def _check_gravatar(self, client, findings, sources) -> None:
        await self.limiter.wait("gravatar.com")
        md5 = hashlib.md5(self.email.encode()).hexdigest()
        url = f"https://www.gravatar.com/{md5}.json"
        try:
            resp = await client.get(url)
        except Exception:
            return
        if resp.status_code != 200:
            return
        try:
            entry = (resp.json().get("entry") or [None])[0]
        except Exception:
            entry = None
        if not entry:
            return

        categories = []
        if entry.get("currentLocation"):
            categories.append("location_disclosed")
        categories += _detect_categories(entry.get("aboutMe") or "")
        if entry.get("urls") or entry.get("accounts"):
            categories.append("contact_info_disclosed")
        self._record(findings, sources, "Gravatar", f"https://gravatar.com/{entry.get('preferredUsername', md5)}", categories)

    @staticmethod
    def _severity(findings: list[dict]) -> str:
        all_cats = {c for f in findings for c in f["categories_disclosed"]}
        if {"location_disclosed", "employer_disclosed"} <= all_cats:
            return "HIGH"
        if len(all_cats) >= 2:
            return "MEDIUM"
        return "LOW" if all_cats else "CLEAN"
