"""Social-profile content module (build-order step 8).

Input: public profile URLs (from username_module + dork_module) and the
verified email. Fetches ONLY publicly visible content — no login, no cookies,
no access-control bypass — across Reddit, dev.to, Gravatar, HackerNews, Medium,
and Nitter (Twitter/X mirror).

ETHICAL SCOPING (differs from a generic OSINT tool):
  * It flags disclosure CATEGORIES: location_disclosed, employer_disclosed,
    contact_info_disclosed.
  * It does NOT extract behavioral routine ("every morning", "my commute",
    daily patterns). That is stalking intelligence, not a self-audit finding,
    and is intentionally excluded — do not add it back.

Severity: HIGH = location + employer both public, MEDIUM = one of them + contact
info, LOW = a single category.
"""
from __future__ import annotations

from modules.base import BaseModule, DomainRateLimiter

# Disclosure categories this module is allowed to detect. Note the deliberate
# absence of any "routine"/"schedule"/"commute" category.
ALLOWED_CATEGORIES = {
    "location_disclosed",
    "employer_disclosed",
    "contact_info_disclosed",
    "relationship_disclosed",
}


class SocialContentModule(BaseModule):
    name = "social_content_module"

    def __init__(self, profile_urls: list[str], email: str) -> None:
        self.profile_urls = profile_urls or []
        self.email = (email or "").lower()
        self.limiter = DomainRateLimiter()

    async def run(self) -> dict:
        if not self.profile_urls:
            return self.clean()
        # TODO(step 8): per-platform public fetch (rate-limited) -> detect only
        #   ALLOWED_CATEGORIES -> return categories + source URL, never post text
        #   and never routine/schedule patterns.
        return self.clean()
