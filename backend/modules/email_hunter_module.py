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

from modules.base import BaseModule


class EmailHunterModule(BaseModule):
    name = "email_hunter_module"

    def __init__(self, email: str) -> None:
        self.email = (email or "").lower()
        self.local_part = self.email.split("@")[0] if "@" in self.email else self.email

    async def run(self) -> dict:
        # TODO(step 6): SerpAPI dork set -> raw fetch (<=2MB, <=50 urls)
        #   -> classify_leak_type / extract_sensitive_fields (CATEGORIES ONLY)
        #   -> detect_credential_pattern (SHAPE ONLY) -> extract_other_emails.
        return self.clean()
