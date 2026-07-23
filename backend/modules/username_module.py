"""Cross-platform username module (build-order step 7).

Uses Sherlock to find which platforms a handle is claimed on. High-value
platforms (Twitter/X, Reddit, Instagram, LinkedIn, Keybase, Gravatar, ...) are
flagged, and discovered profile URLs are passed to social_content_module.

Severity: HIGH >=10 platforms, MEDIUM 5-9, LOW <5.
"""
from __future__ import annotations

from typing import Optional

from modules.base import BaseModule

HIGH_VALUE = {
    "Twitter", "X", "Reddit", "Instagram", "TikTok", "LinkedIn", "Facebook",
    "Steam", "HackerNews", "dev.to", "Medium", "Keybase", "Gravatar", "Twitch",
    "YouTube", "Pinterest", "Telegram", "Mastodon", "Bluesky", "Snapchat",
    "Discord", "Spotify", "SoundCloud", "Behance", "Dribbble",
}


class UsernameModule(BaseModule):
    name = "username_module"

    def __init__(self, github_username: Optional[str], usernames: list[str], email: str) -> None:
        candidates: list[str] = []
        if github_username:
            candidates.append(github_username)
        candidates.extend(usernames or [])
        if email and "@" in email:
            candidates.append(email.split("@")[0])
        # de-dupe, preserve order
        seen: set[str] = set()
        self.usernames = [u for u in candidates if u and not (u.lower() in seen or seen.add(u.lower()))]

    async def run(self) -> dict:
        if not self.usernames:
            return self.clean()
        # TODO(step 7): asyncio.to_thread(sherlock, username) per handle;
        #   collect "Claimed" sites; flag HIGH_VALUE; tag profile URLs for
        #   social_content_module; severity by platform count.
        return self.clean()
