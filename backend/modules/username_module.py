"""Cross-platform username module (build-order step 7).

Runs direct, verifiable existence checks (not the full sherlock-project
library — its public API is CLI-only and its ~400-site sweep returns a lot of
soft-404 false positives for anonymous requests) against a curated set of
platforms where "claimed" vs "not claimed" can be told apart reliably:
Reddit, Hacker News, dev.to, Keybase, Steam, Behance, Dribbble, SoundCloud,
Pinterest, Medium, and Twitter/X (via a Nitter mirror). Discovered profile
URLs are picked up by the orchestrator and forwarded to social_content_module.

Severity (relative to the 11 platforms checked here): HIGH >=6, MEDIUM 3-5, LOW 1-2.
"""
from __future__ import annotations

import asyncio
import json as _json
from typing import Optional

from modules.base import BaseModule, make_client

HIGH_VALUE = {
    "Reddit", "HackerNews", "dev.to", "Keybase", "Steam", "Behance",
    "Dribbble", "SoundCloud", "Pinterest", "Medium", "Twitter/X",
}


def _checker(status_ok, not_found_markers=()):
    def check(status_code: int, text: str) -> bool:
        if not status_ok(status_code):
            return False
        lowered = text.lower()
        return not any(marker in lowered for marker in not_found_markers)

    return check


async def _reddit_check(status_code: int, text: str) -> bool:
    if status_code != 200:
        return False
    try:
        return bool(_json.loads(text).get("data"))
    except Exception:
        return False


async def _hn_check(status_code: int, text: str) -> bool:
    return status_code == 200 and text.strip() != "null"


async def _keybase_check(status_code: int, text: str) -> bool:
    if status_code != 200:
        return False
    try:
        data = _json.loads(text)
        return data.get("status", {}).get("code") == 0 and bool(data.get("them")) and data["them"][0] is not None
    except Exception:
        return False


PLATFORMS: dict[str, dict] = {
    "Reddit": {
        "url": "https://www.reddit.com/user/{u}/about.json",
        "checker": _reddit_check,
        "public_url": "https://www.reddit.com/user/{u}/",
    },
    "HackerNews": {
        "url": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
        "checker": _hn_check,
        "public_url": "https://news.ycombinator.com/user?id={u}",
    },
    "dev.to": {
        "url": "https://dev.to/api/users/by_username?url={u}",
        "checker": lambda sc, t: sc == 200,
        "public_url": "https://dev.to/{u}",
    },
    "Keybase": {
        "url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}",
        "checker": _keybase_check,
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{u}?xml=1",
        "checker": lambda sc, t: sc == 200 and "could not be found" not in t.lower(),
        "public_url": "https://steamcommunity.com/id/{u}",
    },
    "Behance": {
        "url": "https://www.behance.net/{u}",
        "checker": lambda sc, t: sc == 200,
    },
    "Dribbble": {
        "url": "https://dribbble.com/{u}",
        "checker": lambda sc, t: sc == 200,
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{u}",
        "checker": lambda sc, t: sc == 200 and "we can't find that page" not in t.lower(),
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{u}/",
        "checker": lambda sc, t: sc == 200,
    },
    "Medium": {
        "url": "https://medium.com/@{u}",
        "checker": lambda sc, t: sc == 200,
    },
    "Twitter/X": {
        "url": "https://nitter.net/{u}",
        "checker": lambda sc, t: sc == 200 and "user not found" not in t.lower(),
    },
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
        seen: set[str] = set()
        self.usernames = [u for u in candidates if u and not (u.lower() in seen or seen.add(u.lower()))]

    async def run(self) -> dict:
        if not self.usernames:
            return self.clean()

        found: list[dict] = []
        sources: list[str] = []

        async with make_client(timeout=8) as client:
            for username in self.usernames:
                await self._check_all_platforms(client, username, found, sources)

        if not found:
            return self.clean()

        high_value_hits = [f["found_platform"] for f in found if f["found_platform"] in HIGH_VALUE]
        count = len(found)
        severity = "HIGH" if count >= 6 else "MEDIUM" if count >= 3 else "LOW"

        summary_finding = {
            "type": "cross_platform_footprint",
            "category": "public profiles found across platforms",
            "detail": f"Found on {count} platform(s): {', '.join(f['found_platform'] for f in found)}.",
            "found_platforms": [f["found_platform"] for f in found],
            "profiles": found,
            "source": sources[0] if sources else "",
        }
        return self.result(severity, [summary_finding], sources)

    async def _check_all_platforms(self, client, username: str, found: list[dict], sources: list[str]) -> None:
        async def check_one(platform: str, cfg: dict) -> None:
            url = cfg["url"].format(u=username)
            try:
                resp = await client.get(url)
                text = resp.text
            except Exception:
                return
            try:
                ok = cfg["checker"](resp.status_code, text)
                if asyncio.iscoroutine(ok):
                    ok = await ok
            except Exception:
                ok = False
            if ok:
                public_url = cfg.get("public_url", cfg["url"]).format(u=username)
                found.append({"found_platform": platform, "username": username, "url": public_url})
                sources.append(public_url)

        await asyncio.gather(*[check_one(p, cfg) for p, cfg in PLATFORMS.items()])
