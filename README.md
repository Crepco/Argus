# Argus — Personal OSINT Exposure Auditor

A **defensive** privacy tool. It shows you exactly what an attacker could find
about **an identity you can prove you control**, in under 10 minutes, then hands
you a prioritized remediation plan. Same category as Google's "Results about
you" and SpiderFoot — public sources only, no authenticated scraping, no
bypassing access controls, no long-term data storage.

## What makes this a self-audit tool (and not a targeting tool)

The single design decision that keeps this defensive is **ownership
verification**. You cannot scan an identifier you haven't proved you control:

| Identifier | Proof required before it is scanned |
|------------|-------------------------------------|
| Email      | One-time code sent to that inbox |
| GitHub     | OAuth login as that account |
| Domain     | DNS `TXT` challenge record |
| Usernames / LinkedIn | Only accepted **after** a primary identifier (email, GitHub, or domain) is verified |

`/api/audit/start` rejects any identifier without a valid, unexpired
verification token. A consent checkbox alone is not accepted — it can't
distinguish "auditing myself" from "profiling someone else."

Two further scopings vs. a generic OSINT tool:
- **No behavioral-routine extraction.** The social module flags whether you
  disclose location / employer / contact info. It does **not** mine daily
  patterns ("my commute", "every morning") — that's stalking intel, not a
  self-audit finding.
- **Breach/paste hunting is categories-only.** `email_hunter` reports *that* an
  address appears in a leak and *what category* of data sits near it. It never
  returns password, hash, or credential values.

## Architecture

```
React (Vite) ──POST /api/audit/start──▶ FastAPI ──asyncio.gather──▶ 8 modules
     ▲                                     │                            │
     └────── WebSocket /ws/audit/{id} ◀────┴──── Redis pub/sub ◀────────┘
                                           │
                                   OpenRouter (synthesis)
```

- **Backend:** FastAPI + Uvicorn, fully async (`httpx`, `asyncio`)
- **Session storage:** Redis, 30-minute TTL, no database
- **Streaming:** each module result is published to Redis and relayed to the
  browser over a WebSocket the moment it lands
- **Synthesis:** OpenRouter (`anthropic/claude-sonnet-4-6`)

## Quick start

```bash
# 1. Backend
python -m venv .venv && source .venv/Scripts/activate   # Windows Git Bash
pip install -r requirements.txt
cp .env.example .env        # fill in keys; VERIFICATION_SECRET is required
redis-server                # or point REDIS_URL at a running instance
uvicorn main:app --reload --app-dir backend

# 2. Frontend
cd frontend && npm install && npm run dev
```

With no `SMTP_*` configured, email one-time codes are printed to the backend
console — fine for local development.

## Ethical guardrails

1. Ownership verified before any identifier is scanned (see table above)
2. Consent checkbox required **in addition** to verification, validated backend-side
3. Rate limit: 3 audits per IP per hour
4. Redis TTL: all session data auto-purges after 30 minutes
5. No credential values ever returned — categories and patterns only
6. Metadata module skips files over 5 MB (PDF) / 2 MB (image); deletes after extraction
7. Max 50 paste URLs fetched per audit
8. Social module: public profiles only — no login, no cookies, no routine mining
9. User-Agent on all outbound requests: `OSINT-Privacy-Auditor/1.0 (Personal privacy audit tool)`
10. 1-second crawl delay between requests to the same domain
11. No database — zero long-term PII storage by design
