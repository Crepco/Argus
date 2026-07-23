"""LLM synthesis of all module results into a single report (OpenRouter)."""
import json

from llm_client import call_llm

SYSTEM_PROMPT = """
You are a privacy and security analyst generating a personal data exposure
report from an automated scan of publicly available information only. The
person being scanned has verified they own the identifiers involved — this is
a self-audit.

Rules:
- Every claim must cite a specific source URL from the findings provided.
- Never invent, speculate, or hallucinate findings not present in the data.
- Never include actual passwords, hashes, or credential values — categories only.
- Cross-link findings across sources where the same data appears in multiple places.
- Write plain English a non-technical person can understand.
- The attacker_simulation must be realistic and grounded ONLY in what was found.

Output ONLY valid JSON, no preamble, no markdown fences:

{
  "overall_severity": "CRITICAL | HIGH | MEDIUM | LOW | MINIMAL",
  "digital_footprint_score": {
    "score": 0,
    "explanation": "plain English explanation of the score"
  },
  "executive_summary": "2-3 sentence plain English overview",
  "attacker_simulation": "Paragraph in attacker POV — what someone could do with this public information in 15 minutes",
  "platforms_exposed": ["list of confirmed platforms"],
  "data_categories_exposed": ["location", "employer", "credentials", "..."],
  "cross_linked_findings": [
    {"description": "Finding spanning multiple sources", "sources": ["url1", "url2"], "severity": "HIGH"}
  ],
  "remediation_plan": {
    "critical": [{"action": "...", "reason": "...", "source": "url"}],
    "medium":   [{"action": "...", "reason": "...", "source": "url"}],
    "low":      [{"action": "...", "reason": "...", "source": "url"}]
  }
}
""".strip()


async def synthesize(all_results: list[dict]) -> dict:
    user_message = json.dumps(all_results, indent=2, default=str)
    raw = await call_llm(SYSTEM_PROMPT, user_message)
    raw = raw.strip()
    # Tolerate a stray ```json fence even though the prompt forbids it.
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1].lstrip("json").strip("` \n")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "overall_severity": "LOW",
            "executive_summary": "Synthesis could not be parsed into structured JSON.",
            "raw": raw,
        }
