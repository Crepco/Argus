"""Gemini (Google Generative Language API) LLM client. Single entry point for
all synthesis calls."""
import httpx

from config import settings

MODEL = "gemini-2.5-flash"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"


async def call_llm(system_prompt: str, user_message: str, max_tokens: int = 8000) -> str:
    if not settings.GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not configured")

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            GEMINI_URL,
            params={"key": settings.GEMINI_API_KEY},
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": user_message}]}],
                "systemInstruction": {"parts": [{"text": system_prompt}]},
                "generationConfig": {
                    "maxOutputTokens": max_tokens,
                    # Gemini 2.5's "thinking" tokens count against maxOutputTokens and
                    # are spent BEFORE the visible answer — with many findings to
                    # synthesize, that was eating the budget and truncating the JSON
                    # before it closed. Not needed for this structured-output task.
                    "thinkingConfig": {"thinkingBudget": 0},
                },
            },
        )
        response.raise_for_status()
        data = response.json()
        candidate = data["candidates"][0]
        parts = candidate.get("content", {}).get("parts", [])
        if not parts:
            raise RuntimeError(f"Gemini returned no content (finishReason={candidate.get('finishReason')})")
        return "".join(p.get("text", "") for p in parts)
