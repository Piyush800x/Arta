"""
gemini_client.py — Thin wrapper around google-generativeai.

Every agent calls ask() or ask_json(). Rate-limit handling and
retry logic live here so agents stay clean.
"""

import asyncio
import json
import re
import google.generativeai as genai
from config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

MODEL = "gemini-flash-lite-latest"

# Gemini free tier: 15 req/min — enforce a small gap between calls.
_CALL_DELAY_SECONDS = 4


async def ask(prompt: str) -> str:
    """Send a plain text prompt. Returns the response as a string."""
    await asyncio.sleep(_CALL_DELAY_SECONDS)
    model = genai.GenerativeModel(MODEL)
    response = await asyncio.to_thread(model.generate_content, prompt)
    return response.text


async def ask_json(prompt: str) -> dict | list:
    """
    Send a prompt that expects a JSON response.
    - Strips markdown fences if Gemini wraps the output in them.
    - Retries once with extraction if JSON parsing fails.
    """
    full_prompt = prompt + "\n\nRespond ONLY with valid JSON. No markdown, no explanation."
    raw = await ask(full_prompt)

    # Strip ```json ... ``` fences
    cleaned = raw.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
    cleaned = re.sub(r"```$",          "", cleaned).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to extract the first JSON object/array from surrounding text
        match = re.search(r"(\{.*\}|\[.*\])", cleaned, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        raise
