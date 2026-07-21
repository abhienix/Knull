"""
Knull - core/assistant.py

Conversational AI Assistant engine. Provides a chat interface where Knull acts
as a security assistant talking to the pentester in natural language.
"""

import json
import requests
from dotenv import load_dotenv

load_dotenv()

import config
from core import scanner, advisor, executor, report

CHAT_SYSTEM_PROMPT = """You are Knull, an AI Penetration Testing & Security Audit Assistant.
You converse with the security operator in a professional, conversational manner.

YOUR PERSONALITY & RESPONSE STYLE:
- Talk like a colleague pentester in real-time.
- State clearly what you scanned, discovered, and triaged.
- Format findings into brief, human-friendly summaries:
  "I scanned {target} and found ports 80 and 443 open. Here's what I observed..."
  "I found missing HSTS/CSP headers. We can run testssl_scan or nuclei_misconfig_template to verify further."
- Ask for operator approval before running active verification actions.
- Keep responses concise, clear, and actionable.

AVAILABLE TOOLS ALLOW-LIST:
{tool_catalog}
"""

def _tool_catalog_text() -> str:
    lines = []
    for tool_id, meta in config.ALLOWED_TOOLS.items():
        lines.append(f"- {tool_id} (tier {meta['tier']}): {meta['description']}")
    return "\n".join(lines)


def chat_response(history: list, user_message: str, current_session: dict = None) -> dict:
    """
    Processes chat input from the user, invokes tools/recon if requested,
    and returns conversational AI response.
    """
    if not config.GROQ_API_KEY:
        return {"response": "GROQ_API_KEY is missing in your .env file."}

    system_prompt = CHAT_SYSTEM_PROMPT.format(tool_catalog=_tool_catalog_text())
    messages = [{"role": "system", "content": system_prompt}]

    # Include session context if active
    if current_session and current_session.get("asset_profile"):
        context_str = f"ACTIVE TARGET SESSION: {json.dumps(current_session['asset_profile'])}"
        messages.append({"role": "system", "content": context_str})

    # Append chat history
    for h in history[-8:]:
        messages.append({"role": h["role"], "content": h["content"]})

    messages.append({"role": "user", "content": user_message})

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"},
            json={
                "model": config.GROQ_MODEL,
                "messages": messages,
                "temperature": 0.4,
                "max_tokens": 800,
            },
            timeout=45,
        )
        resp.raise_for_status()
        reply_text = resp.json()["choices"][0]["message"]["content"]
        return {"response": reply_text}
    except Exception as e:
        return {"response": f"Knull AI Engine Error: {str(e)}"}
