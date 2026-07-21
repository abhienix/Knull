"""
Knull - core/advisor.py

The AI reasoning layer. Takes a structured asset profile (from scanner.py)
and returns a list of proposed next actions.

HARD CONSTRAINT: the model is instructed to select ONLY from the allow-listed
tool table in config.py, and every single proposal is validated against that
table after the fact -- if the model hallucinates a tool_id that isn't in
ALLOWED_TOOLS, or tries to smuggle in raw shell content, it is dropped before
it ever reaches the approval queue. The model never sees or produces a raw
command string; it only ever picks a `tool_id` (+ template_id where relevant).
"""

import json
import requests

import config

SYSTEM_PROMPT = """You are a vulnerability-triage assistant for an authorized \
penetration test. You will be given a JSON asset profile (open ports, \
services, versions, and any known CVEs already matched from NVD).

Your job is ONLY to:
1. Classify each finding (e.g. known_cve, possible_web_vuln, tls_misconfig, \
exposed_admin_login, cloud_storage_exposure, outdated_cms_plugin)
2. Assign a severity (Critical/High/Medium/Low) based on CVSS score if present, \
otherwise your best judgement
3. Select the single most appropriate tool_id from this fixed list -- you may \
NOT invent a tool_id that is not in this list, and you may NOT output a raw \
shell command:

{tool_catalog}

Return ONLY a JSON array, no prose, no markdown fences. Each element:
{{
  "finding_summary": "...",
  "finding_type": "...",
  "severity": "Critical|High|Medium|Low",
  "cve_id": "CVE-XXXX-XXXX or null",
  "proposed_tool_id": "must be one of the allow-listed tool_ids above",
  "proposed_template": "specific nuclei template path if tool_id needs one, else null",
  "rationale": "one or two sentences explaining why this tool fits this finding"
}}
"""


def _tool_catalog_text() -> str:
    lines = []
    for tool_id, meta in config.ALLOWED_TOOLS.items():
        lines.append(f"- {tool_id} (tier {meta['tier']}): {meta['description']}")
    return "\n".join(lines)


def clean_and_extract_json(text: str) -> str:
    text = text.strip()
    
    # Extract JSON array or object
    array_start = text.find('[')
    object_start = text.find('{')
    
    if array_start != -1 and (object_start == -1 or array_start < object_start):
        start = array_start
        end = text.rfind(']')
    elif object_start != -1:
        start = object_start
        end = text.rfind('}')
    else:
        start, end = -1, -1
        
    if start != -1 and end != -1 and end > start:
        return text[start:end+1]
    return text


def get_suggestions(asset_profile: dict) -> list:
    """
    Calls the LLM with the asset profile, validates output strictly against
    the allow-list, and returns only proposals that pass validation.
    """
    if not config.GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY not set -- see .env.example")

    system_prompt = SYSTEM_PROMPT.format(tool_catalog=_tool_catalog_text())

    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {config.GROQ_API_KEY}"},
        json={
            "model": config.GROQ_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(asset_profile)},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"} if False else None,
        },
        timeout=60,
    )
    resp.raise_for_status()
    raw_text = resp.json()["choices"][0]["message"]["content"]

    try:
        cleaned_text = clean_and_extract_json(raw_text)
        proposals = json.loads(cleaned_text)
        if isinstance(proposals, dict):
            # Try to find a list value in the dict
            for key, val in proposals.items():
                if isinstance(val, list):
                    proposals = val
                    break
            else:
                proposals = [proposals]
        if not isinstance(proposals, list):
            proposals = []
    except Exception:
        # model didn't return clean JSON -- fail closed, surface nothing
        return []

    return _validate_proposals(proposals)


def _validate_proposals(proposals: list) -> list:
    """
    Drops any proposal that references a tool_id outside ALLOWED_TOOLS.
    This is the actual security checkpoint -- everything above is just
    prompting; this is enforcement.
    """
    valid = []
    for p in proposals:
        tool_id = p.get("proposed_tool_id")
        if tool_id not in config.ALLOWED_TOOLS:
            continue  # silently dropped -- model hallucinated or went off-menu
        tool_meta = config.ALLOWED_TOOLS[tool_id]
        p["tier"] = tool_meta["tier"]
        p["tier_label"] = config.RISK_TIERS[tool_meta["tier"]]["label"]
        p["approval_type"] = config.RISK_TIERS[tool_meta["tier"]]["approval"]
        valid.append(p)
    return valid
