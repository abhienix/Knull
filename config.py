"""
Knull - AI-Assisted VAPT Assistant
config.py

Central configuration. This file is the single source of truth for:
  - which tools Knull is allowed to execute at all (ALLOWED_TOOLS)
  - what risk tier each action type sits at, and what that tier requires
    before execution is permitted (RISK_TIERS)

Design principle: the AI advisor layer NEVER constructs a raw shell command.
It only ever returns a `tool_id` + `template_id` that must already exist in
ALLOWED_TOOLS below. If the AI proposes something not in this table, the
executor rejects it outright. This file is the actual security boundary of
the whole project -- treat changes to it with the same care as changes to
firewall rules.
"""

import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- LLM provider -----------------------------------------------------------
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = "llama-3.3-70b-versatile"

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # optional, raises rate limit

# --- Storage -----------------------------------------------------------------
SCOPE_FILE = os.path.join(BASE_DIR, "scope", "authorization.json")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")

# --- Risk tiers ---------------------------------------------------------------
# tier 1: passive / detection-only. Auto-eligible for one-click approval.
# tier 2: active but non-destructive verification. Requires explicit approval
#         (still one click, but shown with a visible warning banner).
# tier 3: touches real data or real credentials. Requires TYPED confirmation
#         (user must type the target hostname back) before it can run.
# tier 4: never auto-executed by Knull under any configuration. Knull will
#         surface these as a recommended manual step only, with instructions,
#         and will not shell out to run them itself.
RISK_TIERS = {
    1: {
        "label": "Detection / passive",
        "approval": "one_click",
        "description": "Read-only checks against public/known signatures. No live exploitation attempt.",
    },
    2: {
        "label": "Active verification",
        "approval": "one_click_with_warning",
        "description": "Sends crafted-but-benign requests to confirm a suspected issue exists. No data extracted, no credentials used.",
    },
    3: {
        "label": "Data/credential impact",
        "approval": "typed_confirmation",
        "description": "Would extract real data or submit real credentials against a live target. Requires the operator to type the target back to confirm.",
    },
    4: {
        "label": "Manual only - not automated",
        "approval": "not_executable",
        "description": "Knull will recommend this step and show the exact manual command, but will never execute it itself.",
    },
}

# --- Allow-listed tools --------------------------------------------------------
# This is the ONLY set of actions the AI advisor is permitted to select from.
# Each entry: how to invoke it, what risk tier it sits at, and a human-readable
# description shown in the approval queue.
ALLOWED_TOOLS = {

    "nmap_vuln_scripts": {
        "tier": 1,
        "binary": "nmap",
        "build_cmd": lambda target: ["nmap", "-sV", "--script", "vuln", target],
        "description": "Runs nmap's built-in NSE vulnerability-detection scripts against the target.",
    },

    "nuclei_cve_template": {
        "tier": 1,
        "binary": "nuclei",
        "build_cmd": lambda target, template: ["nuclei", "-u", target, "-t", template, "-silent"],
        "description": "Runs a specific, named Nuclei community template matched to a known CVE.",
    },

    "nuclei_misconfig_template": {
        "tier": 1,
        "binary": "nuclei",
        "build_cmd": lambda target, template: ["nuclei", "-u", target, "-t", template, "-silent"],
        "description": "Runs a Nuclei misconfiguration/best-practice template (headers, defaults, etc.).",
    },

    "testssl_scan": {
        "tier": 1,
        "binary": "testssl.sh",
        "build_cmd": lambda target: ["testssl.sh", "--quiet", "--jsonfile-pretty", "-", target],
        "description": "Checks TLS/SSL configuration, cipher support, and known TLS vulnerabilities.",
    },

    "wpscan_enumerate": {
        "tier": 1,
        "binary": "wpscan",
        "build_cmd": lambda target: ["wpscan", "--url", target, "--enumerate", "vp", "--no-banner"],
        "description": "Enumerates WordPress plugin versions and checks against known vulnerabilities.",
    },

    "dalfox_xss_scan": {
        "tier": 2,
        "binary": "dalfox",
        "build_cmd": lambda target: ["dalfox", "url", target, "--silence"],
        "description": "Sends benign test payloads to confirm reflected/stored XSS. Does not exfiltrate anything.",
    },

    "sqlmap_detect_only": {
        "tier": 2,
        "binary": "sqlmap",
        "build_cmd": lambda target: [
            "sqlmap", "-u", target, "--batch", "--level=1", "--risk=1",
            "--no-cast", "--disable-coloring",
        ],
        "description": "Detects likely SQL injection only. Explicitly excludes --dump, --os-shell, and any data-extraction flags.",
    },

    "sqlmap_extract_data": {
        "tier": 3,
        "binary": "sqlmap",
        "build_cmd": lambda target: ["sqlmap", "-u", target, "--batch", "--dump"],
        "description": "Extracts real data from a confirmed-vulnerable database. Requires typed confirmation.",
    },

    "s3_list_only": {
        "tier": 1,
        "binary": "aws",
        "build_cmd": lambda bucket: ["aws", "s3", "ls", f"s3://{bucket}", "--no-sign-request"],
        "description": "Lists bucket contents only. Does not download any object.",
    },

    "s3_download_object": {
        "tier": 3,
        "binary": "aws",
        "build_cmd": lambda bucket, key: ["aws", "s3", "cp", f"s3://{bucket}/{key}", "./evidence/", "--no-sign-request"],
        "description": "Downloads a specific object from a publicly listable bucket as evidence. Requires typed confirmation.",
    },

    "hydra_default_creds": {
        "tier": 4,
        "binary": "hydra",
        "build_cmd": None,  # deliberately not automated -- see manual_instructions
        "manual_instructions": (
            "hydra -L wordlists/small_known_defaults_users.txt "
            "-P wordlists/small_known_defaults_pass.txt "
            "-t 4 -W 30 {target} {service}"
        ),
        "description": (
            "Default/weak credential check against a live login service. "
            "Knull will NOT run this automatically under any settings -- every "
            "attempt is a real authentication event with real side effects "
            "(lockouts, alerting). Knull surfaces this as a recommended manual "
            "step with the exact command an operator should run by hand, "
            "against a small known-defaults list only."
        ),
    },
}
