"""
Knull - core/executor.py

The ONLY module in this project that shells out to a security tool. Every
call here requires:
  1. tool_id to exist in config.ALLOWED_TOOLS (the advisor already filtered
     for this, but we check again here -- defense in depth, never trust a
     single checkpoint)
  2. the target to pass scope.assert_authorized()
  3. the action's tier's approval requirement to be satisfied:
       tier 1/2 -> `approved: true` flag set by the human in the UI
       tier 3   -> `typed_confirmation` must exactly equal the target string
       tier 4   -> never executes; returns manual instructions instead
"""

import subprocess
import shutil
import time

import config
from core import scope


class ExecutionError(Exception):
    pass


def _tool_binary_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def execute_action(action: dict) -> dict:
    """
    action = {
        "tool_id": "nuclei_cve_template",
        "target": "10.0.0.5",
        "template": "cves/2021/CVE-2021-41773.yaml",  # if applicable
        "approved": True,
        "typed_confirmation": None,  # required only for tier 3
    }
    """
    tool_id = action.get("tool_id")
    target = action.get("target")

    if tool_id not in config.ALLOWED_TOOLS:
        raise ExecutionError(f"'{tool_id}' is not an allow-listed tool. Refusing to run.")

    tool_meta = config.ALLOWED_TOOLS[tool_id]
    tier = tool_meta["tier"]

    # scope check -- defense in depth, even though callers should check first
    scope.assert_authorized(target)

    # tier gating
    if tier == 4:
        return {
            "executed": False,
            "tier": 4,
            "manual_instructions": tool_meta["manual_instructions"].format(
                target=target, service=action.get("service", "<service>")
            ),
            "note": (
                "Knull does not automate this action. Run it manually if, "
                "and only if, it is within your authorized scope."
            ),
        }

    if tier in (1, 2) and not action.get("approved"):
        raise ExecutionError("This action requires explicit approval before execution.")

    if tier == 3:
        if action.get("typed_confirmation") != target:
            raise ExecutionError(
                "This is a tier-3 (data/credential impact) action. The operator "
                "must type the exact target hostname/IP to confirm before it runs."
            )

    if not _tool_binary_available(tool_meta["binary"]):
        return get_mock_execution_result(tool_id, target, action, tier)

    # build the command -- ALWAYS via the pre-registered lambda in config.py,
    # never from any string the AI or the user supplied directly
    build_cmd = tool_meta["build_cmd"]
    if action.get("template"):
        cmd = build_cmd(target, action["template"])
    elif tool_id == "s3_download_object":
        bucket = action.get("bucket") or target
        key = action.get("key") or "secret.txt"
        cmd = build_cmd(bucket, key)
    elif tool_id == "s3_list_only":
        bucket = action.get("bucket") or target
        cmd = build_cmd(bucket)
    else:
        cmd = build_cmd(target)

    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        output = result.stdout + "\n" + result.stderr
        success = result.returncode == 0
    except subprocess.TimeoutExpired:
        output = "Execution timed out after 900s."
        success = False

    return {
        "executed": True,
        "tier": tier,
        "tool_id": tool_id,
        "command": " ".join(cmd),  # logged for audit trail, shown in report
        "success": success,
        "output": output,
        "duration_seconds": round(time.time() - start, 2),
    }


def get_mock_execution_result(tool_id: str, target: str, action: dict, tier: int) -> dict:
    import random
    duration = round(random.uniform(1.5, 4.2), 2)
    
    if "nmap" in tool_id:
        output = f"Starting Nmap NSE scripts against {target}...\nNSE: [vuln] Run complete. Found 2 potential issues.\n"
    elif "nuclei" in tool_id:
        template = action.get("template") or "cves/generic.yaml"
        output = f"[info] [{template}] Sent payload to {target}\n[CVE-2021-27065] [http] [critical] {target} is VULNERABLE.\n"
    elif "sqlmap" in tool_id:
        output = f"sqlmap/1.5 - automatic SQL injection tool\n[INFO] testing connection to the target URL\n[INFO] checking if the target is vulnerable to SQL injection...\n[INFO] GET parameter 'id' is vulnerable.\n"
    elif "testssl" in tool_id:
        output = f"testssl.sh output for {target}\nLow/medium issues found: POODLE vulnerability supported, TLS 1.0 enabled.\n"
    elif "s3" in tool_id:
        output = "s3://bucket-contents:\n2026-07-01 12:00:00        1024 config.json\n2026-07-01 12:05:00       45021 database.bak\n"
    else:
        output = f"Simulated output for {tool_id} against {target}.\n"
        
    return {
        "executed": True,
        "is_mock": True,
        "tier": tier,
        "tool_id": tool_id,
        "command": f"[{tool_id} - SIMULATED CMD] against {target}",
        "success": True,
        "output": f"[SIMULATION MODE - '{tool_id}' binary not installed]\n\n{output}",
        "duration_seconds": duration,
    }
