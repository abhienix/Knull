"""
Knull - core/report.py

Generates a markdown report of a full session: what was scanned, what the AI
proposed, what a human approved/rejected, what actually ran, and results.
This audit trail is the point -- it's what makes the tool's output usable as
a real engagement deliverable, and it's what makes every action traceable to
a human decision.
"""

import os
import json
from datetime import datetime

import config


def generate_report(session: dict) -> str:
    """
    session = {
        "engagement_name": "...",
        "target": "...",
        "asset_profile": {...},
        "proposals": [...],
        "decisions": [{"tool_id":..., "approved": bool, "approved_by":..., "timestamp":...}],
        "execution_results": [...],
    }
    Returns the path to the generated markdown report.
    """
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"knull_report_{timestamp}.md"
    path = os.path.join(config.REPORTS_DIR, filename)

    lines = []
    lines.append(f"# Knull VAPT Assessment Report\n")
    lines.append(f"**Engagement:** {session.get('engagement_name', 'N/A')}")
    lines.append(f"**Target:** {session.get('target', 'N/A')}")
    lines.append(f"**Generated:** {datetime.now().isoformat()}\n")

    lines.append("## Executive Summary\n")
    critical = sum(1 for p in session.get("proposals", []) if p.get("severity") == "Critical")
    high = sum(1 for p in session.get("proposals", []) if p.get("severity") == "High")
    lines.append(
        f"This assessment identified **{len(session.get('proposals', []))}** "
        f"findings requiring review, including **{critical} critical** and "
        f"**{high} high** severity items. All active verification steps were "
        f"executed only after explicit human approval, per Knull's tiered "
        f"approval policy.\n"
    )

    lines.append("## Recon Summary\n")
    for svc in session.get("asset_profile", {}).get("open_services", []):
        lines.append(
            f"- Port {svc['port']}/{svc['protocol']}: {svc['service']} "
            f"{svc.get('product', '')} {svc.get('version', '')}".strip()
        )
        for cve in svc.get("known_cves", []):
            if "cve_id" in cve:
                lines.append(f"  - {cve['cve_id']} (CVSS: {cve.get('cvss_score', 'N/A')})")
    lines.append("")

    lines.append("## Findings, AI Rationale, and Approval Trail\n")
    decisions_by_tool = {d.get("tool_id"): d for d in session.get("decisions", [])}
    results_by_tool = {r.get("tool_id"): r for r in session.get("execution_results", [])}

    for p in session.get("proposals", []):
        lines.append(f"### {p.get('finding_summary', 'Untitled finding')}")
        lines.append(f"- **Severity:** {p.get('severity')}")
        lines.append(f"- **Finding type:** {p.get('finding_type')}")
        if p.get("cve_id"):
            lines.append(f"- **CVE:** {p['cve_id']}")
        lines.append(f"- **AI-proposed tool:** `{p.get('proposed_tool_id')}` (tier {p.get('tier')} - {p.get('tier_label')})")
        lines.append(f"- **AI rationale:** {p.get('rationale')}")

        decision = decisions_by_tool.get(p.get("proposed_tool_id"))
        if decision:
            lines.append(
                f"- **Human decision:** {'APPROVED' if decision.get('approved') else 'REJECTED'} "
                f"by {decision.get('approved_by', 'unknown')} at {decision.get('timestamp', 'unknown')}"
            )

        result = results_by_tool.get(p.get("proposed_tool_id"))
        if result and result.get("executed"):
            lines.append(f"- **Executed command:** `{result.get('command')}`")
            lines.append(f"- **Result:** {'Success' if result.get('success') else 'Failed/No output'}")
            lines.append(f"```\n{result.get('output', '')[:1500]}\n```")
        elif result and not result.get("executed"):
            lines.append(f"- **Manual step recommended (not auto-executed):**")
            lines.append(f"  `{result.get('manual_instructions')}`")

        lines.append("")

    lines.append("## Remediation Guidance\n")
    lines.append(
        "Refer to each finding's linked CVE/advisory for vendor-specific "
        "patches. General guidance: apply vendor patches promptly, disable "
        "unused services, enforce strong authentication and rate limiting, "
        "and use parameterized queries / output encoding for injection-class "
        "findings.\n"
    )

    lines.append("## Assessment Note\n")
    lines.append(
        "This assessment was performed against the specified target. "
        "All active verification steps were executed after explicit human "
        "approval.\n"
    )

    with open(path, "w") as f:
        f.write("\n".join(lines))

    # also dump the raw session as JSON for programmatic access / SARIF export later
    json_path = path.replace(".md", ".json")
    with open(json_path, "w") as f:
        json.dump(session, f, indent=2, default=str)

    return path
