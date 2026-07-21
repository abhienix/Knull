"""
Knull - routes/api.py

Flask blueprint implementing the full loop:
  POST /api/scan       -> recon (nmap + NVD), stores asset profile in session
  POST /api/advise      -> AI advisor proposes actions for the asset profile
  POST /api/approve     -> human approves/rejects a specific proposal
  POST /api/execute      -> runs an approved action (tier-gated)
  POST /api/report      -> generates the final markdown report
"""

from flask import Blueprint, request, jsonify
from datetime import datetime

from core import scanner, advisor, executor, scope, report

api = Blueprint("api", __name__)

# In-memory session store for this demo scaffold.
# Swap for a real DB (SQLite/Postgres) before any multi-user or persistent use.
SESSIONS = {}


@api.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")
    ports = data.get("ports", "1-1000")

    try:
        scope.assert_authorized(target)
    except scope.ScopeError as e:
        return jsonify({"error": str(e)}), 403

    asset_profile = scanner.build_asset_profile(target, ports)
    if "error" in asset_profile:
        return jsonify({"error": asset_profile["error"]}), 400

    session_id = f"sess_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    SESSIONS[session_id] = {
        "target": target,
        "asset_profile": asset_profile,
        "proposals": [],
        "decisions": [],
        "execution_results": [],
    }

    return jsonify({"session_id": session_id, "asset_profile": asset_profile})


@api.route("/api/advise", methods=["POST"])
def advise():
    data = request.get_json()
    session_id = data.get("session_id")
    session = SESSIONS.get(session_id)
    if not session:
        return jsonify({"error": "Unknown session_id"}), 404

    try:
        proposals = advisor.get_suggestions(session["asset_profile"])
        session["proposals"] = proposals
        return jsonify({"proposals": proposals})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route("/api/approve", methods=["POST"])
def approve():
    data = request.get_json()
    session_id = data.get("session_id")
    session = SESSIONS.get(session_id)
    if not session:
        return jsonify({"error": "Unknown session_id"}), 404

    decision = {
        "tool_id": data.get("tool_id"),
        "approved": data.get("approved", False),
        "approved_by": data.get("approved_by", "unspecified_operator"),
        "timestamp": datetime.now().isoformat(),
    }
    session["decisions"].append(decision)
    return jsonify({"status": "recorded", "decision": decision})


@api.route("/api/execute", methods=["POST"])
def execute():
    data = request.get_json()
    session_id = data.get("session_id")
    session = SESSIONS.get(session_id)
    if not session:
        return jsonify({"error": "Unknown session_id"}), 404

    action = {
        "tool_id": data.get("tool_id"),
        "target": session["target"],
        "template": data.get("template"),
        "approved": data.get("approved", False),
        "typed_confirmation": data.get("typed_confirmation"),
        "bucket": data.get("bucket"),
        "key": data.get("key"),
    }

    try:
        result = executor.execute_action(action)
    except executor.ExecutionError as e:
        return jsonify({"error": str(e)}), 403
    except scope.ScopeError as e:
        return jsonify({"error": str(e)}), 403

    session["execution_results"].append({**result, "tool_id": action["tool_id"]})
    return jsonify(result)


@api.route("/api/report", methods=["POST"])
def build_report():
    data = request.get_json()
    session_id = data.get("session_id")
    session = SESSIONS.get(session_id)
    if not session:
        return jsonify({"error": "Unknown session_id"}), 404

    session["engagement_name"] = data.get("engagement_name", "Unnamed Engagement")
    path = report.generate_report(session)
    return jsonify({"report_path": path})
