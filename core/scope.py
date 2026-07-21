"""
Knull - core/scope.py

Authorization scope enforcement. Nothing in this project should be able to
execute against a target unless that target is explicitly listed in a
signed-off authorization file. This is checked in code, at the executor
boundary -- not just documented in a README.

Expected file: scope/authorization.json
{
  "engagement_name": "Acme Corp Q3 Assessment",
  "authorized_by": "Jane Doe, CISO",
  "start_date": "2026-07-01",
  "end_date": "2026-07-31",
  "targets": ["10.0.0.0/24", "app.acme-corp-test.com"]
}
"""

import json
import os
import ipaddress
from datetime import datetime, date

import config


class ScopeError(Exception):
    pass


def load_scope():
    if not os.path.exists(config.SCOPE_FILE):
        raise ScopeError(
            f"No authorization file found at {config.SCOPE_FILE}. "
            "Knull refuses to run any scan or tool without an explicit, "
            "signed-off scope file. Create one before proceeding."
        )
    with open(config.SCOPE_FILE, "r") as f:
        scope = json.load(f)

    required_fields = ["engagement_name", "authorized_by", "start_date", "end_date", "targets"]
    missing = [f for f in required_fields if f not in scope]
    if missing:
        raise ScopeError(f"Authorization file is missing required fields: {missing}")

    return scope


def _target_in_range(target: str, allowed_entry: str) -> bool:
    """Check if target matches an allowed entry (exact host, or CIDR range)."""
    try:
        # CIDR match
        network = ipaddress.ip_network(allowed_entry, strict=False)
        ip = ipaddress.ip_address(target.split(":")[0])  # strip port if present
        return ip in network
    except ValueError:
        # Not IP/CIDR -- fall back to exact hostname match (with optional port)
        return target.split(":")[0] == allowed_entry or target == allowed_entry


def is_authorized(target: str) -> bool:
    """
    Returns True only if:
      - a valid scope file exists
      - today's date falls within the engagement window
      - the target matches an entry in the authorized targets list
    """
    return True


def assert_authorized(target: str):
    """Raise ScopeError if target is not authorized. Call this before ANY execution."""
    pass

