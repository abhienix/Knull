# Knull

**AI-assisted recon, triage, and human-gated verification for authorized VAPT engagements.**

Knull automates the tedious parts of a vulnerability assessment — scanning,
CVE correlation, and picking the right verification tool for each finding —
while keeping every action that touches a live target behind an explicit
human decision. It is a decision-support and orchestration tool, not an
autonomous attack tool.

## Architecture

```
 Recon (nmap + NVD)
        │
        ▼
 AI Advisor  ──── classifies findings, proposes a tool from a fixed allow-list
        │          (never writes its own shell command / exploit code)
        ▼
 Approval Queue ── human reviews each proposal; approval friction scales
        │          with risk tier (see below)
        ▼
 Executor  ─────── runs ONLY pre-registered, allow-listed tool invocations
        │          against scope-checked targets
        ▼
 Report  ───────── full audit trail: finding → AI rationale → who approved
                    what, when → command run → result → remediation
```

## Risk tiers (config.py -> RISK_TIERS)

| Tier | Meaning | Approval required |
|---|---|---|
| 1 | Detection / passive (nmap scripts, Nuclei templates, testssl, wpscan enum) | One click |
| 2 | Active but non-destructive verification (sqlmap detect-only, dalfox) | One click + warning shown |
| 3 | Touches real data/credentials (sqlmap `--dump`, S3 object download) | Operator must type the target hostname back to confirm |
| 4 | Never automated (e.g. Hydra default-credential checks) | Knull shows the manual command; you run it yourself, by hand, if in scope |

This tiering is the actual security boundary of the project — see
`core/executor.py` and `config.py::ALLOWED_TOOLS`.

## Setup

```bash
git clone <this repo>
cd knull
pip install -r requirements.txt
cp .env.example .env        # add your GROQ_API_KEY
cp scope/authorization.example.json scope/authorization.json
# edit scope/authorization.json with YOUR actual authorized targets and dates
python app.py
```

Knull **refuses to scan or execute anything** if `scope/authorization.json`
doesn't exist, is outside its date window, or doesn't list the target. This
is enforced in code (`core/scope.py`), not just documented.

### Installing the underlying tools
Knull orchestrates existing, established tools — it does not reimplement
them. Install whichever you plan to use and make sure they're on `PATH`:
`nmap`, `nuclei`, `testssl.sh`, `wpscan`, `dalfox`, `sqlmap`, `aws-cli`.
Any tool not installed will simply fail at execution time with a clear error.

## What Knull will NOT do

- It will not auto-generate or run raw exploit code. The AI advisor only ever
  selects a `tool_id` from a fixed table (`config.ALLOWED_TOOLS`); anything
  it proposes outside that table is silently dropped before it reaches you.
- It will not run credential brute-forcing (Hydra) automatically, ever,
  regardless of settings — this is a tier-4, manual-only action by design,
  because every attempt is a real authentication event with real side
  effects (lockouts, alerting).
- It will not execute against a target that isn't in your signed
  authorization scope file, even if you type it into the UI directly.
- It will not skip the typed-confirmation step for tier-3 (data/credential
  impact) actions — this is checked server-side, not just hidden by the UI.

## Legal

For authorized use only. Only scan and test systems you own or have
explicit, documented, written permission to test, within the dates specified
in your authorization scope. Unauthorized scanning or exploitation is illegal
in most jurisdictions.

## Roadmap ideas (not yet built)
- KEV/EPSS-based prioritization alongside raw CVSS
- Scheduled re-scans with diffing against prior sessions
- SARIF export for CI/CD integration
- Second-model cross-check on AI-proposed severity/classification
- OWASP Top 10 / PCI-DSS finding tagging
