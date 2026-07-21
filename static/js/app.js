let currentSessionId = null;

async function runScan() {
  const target = document.getElementById("target-input").value.trim();
  const ports = document.getElementById("ports-input").value.trim() || "1-1000";
  const out = document.getElementById("scan-output");
  out.textContent = "Scanning... this can take a minute.";

  const resp = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, ports }),
  });
  const data = await resp.json();

  if (data.error) {
    out.textContent = "Error: " + data.error;
    return;
  }

  currentSessionId = data.session_id;
  out.textContent = JSON.stringify(data.asset_profile, null, 2);
  document.getElementById("advise-section").style.display = "block";
}

async function getAdvice() {
  const resp = await fetch("/api/advise", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId }),
  });
  const data = await resp.json();
  renderProposals(data.proposals || []);
  document.getElementById("report-section").style.display = "block";
}

function renderProposals(proposals) {
  const container = document.getElementById("proposals-list");
  container.innerHTML = "";

  proposals.forEach((p) => {
    const div = document.createElement("div");
    div.className = "proposal tier-" + p.tier;

    let approvalControls = "";
    if (p.approval_type === "one_click" || p.approval_type === "one_click_with_warning") {
      approvalControls = `
        <button onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', false)">Approve & Run</button>
        <button class="reject" onclick="reject('${p.proposed_tool_id}')">Reject</button>`;
    } else if (p.approval_type === "typed_confirmation") {
      approvalControls = `
        <p class="danger">⚠ This action touches real data/credentials. Type the target to confirm:</p>
        <input type="text" id="confirm-${p.proposed_tool_id}" placeholder="Type target exactly">
        <button onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', true)">Confirm & Run</button>
        <button class="reject" onclick="reject('${p.proposed_tool_id}')">Reject</button>`;
    } else if (p.approval_type === "not_executable") {
      approvalControls = `<p class="manual-note">This step is manual-only — Knull will not auto-execute it. See recommendation below.</p>`;
    }

    div.innerHTML = `
      <h3>${p.finding_summary}</h3>
      <p><strong>Severity:</strong> ${p.severity} | <strong>Tier:</strong> ${p.tier} (${p.tier_label})</p>
      <p><strong>Proposed tool:</strong> ${p.proposed_tool_id}</p>
      <p><strong>Rationale:</strong> ${p.rationale}</p>
      <div class="controls">${approvalControls}</div>
      <pre id="result-${p.proposed_tool_id}"></pre>
    `;
    container.appendChild(div);
  });
}

async function approveAndRun(toolId, template, needsTypedConfirm) {
  await fetch("/api/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: currentSessionId,
      tool_id: toolId,
      approved: true,
      approved_by: "operator",
    }),
  });

  const payload = {
    session_id: currentSessionId,
    tool_id: toolId,
    template: template || null,
    approved: true,
  };

  if (needsTypedConfirm) {
    const confirmInput = document.getElementById(`confirm-${toolId}`);
    payload.typed_confirmation = confirmInput ? confirmInput.value.trim() : "";
  }

  const resp = await fetch("/api/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  document.getElementById(`result-${toolId}`).textContent = JSON.stringify(data, null, 2);
}

async function reject(toolId) {
  await fetch("/api/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: currentSessionId,
      tool_id: toolId,
      approved: false,
      approved_by: "operator",
    }),
  });
  document.getElementById(`result-${toolId}`).textContent = "Rejected by operator.";
}

async function generateReport() {
  const engagementName = document.getElementById("engagement-name").value.trim();
  const resp = await fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId, engagement_name: engagementName }),
  });
  const data = await resp.json();
  document.getElementById("report-output").textContent = "Report saved: " + data.report_path;
}
