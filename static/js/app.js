let currentSessionId = null;

function setStep(stepNum) {
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`step-${i}`);
    if (el) {
      if (i < stepNum) {
        el.className = "step-item completed";
      } else if (i === stepNum) {
        el.className = "step-item active";
      } else {
        el.className = "step-item";
      }
    }
  }
}

function updateMetrics(target, openPortsCount, proposalsCount) {
  document.getElementById("metric-target").textContent = target || "None";
  document.getElementById("metric-ports").textContent = openPortsCount !== undefined ? openPortsCount : 0;
  document.getElementById("metric-vulns").textContent = proposalsCount !== undefined ? proposalsCount : 0;
  
  let score = 0;
  if (proposalsCount > 0) score = Math.min(proposalsCount * 25 + 15, 95);
  document.getElementById("metric-score").textContent = `${score} / 100`;
}

async function runScan() {
  const target = document.getElementById("target-input").value.trim();
  const ports = document.getElementById("ports-input").value.trim() || "";
  const isAuto = document.getElementById("auto-mode").checked;
  const out = document.getElementById("scan-output");

  if (!target) {
    alert("Please enter a valid target domain or IP.");
    return;
  }

  updateMetrics(target, 0, 0);
  setStep(1);

  if (isAuto) {
    runAutomatedPipeline(target, ports);
    return;
  }

  out.textContent = `[+] Initiating native Python network & port inspection for ${target}...\n[+] Scanning sockets & banner responses...`;

  const resp = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, ports }),
  });
  const data = await resp.json();

  if (data.error) {
    out.textContent = "[-] Error during scan: " + data.error;
    return;
  }

  currentSessionId = data.session_id;
  const openSvcs = data.asset_profile.open_services || [];
  updateMetrics(target, openSvcs.length, 0);

  let outputText = `[+] Native Network Inspection Complete for ${target}\n`;
  outputText += `[+] Engine: ${data.asset_profile.scan_engine || 'Native Python Inspector'}\n`;
  outputText += `[+] Open ports discovered: ${openSvcs.length}\n\n`;
  
  openSvcs.forEach(svc => {
    outputText += `  - Port ${svc.port}/${svc.protocol}: Service [${svc.service}] Product: [${svc.product}] Version: [${svc.version}]\n`;
  });

  out.textContent = outputText;
  document.getElementById("advise-section").style.display = "block";
  setStep(2);
}

async function getAdvice() {
  setStep(2);
  const resp = await fetch("/api/advise", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId }),
  });
  const data = await resp.json();
  const proposals = data.proposals || [];
  
  const target = document.getElementById("target-input").value.trim();
  const portsCount = parseInt(document.getElementById("metric-ports").textContent) || 0;
  updateMetrics(target, portsCount, proposals.length);

  renderProposals(proposals);
  document.getElementById("report-section").style.display = "block";
  setStep(3);
}

function renderProposals(proposals) {
  const container = document.getElementById("proposals-list");
  container.innerHTML = "";

  proposals.forEach((p) => {
    const div = document.createElement("div");
    div.className = "proposal-card";

    let severityClass = (p.severity || "low").toLowerCase();
    
    let approvalControls = "";
    if (p.approval_type === "one_click" || p.approval_type === "one_click_with_warning") {
      approvalControls = `
        <button class="btn-primary" onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', false)">Approve & Run Verification</button>
        <button class="btn-danger" onclick="reject('${p.proposed_tool_id}')" style="margin-left: 8px;">Reject</button>`;
    } else if (p.approval_type === "typed_confirmation") {
      approvalControls = `
        <p style="color: var(--severity-high); font-weight: 600; font-size: 13px;">⚠️ Tier-3 Action: Type target hostname to confirm execution:</p>
        <input type="text" id="confirm-${p.proposed_tool_id}" placeholder="Type target exactly" style="margin-right: 8px;">
        <button class="btn-primary" onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', true)">Confirm & Run</button>
        <button class="btn-danger" onclick="reject('${p.proposed_tool_id}')" style="margin-left: 8px;">Reject</button>`;
    } else if (p.approval_type === "not_executable") {
      approvalControls = `<p style="color: var(--severity-medium); font-style: italic; font-size: 13px;">Manual Only Step — Knull will not auto-execute this tool.</p>`;
    }

    div.innerHTML = `
      <div class="proposal-header">
        <span class="proposal-title">${p.finding_summary}</span>
        <span class="badge ${severityClass}">${p.severity}</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted); margin: 6px 0;">
        <strong>Proposed Verification:</strong> <code style="color: var(--accent-cyan);">${p.proposed_tool_id}</code> | <strong>Tier:</strong> ${p.tier} (${p.tier_label})
      </p>
      <p style="font-size: 14px; margin: 8px 0; line-height: 1.4;">${p.rationale}</p>
      <div style="margin-top: 12px;">${approvalControls}</div>
      <div class="terminal-window" style="margin-top: 12px;">
        <div class="terminal-header">
          <span class="terminal-title">verification-output [${p.proposed_tool_id}]</span>
        </div>
        <pre id="result-${p.proposed_tool_id}" class="terminal-body">Ready for verification...</pre>
      </div>
    `;
    container.appendChild(div);
  });
}

async function approveAndRun(toolId, template, needsTypedConfirm) {
  setStep(3);
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

  const resultBox = document.getElementById(`result-${toolId}`);
  if (resultBox) {
    resultBox.textContent = `[+] Executing active inspection engine for '${toolId}'...`;
  }

  const resp = await fetch("/api/execute", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  if (resultBox) {
    resultBox.textContent = data.output || JSON.stringify(data, null, 2);
  }
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
  const resultBox = document.getElementById(`result-${toolId}`);
  if (resultBox) {
    resultBox.textContent = "[-] Action rejected by operator.";
  }
}

async function runAutomatedPipeline(target, ports) {
  const status = document.getElementById("status-indicator");
  const out = document.getElementById("scan-output");
  
  setStep(1);
  status.style.display = "block";
  status.textContent = "Status: Executing native Python network & socket inspection...";
  status.style.color = "var(--accent-cyan)";
  out.textContent = `[+] Autonomous Pipeline Started for target: ${target}\n[+] Step 1: Performing concurrent socket scan & banner grabbing...`;
  
  document.getElementById("advise-section").style.display = "none";
  document.getElementById("report-section").style.display = "none";
  
  // 1. Scan
  const scanResp = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, ports }),
  });
  const scanData = await scanResp.json();
  if (scanData.error) {
    status.textContent = "Status: Scan failed.";
    status.style.color = "var(--severity-critical)";
    out.textContent = "Error: " + scanData.error;
    return;
  }
  
  currentSessionId = scanData.session_id;
  const openSvcs = scanData.asset_profile.open_services || [];
  updateMetrics(target, openSvcs.length, 0);

  let outputText = `[+] Native Network Inspection Complete for ${target}\n`;
  outputText += `[+] Open ports discovered: ${openSvcs.length}\n\n`;
  openSvcs.forEach(svc => {
    outputText += `  - Port ${svc.port}/${svc.protocol}: Service [${svc.service}] Product: [${svc.product}] Version: [${svc.version}]\n`;
  });
  out.textContent = outputText;
  
  // 2. Get AI proposals
  setStep(2);
  status.textContent = "Status: Running AI threat triaging & NVD correlation...";
  const adviseResp = await fetch("/api/advise", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId }),
  });
  const adviseData = await adviseResp.json();
  const proposals = adviseData.proposals || [];
  
  updateMetrics(target, openSvcs.length, proposals.length);
  renderProposals(proposals);
  document.getElementById("advise-section").style.display = "block";
  
  if (proposals.length === 0) {
    status.textContent = "Status: No vulnerabilities triaged.";
    await autoGenerateReport(target);
    return;
  }
  
  // 3. Auto execute each proposal
  setStep(3);
  for (let i = 0; i < proposals.length; i++) {
    const p = proposals[i];
    status.textContent = `Status: Running active inspection ${i+1} of ${proposals.length} (${p.proposed_tool_id})...`;
    
    if (p.approval_type === "not_executable") continue;
    
    await fetch("/api/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: currentSessionId,
        tool_id: p.proposed_tool_id,
        approved: true,
        approved_by: "auto_operator",
      }),
    });
    
    const payload = {
      session_id: currentSessionId,
      tool_id: p.proposed_tool_id,
      template: p.proposed_template || null,
      approved: true,
    };
    
    if (p.approval_type === "typed_confirmation") {
      payload.typed_confirmation = target;
    }
    
    const resultBox = document.getElementById(`result-${p.proposed_tool_id}`);
    if (resultBox) {
      resultBox.textContent = `[+] Executing inspection '${p.proposed_tool_id}'...`;
    }
    
    const execResp = await fetch("/api/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const execData = await execResp.json();
    if (resultBox) {
      resultBox.textContent = execData.output || JSON.stringify(execData, null, 2);
    }
  }
  
  // 4. Auto-generate report
  setStep(4);
  status.textContent = "Status: Compiling executive report...";
  await autoGenerateReport(target);
}

async function autoGenerateReport(target) {
  setStep(4);
  const status = document.getElementById("status-indicator");
  const reportName = `Autonomous Audit - ${target}`;
  const reportInput = document.getElementById("engagement-name");
  if (reportInput) reportInput.value = reportName;
  
  const resp = await fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId, engagement_name: reportName }),
  });
  const data = await resp.json();
  
  status.style.color = "#10b981";
  status.textContent = "Status: Audit Complete! Executive Report Generated.";
  
  document.getElementById("report-section").style.display = "block";
  document.getElementById("report-output").textContent = "Executive Report Saved: " + data.report_path;
}

async function generateReport() {
  setStep(4);
  const engagementName = document.getElementById("engagement-name").value.trim();
  const resp = await fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId, engagement_name: engagementName }),
  });
  const data = await resp.json();
  document.getElementById("report-output").textContent = "Executive Report Saved: " + data.report_path;
}
