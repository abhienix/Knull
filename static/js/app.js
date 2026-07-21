let currentSessionId = null;

function setPipelineStatus(statusText, isError = false) {
  const statusEl = document.getElementById("pipeline-status");
  if (statusEl) {
    statusEl.textContent = statusText;
    statusEl.style.color = isError ? "#ff003c" : "#ff3355";
  }
}

async function runScan() {
  const target = document.getElementById("target-input").value.trim();
  const ports = document.getElementById("ports-input").value.trim() || "";
  const isAuto = document.getElementById("auto-mode").checked;
  const out = document.getElementById("scan-output");

  if (!target) {
    alert("Please enter a valid target host or IP.");
    return;
  }

  if (isAuto) {
    runAutomatedPipeline(target, ports);
    return;
  }

  setPipelineStatus("SCANNING...");
  out.textContent = `> Initiating native Python network & port inspection for ${target}...\n> Probing open ports and grabbing service banners...`;

  const resp = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, ports }),
  });
  const data = await resp.json();

  if (data.error) {
    setPipelineStatus("SCAN ERROR", true);
    out.textContent = "[-] Error during scan: " + data.error;
    return;
  }

  currentSessionId = data.session_id;
  const openSvcs = data.asset_profile.open_services || [];
  const endpoints = data.asset_profile.web_endpoints || [];
  const cors = data.asset_profile.cors_analysis || {};

  let outputText = `[+] Native Network Inspection Complete for ${target}\n`;
  outputText += `[+] Engine: ${data.asset_profile.scan_engine || 'Native Python Inspector'}\n`;
  outputText += `[+] Discovered Open Ports: ${openSvcs.length}\n\n`;
  
  openSvcs.forEach(svc => {
    outputText += `  - Port ${svc.port}/${svc.protocol}: Service [${svc.service}] Product: [${svc.product}] Version: [${svc.version}]\n`;
  });

  if (endpoints.length > 0) {
    outputText += `\n[+] Crawled & Probed Endpoints (${endpoints.length}):\n`;
    endpoints.forEach(ep => {
      outputText += `  - ${ep.endpoint} (Status: ${ep.status_code})\n`;
    });
  }

  if (cors.vulnerable) {
    outputText += `\n[!] CORS Configuration Finding:\n  - Reflected Origin: ${cors.allowed_origin} (Credentials: ${cors.allow_credentials})\n`;
  }

  out.textContent = outputText;
  setPipelineStatus("RECON COMPLETE");
  document.getElementById("advise-section").style.display = "block";
}

async function getAdvice() {
  setPipelineStatus("AI TRIAGING...");
  const resp = await fetch("/api/advise", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId }),
  });
  const data = await resp.json();
  const proposals = data.proposals || [];

  renderProposals(proposals);
  setPipelineStatus("TRIAGE COMPLETE");
  document.getElementById("report-section").style.display = "block";
}

function renderProposals(proposals) {
  const container = document.getElementById("proposals-list");
  container.innerHTML = "";

  proposals.forEach((p, idx) => {
    const div = document.createElement("div");
    div.className = "finding-item";

    let approvalControls = "";
    if (p.approval_type === "one_click" || p.approval_type === "one_click_with_warning") {
      approvalControls = `
        <button class="btn-red" onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', false, ${idx})">EXECUTE DIAGNOSTIC</button>
        <button class="btn-micro" onclick="reject('${p.proposed_tool_id}', ${idx})" style="margin-left: 8px;">REJECT</button>`;
    } else if (p.approval_type === "typed_confirmation") {
      approvalControls = `
        <p style="color: var(--red-main); font-weight: 600; font-size: 11px; margin-bottom: 6px;">[!] Tier-3 Action: Confirm target hostname:</p>
        <input type="text" id="confirm-${idx}" placeholder="Type target exactly" style="margin-right: 8px; max-width: 200px;">
        <button class="btn-red" onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', true, ${idx})">CONFIRM & EXECUTE</button>
        <button class="btn-micro" onclick="reject('${p.proposed_tool_id}', ${idx})" style="margin-left: 8px;">REJECT</button>`;
    } else if (p.approval_type === "not_executable") {
      approvalControls = `<p style="color: var(--text-muted); font-style: italic; font-size: 11px;">Manual Step Only — Not auto-executed by Knull.</p>`;
    }

    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span class="finding-title">${p.finding_summary}</span>
        <span class="badge-red">${p.severity}</span>
      </div>
      <p class="finding-desc">
        <strong>Tool:</strong> <code style="color: var(--red-main);">${p.proposed_tool_id}</code> | <strong>Tier:</strong> ${p.tier}
      </p>
      <p style="font-size: 12px; margin: 6px 0; color: #e2e8f0; line-height: 1.4;">${p.rationale}</p>
      <div style="margin-top: 8px;">${approvalControls}</div>
      <div class="cli-window" style="margin-top: 8px;">
        <div class="cli-bar">
          <span>OUTPUT // ${p.proposed_tool_id}</span>
        </div>
        <pre id="result-${idx}" class="cli-body">> Standby for execution...</pre>
      </div>
    `;
    container.appendChild(div);
  });
}

async function approveAndRun(toolId, template, needsTypedConfirm, idx) {
  setPipelineStatus("EXECUTING...");
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
    const confirmInput = document.getElementById(`confirm-${idx}`);
    payload.typed_confirmation = confirmInput ? confirmInput.value.trim() : "";
  }

  const resultBox = document.getElementById(`result-${idx}`);
  if (resultBox) {
    resultBox.textContent = `> Executing diagnostic inspection engine for '${toolId}'...`;
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
  setPipelineStatus("EXECUTION FINISHED");
}

async function reject(toolId, idx) {
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
  const resultBox = document.getElementById(`result-${idx}`);
  if (resultBox) {
    resultBox.textContent = "> Action rejected by operator.";
  }
}

async function runAutomatedPipeline(target, ports) {
  const out = document.getElementById("scan-output");
  
  setPipelineStatus("PIPELINE RUNNING");
  out.textContent = `> Autonomous Pipeline Started for target: ${target}\n> Step 1: Performing concurrent socket scan & banner grabbing...`;
  
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
    setPipelineStatus("SCAN ERROR", true);
    out.textContent = "[-] Error: " + scanData.error;
    return;
  }
  
  currentSessionId = scanData.session_id;
  const openSvcs = scanData.asset_profile.open_services || [];
  const endpoints = scanData.asset_profile.web_endpoints || [];
  const cors = scanData.asset_profile.cors_analysis || {};

  let outputText = `[+] Native Network Inspection Complete for ${target}\n`;
  outputText += `[+] Discovered Open Ports: ${openSvcs.length}\n\n`;
  openSvcs.forEach(svc => {
    outputText += `  - Port ${svc.port}/${svc.protocol}: Service [${svc.service}] Product: [${svc.product}] Version: [${svc.version}]\n`;
  });

  if (endpoints.length > 0) {
    outputText += `\n[+] Crawled & Probed Endpoints (${endpoints.length}):\n`;
    endpoints.forEach(ep => {
      outputText += `  - ${ep.endpoint} (Status: ${ep.status_code})\n`;
    });
  }

  if (cors.vulnerable) {
    outputText += `\n[!] CORS Configuration Finding:\n  - Reflected Origin: ${cors.allowed_origin} (Credentials: ${cors.allow_credentials})\n`;
  }

  out.textContent = outputText;
  
  // 2. Get AI proposals
  setPipelineStatus("AI TRIAGING");
  const adviseResp = await fetch("/api/advise", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId }),
  });
  const adviseData = await adviseResp.json();
  const proposals = adviseData.proposals || [];
  
  renderProposals(proposals);
  document.getElementById("advise-section").style.display = "block";
  
  if (proposals.length === 0) {
    setPipelineStatus("NO FINDINGS");
    await autoGenerateReport(target);
    return;
  }
  
  // 3. Auto execute each proposal with unique idx
  for (let i = 0; i < proposals.length; i++) {
    const p = proposals[i];
    setPipelineStatus(`EXECUTING ${i+1}/${proposals.length}`);
    
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
    
    const resultBox = document.getElementById(`result-${i}`);
    if (resultBox) {
      resultBox.textContent = `> Running inspection '${p.proposed_tool_id}'...`;
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
  setPipelineStatus("GENERATING REPORT");
  await autoGenerateReport(target);
}

async function autoGenerateReport(target) {
  const reportName = `Autonomous Audit - ${target}`;
  const reportInput = document.getElementById("engagement-name");
  if (reportInput) reportInput.value = reportName;
  
  const resp = await fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId, engagement_name: reportName }),
  });
  const data = await resp.json();
  
  setPipelineStatus("PIPELINE COMPLETE");
  
  document.getElementById("report-section").style.display = "block";
  document.getElementById("report-output").textContent = data.report_path;
}

async function generateReport() {
  const engagementName = document.getElementById("engagement-name").value.trim();
  const resp = await fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId, engagement_name: engagementName }),
  });
  const data = await resp.json();
  document.getElementById("report-output").textContent = data.report_path;
}
