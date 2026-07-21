let currentSessionId = null;

function setPipelineStatus(statusText, isError = false) {
  const statusEl = document.getElementById("pipeline-status");
  if (statusEl) {
    statusEl.textContent = statusText;
    statusEl.style.color = isError ? "#ff003c" : "#ff3355";
  }
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));

  const targetBtn = Array.from(document.querySelectorAll(".tab-btn")).find(b => b.getAttribute("onclick").includes(tabId));
  if (targetBtn) targetBtn.classList.add("active");

  const targetPane = document.getElementById(`tab-${tabId}`);
  if (targetPane) targetPane.classList.add("active");
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
  out.textContent = `> Initiating deep network & web inspection for ${target}...\n> Probing socket ports, crawling endpoints, and auditing CORS headers...`;

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
  renderAttackSurface(data.asset_profile);

  out.textContent = `[+] Recon complete for ${target}. Discovered ${data.asset_profile.open_services.length} ports & ${data.asset_profile.web_endpoints.length} endpoints.`;
  setPipelineStatus("RECON COMPLETE");
  switchTab("overview");
}

function renderAttackSurface(profile) {
  const svcsContainer = document.getElementById("services-list");
  const epsContainer = document.getElementById("endpoints-list");

  svcsContainer.innerHTML = "";
  epsContainer.innerHTML = "";

  const openSvcs = profile.open_services || [];
  if (openSvcs.length === 0) {
    svcsContainer.innerHTML = `<div class="placeholder-text">No open ports detected.</div>`;
  } else {
    openSvcs.forEach(svc => {
      const div = document.createElement("div");
      div.className = "svc-item";
      div.innerHTML = `
        <div class="svc-title">Port ${svc.port}/${svc.protocol} - ${svc.service.toUpperCase()}</div>
        <div style="color: var(--text-muted); margin-top: 4px; font-size: 12px;">Product: ${svc.product || 'Unknown'} ${svc.version || ''}</div>
      `;
      svcsContainer.appendChild(div);
    });
  }

  const endpoints = profile.web_endpoints || [];
  if (endpoints.length === 0) {
    epsContainer.innerHTML = `<div class="placeholder-text">No administrative/API endpoints discovered.</div>`;
  } else {
    endpoints.forEach(ep => {
      const div = document.createElement("div");
      div.className = "svc-item";
      div.innerHTML = `
        <div class="svc-title">${ep.endpoint}</div>
        <div style="color: var(--text-muted); margin-top: 4px; font-size: 12px;">HTTP Status Code: ${ep.status_code}</div>
      `;
      epsContainer.appendChild(div);
    });
  }
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
}

function renderProposals(proposals) {
  const container = document.getElementById("proposals-list");
  container.innerHTML = "";

  if (proposals.length === 0) {
    container.innerHTML = `<div class="placeholder-text">No actionable vulnerabilities or misconfigurations triaged.</div>`;
    return;
  }

  proposals.forEach((p, idx) => {
    const div = document.createElement("div");
    div.className = "finding-card-v2";

    let approvalControls = "";
    if (p.approval_type === "one_click" || p.approval_type === "one_click_with_warning") {
      approvalControls = `
        <button class="btn-audit" onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', false, ${idx})">EXECUTE DIAGNOSTIC</button>
        <button class="btn-audit" onclick="reject('${p.proposed_tool_id}', ${idx})" style="background: transparent; border: 1px solid var(--red-border); color: var(--red-main); margin-left: 8px;">REJECT</button>`;
    } else if (p.approval_type === "typed_confirmation") {
      approvalControls = `
        <p style="color: var(--red-main); font-weight: 600; font-size: 11px; margin-bottom: 6px;">[!] Tier-3 Action: Confirm target hostname:</p>
        <input type="text" id="confirm-${idx}" placeholder="Type target exactly" style="margin-right: 8px; max-width: 200px;">
        <button class="btn-audit" onclick="approveAndRun('${p.proposed_tool_id}', '${p.proposed_template || ""}', true, ${idx})">CONFIRM & EXECUTE</button>
        <button class="btn-audit" onclick="reject('${p.proposed_tool_id}', ${idx})" style="background: transparent; border: 1px solid var(--red-border); color: var(--red-main); margin-left: 8px;">REJECT</button>`;
    } else if (p.approval_type === "not_executable") {
      approvalControls = `<p style="color: var(--text-muted); font-style: italic; font-size: 11px;">Manual Step Only — Not auto-executed by Knull.</p>`;
    }

    div.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span style="font-weight: 700; color: #fff; font-family: 'Fira Code', monospace;">${p.finding_summary}</span>
        <span class="badge-fail">${p.severity}</span>
      </div>
      <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0;">
        <strong>Tool:</strong> <code style="color: var(--red-main);">${p.proposed_tool_id}</code> | <strong>Tier:</strong> ${p.tier}
      </p>
      <p style="font-size: 13px; margin: 6px 0; color: #e2e8f0; line-height: 1.4;">${p.rationale}</p>
      <div style="margin-top: 8px;">${approvalControls}</div>
      <div class="console-box" style="margin-top: 8px; height: 120px;">
        <div class="box-header">OUTPUT // ${p.proposed_tool_id}</div>
        <pre id="result-${idx}" class="console-body">> Standby for execution...</pre>
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
  out.textContent = `> Autonomous Pipeline Started for target: ${target}\n> Step 1: Performing concurrent socket scan, endpoint crawling & CORS check...`;
  
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
  renderAttackSurface(scanData.asset_profile);
  
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
  
  if (proposals.length === 0) {
    setPipelineStatus("NO FINDINGS");
    await autoGenerateReport(target);
    return;
  }
  
  // 3. Auto execute each proposal
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
  switchTab("report");
}

async function autoGenerateReport(target) {
  const reportName = `Autonomous Audit - ${target}`;
  
  const resp = await fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: currentSessionId, engagement_name: reportName }),
  });
  const data = await resp.json();
  
  setPipelineStatus("AUDIT COMPLETE");
  
  const container = document.getElementById("report-content");
  container.innerHTML = `
    <div style="font-size: 14px; font-weight: 700; color: #10b981; margin-bottom: 10px;">[+] EXECUTIVE AUDIT REPORT GENERATED SUCCESSFULLY</div>
    <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Saved to: <code style="color: var(--red-main);">${data.report_path}</code></div>
    <div style="font-size: 13px; font-weight: 700; color: #fff; margin-top: 16px;">RECOMMENDED NGINX DIRECTIVES:</div>
    <pre class="report-code">server {
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self';" always;
    server_tokens off;
}</pre>
  `;
}
