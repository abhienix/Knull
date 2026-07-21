let history = [];
let currentSessionId = null;

function appendTerminalLog(text) {
  const term = document.getElementById("terminal-stream");
  if (!term) return;

  term.textContent += "\n" + text;
  term.scrollTop = term.scrollHeight;
}

async function sendMessage() {
  const input = document.getElementById("chat-input");
  if (!input) return;

  const text = input.value.trim();
  if (!text) return;

  // Print prompt command line to stream
  appendTerminalLog(`knull@security:~$ ${text}`);
  input.value = "";
  history.push({ role: "user", content: text });

  // Check domain/IP input e.g. "www.google.com" or "scan www.iacsd.com"
  const domainMatch = text.match(/(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}/i);
  if (domainMatch) {
    const target = domainMatch[0];
    document.getElementById("term-session").textContent = `SESSION: ACTIVE [${target}]`;
    
    appendTerminalLog(`> Initiating active native security inspection against target: ${target}`);
    appendTerminalLog(`> Phase 1: Probing socket ports and grabbing service banners...`);
    
    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, ports: "80,443,53,8080" }),
      });
      const data = await resp.json();

      if (data.error) {
        appendTerminalLog(`[-] ERROR: ${data.error}`);
        return;
      }

      currentSessionId = data.session_id;
      const profile = data.asset_profile;
      const openSvcs = profile.open_services || [];
      const endpoints = profile.web_endpoints || [];
      const cors = profile.cors_analysis || {};

      appendTerminalLog(`[+] Phase 1 Complete for ${target}`);
      appendTerminalLog(`[+] Open Ports Discovered (${openSvcs.length}):`);
      openSvcs.forEach(s => {
        appendTerminalLog(`    - Port ${s.port}/${s.protocol}: Service [${s.service}] Product: [${s.product}] Version: [${s.version || 'Unspecified'}]`);
      });

      if (endpoints.length > 0) {
        appendTerminalLog(`\n[+] Phase 2: Crawling Web Administrative & API Endpoints (${endpoints.length}):`);
        endpoints.forEach(e => {
          appendTerminalLog(`    - Endpoint Discovered: ${e.endpoint} (HTTP Status Code: ${e.status_code})`);
        });
      }

      if (cors.vulnerable) {
        appendTerminalLog(`\n[!] CORS Configuration Warning:\n    - Reflected Origin: ${cors.allowed_origin} (Credentials: ${cors.allow_credentials})`);
      }

      // Auto-trigger AI Triage Phase
      appendTerminalLog(`\n> Phase 3: Querying Groq AI Reasoning Engine for vulnerability triaging...`);
      const adviseResp = await fetch("/api/advise", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: currentSessionId }),
      });
      const adviseData = await adviseResp.json();
      const proposals = adviseData.proposals || [];

      if (proposals.length === 0) {
        appendTerminalLog(`[+] AI Triage Complete: No critical vulnerabilities triaged.`);
      } else {
        appendTerminalLog(`[+] AI Triage Complete: Discovered ${proposals.length} Action Proposals:`);
        proposals.forEach((p, idx) => {
          appendTerminalLog(`\n    [Action ${idx + 1}] ${p.finding_summary} (${p.severity.toUpperCase()})`);
          appendTerminalLog(`    * Proposed Tool: ${p.proposed_tool_id} (Tier ${p.tier})`);
          appendTerminalLog(`    * Rationale: ${p.rationale}`);
        });
      }

      // Auto-generate report
      appendTerminalLog(`\n> Phase 4: Compiling executive report & remediation directives...`);
      const rptResp = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: currentSessionId, engagement_name: `Audit - ${target}` }),
      });
      const rptData = await rptResp.json();
      appendTerminalLog(`[+] AUDIT COMPLETE! Executive report saved: ${rptData.report_path}`);

    } catch (e) {
      appendTerminalLog(`[-] Network execution error: ${e.message}`);
    }
    return;
  }

  // Conversational response via Groq AI engine
  try {
    const chatResp = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        session_id: currentSessionId,
        history: history,
      }),
    });
    const data = await chatResp.json();
    const reply = data.response || "No response generated.";

    appendTerminalLog(`> ${reply}`);
    history.push({ role: "assistant", content: reply });
  } catch (e) {
    appendTerminalLog(`[-] Chat error: ${e.message}`);
  }
}
