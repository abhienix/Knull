let history = [];
let currentSessionId = null;

function appendMessage(sender, text) {
  const container = document.getElementById("chat-messages");
  const div = document.createElement("div");
  div.className = `msg ${sender}`;

  const header = document.createElement("div");
  header.className = "msg-header";
  header.textContent = sender === "assistant" ? "💀 KNULL AI ASSISTANT" : "👤 OPERATOR";

  const body = document.createElement("div");
  body.className = "msg-body";
  body.innerHTML = text.replace(/\n/g, "<br>").replace(/`([^`]+)`/g, "<code>$1</code>");

  div.appendChild(header);
  div.appendChild(body);
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

async function sendMessage() {
  const input = document.getElementById("chat-input");
  const text = input.value.trim();
  if (!text) return;

  appendMessage("user", text);
  input.value = "";
  history.push({ role: "user", content: text });

  // Detect explicit scan command e.g. "scan www.google.com"
  const scanMatch = text.match(/(?:scan|audit|inspect)\s+([a-zA-Z0-9\.\-]+)/i);
  if (scanMatch && scanMatch[1]) {
    const target = scanMatch[1];
    appendMessage("assistant", `Initiating deep network & web inspection for \`${target}\`...`);
    
    const resp = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, ports: "80,443,53,8080" }),
    });
    const data = await resp.json();

    if (data.error) {
      appendMessage("assistant", `[-] Error during scan: ${data.error}`);
      return;
    }

    currentSessionId = data.session_id;
    const profile = data.asset_profile;
    const openSvcs = profile.open_services || [];
    const endpoints = profile.web_endpoints || [];

    let scanSummary = `[+] Recon complete for \`${target}\`:\n`;
    scanSummary += `- Discovered Open Ports: ${openSvcs.length}\n`;
    openSvcs.forEach(s => {
      scanSummary += `  * Port ${s.port}/${s.protocol}: ${s.service} (${s.product})\n`;
    });
    if (endpoints.length > 0) {
      scanSummary += `- Crawled Endpoints: ${endpoints.length}\n`;
      endpoints.forEach(e => {
        scanSummary += `  * ${e.endpoint} (Status ${e.status_code})\n`;
      });
    }
    scanSummary += `\nWould you like me to triage vulnerabilities or run a diagnostic test for this target?`;
    appendMessage("assistant", scanSummary);
    history.push({ role: "assistant", content: scanSummary });
    return;
  }

  // General conversational response
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
  const reply = data.response || "No response received.";

  appendMessage("assistant", reply);
  history.push({ role: "assistant", content: reply });
}
