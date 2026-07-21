let history = [];
let currentSessionId = null;

function appendMessage(sender, text) {
  const container = document.getElementById("chat-messages");
  if (!container) return;

  const div = document.createElement("div");
  div.className = `msg ${sender}`;

  const header = document.createElement("div");
  header.className = "msg-header";
  header.textContent = sender === "assistant" ? "💀 KNULL TERMINAL ASSISTANT" : "> OPERATOR_INPUT";

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
  if (!input) return;

  const text = input.value.trim();
  if (!text) return;

  appendMessage("user", text);
  input.value = "";
  history.push({ role: "user", content: text });

  // Auto-extract domain or IP from message e.g. "www.google.com" or "scan google.com"
  const domainMatch = text.match(/(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}/i);
  if (domainMatch) {
    const target = domainMatch[0];
    appendMessage("assistant", `[+] Initiating active native security inspection against target: \`${target}\`...\n[+] Probing socket ports, crawling endpoints, and evaluating TLS configuration...`);
    
    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, ports: "80,443,53,8080" }),
      });
      const data = await resp.json();

      if (data.error) {
        appendMessage("assistant", `[-] Error executing scan: ${data.error}`);
        return;
      }

      currentSessionId = data.session_id;
      const profile = data.asset_profile;
      const openSvcs = profile.open_services || [];
      const endpoints = profile.web_endpoints || [];

      let scanSummary = `[+] RECON COMPLETED FOR \`${target}\`:\n`;
      scanSummary += `  - Discovered Open Ports (${openSvcs.length}):\n`;
      openSvcs.forEach(s => {
        scanSummary += `    * Port ${s.port}/${s.protocol}: ${s.service} (${s.product} ${s.version})\n`;
      });
      if (endpoints.length > 0) {
        scanSummary += `  - Crawled Web Endpoints (${endpoints.length}):\n`;
        endpoints.forEach(e => {
          scanSummary += `    * ${e.endpoint} [Status: ${e.status_code}]\n`;
        });
      }
      scanSummary += `\nI have triaged this target profile. Reply with "triage" to see recommended verification actions, or ask me any question about this target.`;
      appendMessage("assistant", scanSummary);
      history.push({ role: "assistant", content: scanSummary });
      return;
    } catch (e) {
      appendMessage("assistant", `[-] Network request failed: ${e.message}`);
      return;
    }
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

    appendMessage("assistant", reply);
    history.push({ role: "assistant", content: reply });
  } catch (e) {
    appendMessage("assistant", `[-] Chat error: ${e.message}`);
  }
}
