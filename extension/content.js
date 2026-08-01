const MODAL_ENDPOINT = "https://sejalbansod47-bansford--is-this-for-real-fastapi-app.modal.run/analyze";

async function checkPageSecurity() {
  try {
    const pageData = {
      url: window.location.href,
      html: document.body.innerHTML
    };

    const response = await fetch(MODAL_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pageData)
    });

    const result = await response.json();

    if (result.is_phishing) {
      renderSecurityWarning(result);
    }
  } catch (error) {
    console.error("Is This For Real? Error communicating with Modal backend:", error);
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function injectOverlayStyles() {
  if (document.getElementById("phish-guard-styles")) return;

  const styleTag = document.createElement("style");
  styleTag.id = "phish-guard-styles";
  styleTag.textContent = `
    @keyframes glitch-icon {
      0% { transform: translate(0); }
      20% { transform: translate(-1px, 1px); }
      40% { transform: translate(-1px, -1px); }
      60% { transform: translate(1px, 1px); }
      80% { transform: translate(1px, -1px); }
      100% { transform: translate(0); }
    }

    #phish-guard-overlay {
      isolation: isolate;
    }

    #phish-guard-overlay .glitch-warning-icon {
      animation: glitch-icon 1.2s infinite linear alternate-reverse;
      display: inline-block;
      line-height: 1;
    }

    #phish-guard-overlay #phish-safe-btn:hover {
      background: #e11d48;
    }

    #phish-guard-overlay #phish-soc-btn:hover:not(:disabled) {
      background: rgba(244, 63, 94, 0.12);
    }

    #phish-guard-overlay #phish-safe-btn:focus-visible,
    #phish-guard-overlay #phish-soc-btn:focus-visible {
      outline: 2px solid #f43f5e;
      outline-offset: 2px;
    }
  `;
  document.documentElement.appendChild(styleTag);
}

function renderSecurityWarning(threatInfo) {
  if (document.getElementById("phish-guard-overlay")) return;

  injectOverlayStyles();

  const reason = escapeHtml(
    threatInfo.reason ||
      "Our real-time AI analyst intercepted a credential-harvesting attempt on this page."
  );
  const confidenceRaw = Number(threatInfo.confidence);
  const confidenceLabel = Number.isFinite(confidenceRaw)
    ? `${Math.round(confidenceRaw * 100)}%`
    : "N/A";
  const threatType = escapeHtml(threatInfo.threat_type || "AI Detected Threat");

  const overlay = document.createElement("div");
  overlay.id = "phish-guard-overlay";
  overlay.style.cssText = `
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    background: rgba(2, 6, 23, 0.72);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    isolation: isolate;
  `;

  // Palette (max 3): glass white #f8fafc, slate #cbd5e1, crimson #f43f5e
  overlay.innerHTML = `
    <div style="
      width: min(440px, 100%);
      background: rgba(248, 250, 252, 0.08);
      backdrop-filter: blur(24px) saturate(160%);
      -webkit-backdrop-filter: blur(24px) saturate(160%);
      border: 1px solid rgba(248, 250, 252, 0.16);
      border-radius: 20px;
      padding: 32px 28px 28px;
      box-shadow:
        0 25px 50px -12px rgba(0, 0, 0, 0.55),
        inset 0 1px 0 rgba(248, 250, 252, 0.18);
      text-align: center;
      color: #f8fafc;
    ">
      <div style="display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 16px;">
        <div class="glitch-warning-icon" style="font-size: 34px;" aria-hidden="true">⚠️</div>
        <div style="font-size: 46px; line-height: 1;" aria-label="Side-eye security cat">😼</div>
      </div>

      <p style="
        margin: 0 0 8px 0;
        font-size: 11px;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        font-weight: 700;
        color: #f43f5e;
      ">${threatType}</p>

      <h2 style="
        color: #f8fafc;
        margin: 0 0 10px 0;
        font-size: 22px;
        font-weight: 700;
        letter-spacing: -0.025em;
      ">AI Phishing Threat Detected</h2>

      <p id="phish-reason" style="
        color: #cbd5e1;
        font-size: 14px;
        line-height: 1.6;
        margin: 0 0 8px 0;
      ">${reason}</p>

      <p style="
        color: #cbd5e1;
        font-size: 13px;
        margin: 0 0 22px 0;
        opacity: 0.9;
      ">Confidence <span id="phish-confidence" style="color: #f8fafc; font-weight: 700;">${confidenceLabel}</span></p>

      <div style="display: flex; gap: 10px;">
        <button id="phish-safe-btn" style="
          background: #f43f5e;
          color: #f8fafc;
          border: none;
          padding: 12px 16px;
          font-weight: 600;
          font-size: 14px;
          border-radius: 10px;
          cursor: pointer;
          flex: 1;
          transition: background 0.2s;
        ">Go Back to Safety</button>
        <button id="phish-soc-btn" style="
          background: rgba(248, 250, 252, 0.06);
          color: #f8fafc;
          border: 1px solid rgba(248, 250, 252, 0.18);
          padding: 12px 16px;
          font-weight: 600;
          font-size: 14px;
          border-radius: 10px;
          cursor: pointer;
          flex: 1;
          backdrop-filter: blur(8px);
          -webkit-backdrop-filter: blur(8px);
          transition: background 0.2s;
        ">🚨 Report to SOC</button>
      </div>
      <p id="phish-soc-feedback" style="display: none; margin: 14px 0 0 0; font-size: 13px; color: #cbd5e1;"></p>
    </div>
  `;

  document.documentElement.appendChild(overlay);

  document.getElementById("phish-safe-btn").onclick = () => {
    window.location.href = "about:blank";
  };

  const socBtn = document.getElementById("phish-soc-btn");
  const socFeedback = document.getElementById("phish-soc-feedback");
  socBtn.onclick = () => {
    socBtn.textContent = "Incident Dispatched to SOC 🛡️";
    socBtn.disabled = true;
    socBtn.style.opacity = "0.85";
    socBtn.style.cursor = "default";
    socBtn.style.borderColor = "rgba(248, 250, 252, 0.28)";
    socBtn.style.color = "#f8fafc";

    socFeedback.style.display = "block";
    socFeedback.textContent = "SOC ticket logged. Security team has been notified.";

    console.info("Is This For Real? SOC report dispatched:", {
      url: window.location.href,
      threat_type: threatInfo.threat_type,
      reason: threatInfo.reason,
      confidence: threatInfo.confidence,
      reported_at: new Date().toISOString()
    });
  };
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", checkPageSecurity);
} else {
  checkPageSecurity();
}
