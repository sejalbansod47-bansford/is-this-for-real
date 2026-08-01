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

function renderSecurityWarning(threatInfo) {
  if (document.getElementById("itfr-overlay")) return;

  const overlay = document.createElement("div");
  overlay.id = "itfr-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0; width: 100vw; height: 100vh;
    background: rgba(15, 23, 42, 0.95);
    backdrop-filter: blur(8px);
    z-index: 9999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: system-ui, -apple-system, sans-serif;
    color: #f8fafc;
  `;

  overlay.innerHTML = `
    <div style="background: #1e293b; border: 1px solid #ef4444; border-radius: 16px; padding: 32px; max-width: 520px; width: 90%; box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.3);">
      <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
        <span style="font-size: 32px;">🚨</span>
        <h2 style="margin: 0; color: #f87171; font-size: 24px; font-weight: 700;">Is This For Real?</h2>
      </div>
      <p style="color: #94a3b8; margin-bottom: 20px; line-height: 1.5; font-size: 14px;">
        Our AI Agent intercepted this page. It detected dynamic spoofing patterns targeting enterprise login portals.
      </p>
      <div style="background: #0f172a; border-left: 4px solid #ef4444; padding: 16px; border-radius: 8px; margin-bottom: 24px;">
        <p style="margin: 0; font-size: 14px; font-weight: 600; color: #fca5a5;">${threatInfo.threat_type || 'Enterprise Security Alert'}</p>
        <p style="margin: 6px 0 0 0; font-size: 13px; color: #cbd5e1; line-height: 1.4;">${threatInfo.reason}</p>
        <p style="margin: 8px 0 0 0; font-size: 11px; color: #64748b; font-weight: 500;">MITRE ATT&CK: ${threatInfo.mitre_tactic || 'T1566.002'}</p>
      </div>
      <div style="display: flex; gap: 12px;">
        <button id="itfr-back" style="flex: 1; padding: 12px; background: #ef4444; border: none; border-radius: 8px; color: white; font-weight: 600; cursor: pointer; font-size: 14px;">
          🛡️ Get Me Out of Here
        </button>
        <button id="itfr-proceed" style="padding: 12px; background: transparent; border: 1px solid #475569; border-radius: 8px; color: #94a3b8; font-size: 12px; cursor: pointer;">
          I know the risks
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById("itfr-back").onclick = () => {
    window.location.href = "https://google.com";
  };
  document.getElementById("itfr-proceed").onclick = () => {
    overlay.remove();
  };
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", checkPageSecurity);
} else {
  checkPageSecurity();
}