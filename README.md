# “Is This for Real?” — Active Browser Interceptor

**Sponsors used:** SAP / IBM · Modal · Supabase

A Chrome extension that acts as a real-time, offensive “shoulder surfer” for employees using enterprise software like SAP or IBM tools.

## The concept

Instead of blocking threats silently, the product intercepts risky moments in the browser—exactly when someone is about to hand over enterprise credentials—and turns that moment into an interactive security challenge.

## How it works

1. When a user navigates to a suspicious login page or clicks a link in a mock email, the extension pauses the browsing flow with a high-priority overlay.
2. It sends page context (URL + DOM snippet) to a **Modal** container, which acts as a “white-hat attacker.” The agent analyzes whether the page is trying to harvest SAP/IBM enterprise credentials (fake SSO, brand-spoofing URLs, credential forms on untrusted domains, and similar patterns).
3. Rather than only blocking the page, the extension surfaces an interactive warning: why this looks like a spoof of an enterprise login (for example SAP payroll / SSO), what signals were detected, and what the user should do next.
4. **Supabase** logs incidents (and can track user responses / security-awareness signals over time).

## Why it wins

It trains humans **at the point of failure**, not during a boring annual compliance video—and it plugs directly into enterprise sponsor platforms (SAP / IBM workflows, Modal compute, Supabase logging).

## Repo layout

```
is-this-for-real/
├── extension/          # Chrome Manifest V3 extension
│   ├── manifest.json
│   ├── background.js
│   └── content.js      # Overlay + page analysis trigger
├── backend/
│   └── modal_app.py    # FastAPI app deployed on Modal
└── demo/
    └── verify-account.html   # Local phishing-style demo page
```

## Quick start

### 1. Load the extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Reload the extension after any `content.js` change

### 2. Backend (Modal)

```bash
cd is-this-for-real
./venv/bin/modal deploy backend/modal_app.py
```

Live analyze endpoint:

`https://sejalbansod47-bansford--is-this-for-real-fastapi-app.modal.run/analyze`

### 3. Run the demo page

```bash
python3 -m http.server 8765 --directory demo
```

Open:

**http://127.0.0.1:8765/verify-account.html**

The filename / URL contains `verify-account` (brand-spoofing signal) and a password form, so the interceptor should fire.

## Detection signals (demo-ready)

- Suspicious URL keywords such as `sap-login`, `ibm-auth`, `slack-update`, `verify-account`, `phish`
- Password fields on unverified domains
- Incident rows written to Supabase `security_logs` when a threat is flagged

## Stack

| Layer | Tech |
| --- | --- |
| Browser | Chrome Extension (Manifest V3) |
| Compute / API | Modal + FastAPI |
| Logging | Supabase |
| Enterprise threat framing | SAP / IBM credential-harvest scenarios |

---

Built for the hackathon: stop the phishing click **in the moment**, then teach why it was dangerous.
