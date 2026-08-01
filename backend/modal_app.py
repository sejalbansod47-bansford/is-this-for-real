import modal
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# Define the Modal App
app = modal.App("is-this-for-real")

web_app = FastAPI()

# Enable CORS so your Chrome Extension can talk to your backend without browser security blocks
web_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Schema for incoming DOM data from the extension
class PageData(BaseModel):
    url: str
    html: str

@web_app.post("/analyze")
def analyze_page(data: PageData):
    url_lower = data.url.lower()
    html_lower = data.html.lower()

    reasons = []
    
    # Check 1: Suspicious domain keywords targeting enterprise apps (SAP / IBM / Slack / SSO)
    if any(fake in url_lower for fake in ["sap-login", "ibm-auth", "slack-update", "verify-account", "phish"]):
        reasons.append("Domain uses brand spoofing tactics mimicking enterprise Single-Sign-On (SSO).")
    
    # Check 2: Password input form on an untrusted domain
    if ("<input" in html_lower and "type=\"password\"" in html_lower) or ("type='password'" in html_lower):
        if not (url_lower.startswith("https://sap.com") or url_lower.startswith("https://ibm.com") or "localhost" in url_lower):
            reasons.append("Credential harvesting pattern detected: Password form found on an unverified third-party domain.")

    # Flag as threat if any heuristic triggers
    if len(reasons) > 0:
        return {
            "is_phishing": True,
            "confidence": 0.96,
            "reason": " ".join(reasons),
            "threat_type": "Enterprise Credential Harvester",
            "mitre_tactic": "T1566.002 - Spearphishing Link"
        }

    return {
        "is_phishing": False,
        "confidence": 0.02,
        "reason": "Page appears clean."
    }

# Build the Modal image container
image = modal.Image.debian_slim().pip_install("fastapi", "pydantic")

@app.function(image=image)
@modal.asgi_app()
def fastapi_app():
    return web_app