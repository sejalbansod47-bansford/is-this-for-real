import os
import modal
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client

app = modal.App("is-this-for-real")

image = modal.Image.debian_slim().pip_install("fastapi", "pydantic", "supabase")

SUSPICIOUS_KEYWORDS = (
    "sap-login",
    "ibm-auth",
    "slack-update",
    "verify-account",
    "phish",
    "account-verify",
    "secure-login",
    "login-verify",
    "webmail-login",
    "okta-login",
    "sso-login",
    "mfa-reset",
)


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("supabase-secret")],
)
@modal.asgi_app()
def fastapi_app():
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_KEY")
    supabase: Client = create_client(supabase_url, supabase_key)

    inner_web_app = FastAPI()
    inner_web_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    class PageData(BaseModel):
        url: str
        html: str = ""

    def heuristic_result(url: str, html: str):
        url_lower = (url or "").lower()
        html_lower = (html or "").lower()
        reasons = []

        hit = next((k for k in SUSPICIOUS_KEYWORDS if k in url_lower), None)
        if hit:
            reasons.append(
                f"URL contains brand-spoofing / phishing keyword '{hit}'."
            )

        has_password = (
            'type="password"' in html_lower
            or "type='password'" in html_lower
            or "type=password" in html_lower
        )
        # Do NOT treat localhost as trusted — needed for local hackathon demos
        trusted = any(
            t in url_lower
            for t in (
                "https://sap.com",
                "https://www.sap.com",
                "https://ibm.com",
                "https://www.ibm.com",
                "https://google.com",
                "https://www.google.com",
                "https://microsoft.com",
                "https://www.microsoft.com",
                "https://apple.com",
                "https://www.apple.com",
                "https://github.com",
            )
        )
        if has_password and not trusted:
            reasons.append(
                "Password form detected on an unverified third-party domain."
            )

        if reasons:
            return {
                "is_phishing": True,
                "confidence": 0.94,
                "reason": " ".join(reasons),
                "threat_type": "Brand Spoofing",
            }

        return {
            "is_phishing": False,
            "confidence": 0.04,
            "reason": "Page appears clean.",
            "threat_type": "None",
        }

    def threat_response(data: PageData, result: dict):
        threat_info = {
            "url": data.url,
            "threat_type": result.get("threat_type", "Heuristic Detected Threat"),
            "reason": result.get("reason", "Flagged by security analysis."),
            "confidence": result.get("confidence", 0.95),
        }
        try:
            supabase.table("security_logs").insert(threat_info).execute()
        except Exception as e:
            print("Supabase Insert Error:", e)

        return {
            "is_phishing": True,
            "confidence": threat_info["confidence"],
            "reason": threat_info["reason"],
            "threat_type": threat_info["threat_type"],
            "mitre_tactic": "T1566 - Phishing via Heuristic Detection",
        }

    @inner_web_app.get("/health")
    def health():
        return {"status": "ok", "mode": "heuristic-only"}

    @inner_web_app.post("/analyze")
    def analyze_page(data: PageData):
        # Pure heuristics — Gemini/OpenAI quotas are exhausted for this hackathon
        result = heuristic_result(data.url, data.html)
        print("Heuristic result:", result)
        if result.get("is_phishing"):
            return threat_response(data, result)
        return {
            "is_phishing": False,
            "confidence": result.get("confidence", 0.01),
            "reason": result.get("reason", "Page appears clean."),
        }

    return inner_web_app
