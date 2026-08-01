import os
import json
import modal
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
import openai

app = modal.App("is-this-for-real")

image = modal.Image.debian_slim().pip_install("fastapi", "pydantic", "supabase", "openai")

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
)


@app.function(
    image=image,
    secrets=[
        modal.Secret.from_name("supabase-secret"),
        modal.Secret.from_name("gemini-secret"),
        modal.Secret.from_name("openai-secret"),
    ],
)
@modal.asgi_app()
def fastapi_app():
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_KEY")
    supabase: Client = create_client(supabase_url, supabase_key)

    gemini_client = openai.OpenAI(
        api_key=os.environ.get("GEMINI_API_KEY"),
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    )
    openai_client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

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
        html: str

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
            'type="password"' in html_lower or "type='password'" in html_lower
        )
        trusted = any(
            t in url_lower
            for t in ("sap.com", "ibm.com", "localhost", "127.0.0.1", "example.com")
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

    def ask_model(client, model: str, prompt: str):
        completion = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        return json.loads(completion.choices[0].message.content)

    def ask_ai(prompt: str):
        # Prefer OpenAI first — Gemini free tier is currently exhausted (limit: 0)
        providers = [
            ("openai", openai_client, "gpt-4o-mini"),
            ("gemini", gemini_client, "gemini-2.0-flash"),
        ]
        last_error = None
        for name, client, model in providers:
            if name == "openai" and not os.environ.get("OPENAI_API_KEY"):
                continue
            if name == "gemini" and not os.environ.get("GEMINI_API_KEY"):
                continue
            try:
                result = ask_model(client, model, prompt)
                print(f"AI Analysis via {name}/{model}:", result)
                return result
            except Exception as e:
                last_error = e
                print(f"AI Error ({name}/{model}):", e)
        raise last_error or RuntimeError("No AI provider available")

    def threat_response(data: PageData, result: dict):
        threat_info = {
            "url": data.url,
            "threat_type": result.get("threat_type", "AI Detected Threat"),
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
            "mitre_tactic": "T1566 - Phishing via AI Detection",
        }

    @inner_web_app.post("/analyze")
    def analyze_page(data: PageData):
        # 1) Instant heuristic path for reliable hackathon demos
        fallback = heuristic_result(data.url, data.html)
        if fallback.get("is_phishing"):
            print("Heuristic phishing hit (skipping AI):", fallback)
            return threat_response(data, fallback)

        prompt = f"""
        You are an elite cybersecurity expert analyzing a webpage for phishing and credential harvesting.
        URL: {data.url}
        HTML Snippet: {data.html[:2500]}

        Analyze the URL and the HTML for deceptive patterns, fake SSO logins, or urgency tactics.
        CRITICAL RULE: If the URL contains suspicious phishing or brand-spoofing keywords (such as 'sap-login', 'verify-account', 'slack-update', 'ibm-auth', 'phish'), treat it as a malicious phishing attempt and set 'is_phishing' to true, even if the underlying HTML is generic or blank placeholder text.

        Respond strictly in valid JSON format with the following keys:
        - is_phishing (boolean: true if malicious, false if safe)
        - confidence (float between 0.0 and 1.0)
        - reason (short 1-sentence string explaining your finding)
        - threat_type (short string, e.g., 'Brand Spoofing', 'Credential Harvester', or 'None')
        """

        # 2) AI path for borderline pages (OpenAI first, Gemini second)
        try:
            result = ask_ai(prompt)
        except Exception as e:
            print("All AI providers unavailable, using heuristic fallback:", e)
            result = fallback

        if result.get("is_phishing"):
            return threat_response(data, result)

        return {
            "is_phishing": False,
            "confidence": result.get("confidence", 0.01),
            "reason": result.get("reason", "Page appears clean."),
        }

    return inner_web_app
