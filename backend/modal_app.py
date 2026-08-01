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
    "sso-login",
    "mfa-reset",
)


@app.function(
    image=image,
    secrets=[
        modal.Secret.from_name("supabase-secret"),
        modal.Secret.from_name("gemini-secret"),
        modal.Secret.from_name("openai-secret"),
        # Optional: create with `modal secret create groq-secret GROQ_API_KEY=gsk_...`
        # modal.Secret.from_name("groq-secret"),
    ],
)
@modal.asgi_app()
def fastapi_app():
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_KEY")
    supabase: Client = create_client(supabase_url, supabase_key)

    groq_key = os.environ.get("GROQ_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    groq_client = (
        openai.OpenAI(api_key=groq_key, base_url="https://api.groq.com/openai/v1")
        if groq_key
        else None
    )
    openai_client = openai.OpenAI(api_key=openai_key) if openai_key else None

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
            'type="password"' in html_lower or "type='password'" in html_lower
        )
        trusted = any(
            t in url_lower
            for t in (
                "sap.com",
                "ibm.com",
                "localhost",
                "127.0.0.1",
                "example.com",
                "google.com",
                "microsoft.com",
                "apple.com",
                "github.com",
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

    def ask_fast_ai(prompt: str):
        # Groq first (free + very fast), then OpenAI. Skip Gemini — quota exhausted.
        providers = []
        if groq_client:
            providers.append(("groq", groq_client, "llama-3.1-8b-instant"))
        if openai_client:
            providers.append(("openai", openai_client, "gpt-4o-mini"))

        last_error = None
        for name, client, model in providers:
            try:
                completion = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                    temperature=0,
                    max_tokens=300,
                )
                result = json.loads(completion.choices[0].message.content)
                print(f"AI Analysis via {name}/{model}:", result)
                return result
            except Exception as e:
                last_error = e
                print(f"AI Error ({name}/{model}):", e)
        if last_error:
            raise last_error
        raise RuntimeError("No AI provider configured")

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
        # Always compute heuristics first — instant, no quota issues
        fallback = heuristic_result(data.url, data.html)
        if fallback.get("is_phishing"):
            print("Heuristic phishing hit:", fallback)
            return threat_response(data, fallback)

        # Optional AI only for clean/borderline pages (skip if no keys / failures)
        prompt = f"""
        You are a cybersecurity expert. Analyze this page for phishing.
        URL: {data.url}
        HTML Snippet: {(data.html or '')[:1500]}
        Return JSON with keys: is_phishing (bool), confidence (0-1), reason (string), threat_type (string).
        """
        try:
            result = ask_fast_ai(prompt)
            if result.get("is_phishing"):
                return threat_response(data, result)
            return {
                "is_phishing": False,
                "confidence": result.get("confidence", 0.01),
                "reason": result.get("reason", "Page appears clean."),
            }
        except Exception as e:
            print("AI unavailable, returning heuristic result:", e)
            return fallback

    return inner_web_app
