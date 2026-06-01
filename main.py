import os
import secrets
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token


app = FastAPI(title="Wellar Mobile Auth", version="1.0.0")

allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins != ["*"] else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise HTTPException(status_code=500, detail=f"Missing environment variable: {name}")
    return value


def directus_url() -> str:
    return env_required("DIRECTUS_URL").rstrip("/")


def service_token() -> str:
    token = os.getenv("DIRECTUS_SERVICE_TOKEN") or os.getenv("DIRECTUS_TOKEN")
    if not token:
        raise HTTPException(
            status_code=500,
            detail="Missing DIRECTUS_SERVICE_TOKEN or DIRECTUS_TOKEN",
        )
    return token


def auth_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {service_token()}",
        "Content-Type": "application/json",
    }


def split_name(profile: Dict[str, Any]) -> Dict[str, Optional[str]]:
    given = profile.get("given_name") or ""
    family = profile.get("family_name") or ""

    if given or family:
        return {
            "first_name": given or None,
            "last_name": family or None,
        }

    name = (profile.get("name") or "").strip()
    parts = [part for part in name.split(" ") if part]

    return {
        "first_name": parts[0] if parts else None,
        "last_name": " ".join(parts[1:]) if len(parts) > 1 else None,
    }


async def directus_request(
    method: str,
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url = f"{directus_url()}{path}"

    async with httpx.AsyncClient(timeout=25.0) as client:
        response = await client.request(
            method,
            url,
            headers=auth_headers(),
            params=params,
            json=json_body,
        )

    if response.status_code >= 400:
        body = response.text[:2000]
        raise HTTPException(
            status_code=502,
            detail={
                "error": "DIRECTUS_REQUEST_FAILED",
                "method": method,
                "path": path,
                "status": response.status_code,
                "body": body,
            },
        )

    if not response.text:
        return {}

    return response.json()


async def find_directus_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    result = await directus_request(
        "GET",
        "/users",
        params={
            "filter[email][_eq]": email,
            "limit": 1,
            "fields": "id,email,role,status,token,first_name,last_name",
        },
    )

    data = result.get("data") or []
    return data[0] if data else None


async def create_directus_user(profile: Dict[str, Any], email: str) -> Dict[str, Any]:
    role_id = env_required("MOBILE_AUTH_DEFAULT_ROLE_ID")
    names = split_name(profile)

    payload = {
        "email": email,
        "status": "active",
        "role": role_id,
        **names,
    }

    # These fields may not be writable in every Directus setup.
    # If Directus rejects them, remove them in Codex or permissions.
    if profile.get("sub"):
        payload["external_identifier"] = str(profile["sub"])
        payload["provider"] = "google"

    try:
        result = await directus_request("POST", "/users", json_body=payload)
    except HTTPException as exc:
        # Retry without provider/external_identifier if this Directus instance blocks them.
        if isinstance(exc.detail, dict):
            payload.pop("external_identifier", None)
            payload.pop("provider", None)
            result = await directus_request("POST", "/users", json_body=payload)
        else:
            raise

    return result.get("data") or result


async def update_user_token(user_id: str, token: str) -> Dict[str, Any]:
    result = await directus_request(
        "PATCH",
        f"/users/{user_id}",
        json_body={"token": token},
    )
    return result.get("data") or result


def verify_google_token(raw_id_token: str) -> Dict[str, Any]:
    client_id = env_required("GOOGLE_MOBILE_CLIENT_ID")

    try:
        payload = google_id_token.verify_oauth2_token(
            raw_id_token,
            google_requests.Request(),
            client_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "INVALID_GOOGLE_ID_TOKEN",
                "message": str(exc),
            },
        )

    issuer = payload.get("iss")
    if issuer not in ["accounts.google.com", "https://accounts.google.com"]:
        raise HTTPException(
            status_code=401,
            detail={"error": "INVALID_GOOGLE_ISSUER"},
        )

    email = payload.get("email")
    if not email:
        raise HTTPException(
            status_code=401,
            detail={"error": "GOOGLE_EMAIL_MISSING"},
        )

    if payload.get("email_verified") is not True:
        raise HTTPException(
            status_code=401,
            detail={"error": "GOOGLE_EMAIL_NOT_VERIFIED"},
        )

    return payload


@app.get("/")
async def root():
    return {"status": "ok", "service": "mobile-auth"}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mobile-auth"}


@app.post("/auth/google/mobile-exchange")
async def google_mobile_exchange(request: Request):
    body = await request.json()

    raw_id_token = body.get("id_token") or body.get("idToken")
    if not raw_id_token:
        raise HTTPException(
            status_code=400,
            detail={"error": "MISSING_ID_TOKEN"},
        )

    profile = verify_google_token(raw_id_token)
    email = str(profile["email"]).lower().strip()

    user = await find_directus_user_by_email(email)

    if user and user.get("status") not in [None, "active"]:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "DIRECTUS_USER_NOT_ACTIVE",
                "status": user.get("status"),
            },
        )

    if not user:
        user = await create_directus_user(profile, email)

    user_id = user.get("id")
    if not user_id:
        raise HTTPException(
            status_code=502,
            detail={"error": "DIRECTUS_USER_ID_MISSING"},
        )

    static_token = secrets.token_urlsafe(48)
    updated_user = await update_user_token(user_id, static_token)

    return {
        "access_token": static_token,
        "refresh_token": None,
        "expires": None,
        "token_type": "static",
        "user": {
            "id": updated_user.get("id") or user_id,
            "email": updated_user.get("email") or email,
            "role": updated_user.get("role") or user.get("role"),
        },
    }
