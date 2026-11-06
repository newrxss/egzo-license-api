"""EGZO license API for Railway.

Keys are never returned by this API and are stored only as HMAC hashes.
"""
import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import psycopg
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
LICENSE_PEPPER = os.environ.get("LICENSE_PEPPER", "")


def require_config() -> None:
    missing = [name for name, value in {
        "DATABASE_URL": DATABASE_URL,
        "ADMIN_API_KEY": ADMIN_API_KEY,
        "LICENSE_PEPPER": LICENSE_PEPPER,
    }.items() if not value]
    if missing:
        raise RuntimeError("Missing Railway variables: " + ", ".join(missing))


def key_hash(key: str) -> str:
    normalized = key.strip().lower()
    return hmac.new(LICENSE_PEPPER.encode(), normalized.encode(), hashlib.sha256).hexdigest()


def device_hash(device_id: str | None) -> str | None:
    if not device_id:
        return None
    return hashlib.sha256(device_id.encode()).hexdigest()


def admin_only(value: str | None) -> None:
    if not value or not hmac.compare_digest(value, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")


def connection():
    require_config()
    return psycopg.connect(DATABASE_URL, sslmode="require")


def create_tables() -> None:
    with connection() as db, db.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key_hash TEXT PRIMARY KEY,
                duration_seconds INTEGER NOT NULL CHECK (duration_seconds > 0),
                activated_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ,
                device_hash TEXT,
                revoked BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_tables()
    yield


app = FastAPI(title="EGZO License API", lifespan=lifespan)


class ValidateRequest(BaseModel):
    key: str = Field(min_length=8, max_length=128)
    device_id: str | None = Field(default=None, max_length=256)


class AddKeysRequest(BaseModel):
    keys: list[str] = Field(min_length=1, max_length=500)
    duration_days: int = Field(ge=1, le=3650)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/v1/licenses/validate")
def validate_license(request: ValidateRequest):
    now = datetime.now(timezone.utc)
    incoming_key_hash = key_hash(request.key)
    incoming_device_hash = device_hash(request.device_id)

    with connection() as db, db.cursor() as cur:
        cur.execute(
            "SELECT duration_seconds, activated_at, expires_at, device_hash, revoked "
            "FROM licenses WHERE key_hash = %s",
            (incoming_key_hash,),
        )
        license_row = cur.fetchone()
        if not license_row:
            return {"valid": False, "reason": "invalid_key"}

        duration, activated_at, expires_at, saved_device_hash, revoked = license_row
        if revoked:
            return {"valid": False, "reason": "revoked"}

        if saved_device_hash and saved_device_hash != incoming_device_hash:
            return {"valid": False, "reason": "device_mismatch"}

        if not activated_at:
            expires_at = now + timedelta(seconds=duration)
            cur.execute(
                "UPDATE licenses SET activated_at = %s, expires_at = %s, device_hash = %s "
                "WHERE key_hash = %s",
                (now, expires_at, incoming_device_hash, incoming_key_hash),
            )
        elif expires_at <= now:
            return {"valid": False, "reason": "expired", "expires_at": expires_at.isoformat()}

    remaining = max(0, int((expires_at - now).total_seconds()))
    return {"valid": True, "expires_at": expires_at.isoformat(), "seconds_left": remaining}


@app.post("/admin/licenses")
def add_licenses(request: AddKeysRequest, x_admin_key: str | None = Header(default=None)):
    admin_only(x_admin_key)
    duration_seconds = request.duration_days * 24 * 60 * 60
    unique_keys = {key.strip().lower() for key in request.keys if key.strip()}
    added = 0
    with connection() as db, db.cursor() as cur:
        for key in unique_keys:
            cur.execute(
                "INSERT INTO licenses (key_hash, duration_seconds) VALUES (%s, %s) "
                "ON CONFLICT (key_hash) DO NOTHING",
                (key_hash(key), duration_seconds),
            )
            added += cur.rowcount
    return {"added": added, "duplicates": len(unique_keys) - added}


@app.get("/admin/stats")
def stats(x_admin_key: str | None = Header(default=None)):
    admin_only(x_admin_key)
    with connection() as db, db.cursor() as cur:
        cur.execute("SELECT COUNT(*), COUNT(*) FILTER (WHERE activated_at IS NULL), "
                    "COUNT(*) FILTER (WHERE revoked) FROM licenses")
        total, unused, revoked = cur.fetchone()
    return {"total": total, "unused": unused, "revoked": revoked}
