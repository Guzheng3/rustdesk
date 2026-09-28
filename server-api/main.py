"""Minimal single-user RustDesk API server (login + address book).

Implements exactly the API surface the sciter client calls:
  POST /api/login        {username,password,id,uuid,type,deviceInfo} -> {access_token, user:{...}}
  POST /api/logout       {id,uuid} + Bearer -> {}
  POST /api/currentUser  {id,uuid} + Bearer -> {name,...} (error: {"error": "Invalid token"})
  POST /api/ab/get       {} + Bearer -> {data: "<json str>", updated_at}
  POST /api/ab           {data: "<json str>"} + Bearer -> {}
Auth: "Authorization: Bearer <token>"; invalid -> HTTP 401 with {"error": "Invalid token"}
(resp body error field makes the client reset its login state).

Credentials come from env RD_API_USER / RD_API_PASSWORD (upserted on startup).
DB (SQLite) lives at RD_API_DB (default /data/api.db).

Security hardening (enterprise baseline):
  - TLS: set RD_API_TLS_CERT + RD_API_TLS_KEY to serve HTTPS directly on 21114.
  - Login abuse control: per-IP sliding-window rate limit + per-username
    lockout after repeated failures.
  - Tokens are stored hashed (SHA-256) -- a leaked DB yields no live tokens.
  - Address-book payloads are encrypted at rest (AES-256-GCM). Key comes from
    RD_API_ENC_KEY (64 hex chars) or is auto-generated at /data/enc.key (0600).
  - Every auth/ab event is appended to /data/audit.log as JSON lines.
  - Address-book payload size is capped; conservative response headers set.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

DB_PATH = os.environ.get("RD_API_DB", "/data/api.db")
DATA_DIR = Path(DB_PATH).parent
AUDIT_LOG = Path(os.environ.get("RD_API_AUDIT_LOG", str(DATA_DIR / "audit.log")))
AUDIT_MAX_BYTES = 10 * 1024 * 1024
RD_USER = os.environ.get("RD_API_USER", "admin")
RD_PASSWORD = os.environ.get("RD_API_PASSWORD", "")
TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 days
PBKDF2_ITERATIONS = 200_000
LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_PER_WINDOW = 10
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 15 * 60
AB_MAX_BYTES = 4 * 1024 * 1024
ENC_PREFIX = "enc:v1:"

_token_cache: dict[str, int] = {}  # token-hash -> expiry (mirror of DB)
_login_events: dict[str, deque] = defaultdict(deque)  # ip -> timestamps
_lockouts: dict[str, tuple[int, int]] = {}  # username -> (fails, lock_until)
_mutex = threading.Lock()
_audit_mutex = threading.Lock()
_dummy_pw_hash: str | None = None
_gcm = None  # lazily built AESGCM


def db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def audit(event: str, **fields) -> None:
    line = json.dumps({"ts": int(time.time()), "event": event, **fields}, ensure_ascii=False)
    with _audit_mutex:
        if AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > AUDIT_MAX_BYTES:
            AUDIT_LOG.replace(AUDIT_LOG.with_suffix(AUDIT_LOG.suffix + ".1"))
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def _load_enc_key() -> bytes:
    hex_key = os.environ.get("RD_API_ENC_KEY", "").strip()
    if hex_key:
        raw = bytes.fromhex(hex_key)
        if len(raw) != 32:
            raise RuntimeError("RD_API_ENC_KEY must be 64 hex chars (32 bytes)")
        return raw
    key_file = Path(os.environ.get("RD_API_ENC_KEY_FILE", str(DATA_DIR / "enc.key")))
    if key_file.exists():
        return bytes.fromhex(key_file.read_text().strip())
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(secrets.token_hex(32).encode())
    key_file.chmod(0o600)
    return bytes.fromhex(key_file.read_text().strip())


def _ensure_gcm():
    global _gcm
    if _gcm is None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        _gcm = AESGCM(_load_enc_key())
    return _gcm


def encrypt_ab(data: str) -> str:
    gcm = _ensure_gcm()
    nonce = secrets.token_bytes(12)
    ct = gcm.encrypt(nonce, data.encode(), None)
    return ENC_PREFIX + base64.b64encode(nonce + ct).decode()


def decrypt_ab(stored: str) -> str:
    if not stored.startswith(ENC_PREFIX):
        return stored  # legacy plaintext row; re-encrypted on next save
    gcm = _ensure_gcm()
    blob = base64.b64decode(stored[len(ENC_PREFIX):])
    nonce, ct = blob[:12], blob[12:]
    return gcm.decrypt(nonce, ct, None).decode()


def init_db() -> None:
    with db() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(tokens)")}
        if "token" in cols and "token_hash" not in cols:
            # Pre-hardening schema stored raw tokens; wipe and force re-login.
            conn.execute("DROP TABLE tokens")
            audit("tokens_table_migrated")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                pw_hash TEXT NOT NULL,
                email TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS address_book (
                username TEXT PRIMARY KEY,
                data TEXT NOT NULL DEFAULT '{"peers":[],"tags":[]}',
                updated_at INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        if RD_PASSWORD:
            conn.execute(
                "INSERT INTO users(username,pw_hash) VALUES(?,?) "
                "ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash",
                (RD_USER, hash_password(RD_PASSWORD)),
            )


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    ).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS
    ).hex()
    return hmac.compare_digest(candidate, digest)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check_rate_limit(ip: str, username: str) -> str | None:
    """Return an error message when the request must be rejected."""
    now = int(time.time())
    with _mutex:
        events = _login_events[ip]
        while events and events[0] <= now - LOGIN_WINDOW_SECONDS:
            events.popleft()
        if len(events) >= LOGIN_MAX_PER_WINDOW:
            return "Too many login attempts, try later"
        fails, lock_until = _lockouts.get(username, (0, 0))
        if lock_until > now:
            return "Account temporarily locked, try later"
    return None


def record_login_result(ip: str, username: str, ok: bool) -> None:
    now = int(time.time())
    with _mutex:
        _login_events[ip].append(now)
        if ok:
            _lockouts.pop(username, None)
            return
        fails, _ = _lockouts.get(username, (0, 0))
        fails += 1
        lock_until = now + LOCKOUT_SECONDS if fails >= LOCKOUT_THRESHOLD else 0
        _lockouts[username] = (fails, lock_until)
        if lock_until:
            audit("login_locked", ip=ip, username=username)


def auth_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    token_hash = hash_token(authorization[len("Bearer "):].strip())
    expires_at = _token_cache.get(token_hash)
    now = int(time.time())
    if expires_at is None:
        with db() as conn:
            row = conn.execute(
                "SELECT expires_at FROM tokens WHERE token_hash=?", (token_hash,)
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        expires_at = row["expires_at"]
        _token_cache[token_hash] = expires_at
    if expires_at <= now:
        raise HTTPException(status_code=401, detail="Invalid token")
    return token_hash


class LoginBody(BaseModel):
    username: str = ""
    password: str = ""
    id: str = ""
    uuid: str = ""
    type: str = "account"
    verificationCode: str = ""
    tfaCode: str = ""
    secret: str = ""


class AbGetBody(BaseModel):
    id: str = ""
    uuid: str = ""


class AbSaveBody(BaseModel):
    data: str


class SimpleBody(BaseModel):
    id: str = ""
    uuid: str = ""


@asynccontextmanager
async def lifespan(_: FastAPI):
    global _dummy_pw_hash
    _dummy_pw_hash = hash_password(secrets.token_hex(32))
    init_db()
    with db() as conn:
        rows = conn.execute("SELECT token_hash, expires_at FROM tokens").fetchall()
    now = int(time.time())
    _token_cache.update({r["token_hash"]: r["expires_at"] for r in rows if r["expires_at"] > now})
    with db() as conn:
        conn.execute("DELETE FROM tokens WHERE expires_at<=?", (now,))
    audit("boot", tls=bool(os.environ.get("RD_API_TLS_CERT")))
    yield


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException):
    # Client checks body {"error": ...}; 401/400 status triggers token reset.
    return JSONResponse(
        status_code=exc.status_code, content={"error": str(exc.detail)}
    )


@app.post("/api/login")
def login(body: LoginBody, request: Request):
    ip = client_ip(request)
    if body.type not in ("account",):
        return {"error": "Unsupported login type"}
    if not body.username or not body.password:
        return {"error": "Username or password missed"}
    username = body.username[:128]
    if err := check_rate_limit(ip, username):
        audit("login_rate_limited", ip=ip, username=username)
        return {"error": err}
    with db() as conn:
        row = conn.execute(
            "SELECT pw_hash, email FROM users WHERE username=?", (username,)
        ).fetchone()
    # Verify against a dummy hash when the user is unknown, so response timing
    # does not reveal whether the username exists.
    stored = row["pw_hash"] if row else _dummy_pw_hash
    ok = verify_password(body.password, stored or "")
    if row is None or not ok:
        record_login_result(ip, username, ok=False)
        audit("login_fail", ip=ip, username=username)
        return {"error": "Wrong username or password"}
    record_login_result(ip, username, ok=True)
    audit("login_ok", ip=ip, username=username)
    token = secrets.token_hex(32)
    expires_at = int(time.time()) + TOKEN_TTL_SECONDS
    _token_cache[hash_token(token)] = expires_at
    with db() as conn:
        conn.execute(
            "INSERT INTO tokens(token_hash,username,expires_at) VALUES(?,?,?)",
            (hash_token(token), username, expires_at),
        )
        conn.execute(
            "INSERT OR IGNORE INTO address_book(username) VALUES(?)", (username,)
        )
    return {
        "access_token": token,
        "type": "access_token",
        "user": {"name": username, "email": row["email"] or ""},
    }


@app.post("/api/logout")
def logout(request: SimpleBody, authorization: str | None = Header(default=None)):
    try:
        token_hash = auth_token(authorization)
    except HTTPException:
        return {}
    _token_cache.pop(token_hash, None)
    with db() as conn:
        conn.execute("DELETE FROM tokens WHERE token_hash=?", (token_hash,))
    audit("logout", token_hash=token_hash[:12])
    return {}


@app.post("/api/currentUser")
def current_user(request: SimpleBody, authorization: str | None = Header(default=None)):
    token_hash = auth_token(authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM tokens WHERE token_hash=?", (token_hash,)
        ).fetchone()
    return {"name": row["username"]}


@app.post("/api/ab/get")
def ab_get(request: AbGetBody, authorization: str | None = Header(default=None)):
    token_hash = auth_token(authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM tokens WHERE token_hash=?", (token_hash,)
        ).fetchone()
        ab = conn.execute(
            "SELECT data, updated_at FROM address_book WHERE username=?",
            (row["username"],),
        ).fetchone()
    audit("ab_get", username=row["username"])
    if ab is None:
        return {"data": json.dumps({"peers": [], "tags": []}), "updated_at": 0}
    return {"data": decrypt_ab(ab["data"]), "updated_at": ab["updated_at"]}


@app.post("/api/ab")
def ab_save(body: AbSaveBody, authorization: str | None = Header(default=None)):
    token_hash = auth_token(authorization)
    if len(body.data) > AB_MAX_BYTES:
        raise HTTPException(status_code=400, detail="Payload too large")
    json.loads(body.data)  # reject malformed payloads
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM tokens WHERE token_hash=?", (token_hash,)
        ).fetchone()
        conn.execute(
            "INSERT INTO address_book(username,data,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET data=excluded.data, "
            "updated_at=excluded.updated_at",
            (row["username"], encrypt_ab(body.data), int(time.time())),
        )
    audit("ab_save", username=row["username"], bytes=len(body.data))
    return {}


if __name__ == "__main__":
    import uvicorn

    ssl_cert = os.environ.get("RD_API_TLS_CERT", "")
    ssl_key = os.environ.get("RD_API_TLS_KEY", "")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("RD_API_PORT", "21114")),
        ssl_certfile=ssl_cert or None,
        ssl_keyfile=ssl_key or None,
    )
