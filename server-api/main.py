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
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

DB_PATH = os.environ.get("RD_API_DB", "/data/api.db")
RD_USER = os.environ.get("RD_API_USER", "admin")
RD_PASSWORD = os.environ.get("RD_API_PASSWORD", "")
TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 days
PBKDF2_ITERATIONS = 200_000

_token_cache: dict[str, int] = {}  # token -> expiry (mirror of DB, rebuilt on boot)


def db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                pw_hash TEXT NOT NULL,
                email TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
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


def prune_tokens() -> None:
    now = int(time.time())
    stale = [t for t, exp in _token_cache.items() if exp <= now]
    if not stale:
        return
    for t in stale:
        _token_cache.pop(t, None)
    with db() as conn:
        conn.executemany("DELETE FROM tokens WHERE token=?", [(t,) for t in stale])


def auth_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    token = authorization[len("Bearer "):].strip()
    expires_at = _token_cache.get(token)
    now = int(time.time())
    if expires_at is None:
        with db() as conn:
            row = conn.execute(
                "SELECT expires_at FROM tokens WHERE token=?", (token,)
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        expires_at = row["expires_at"]
        _token_cache[token] = expires_at
    if expires_at <= now:
        raise HTTPException(status_code=401, detail="Invalid token")
    return token


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
    init_db()
    with db() as conn:
        rows = conn.execute("SELECT token, expires_at FROM tokens").fetchall()
    now = int(time.time())
    _token_cache.update({r["token"]: r["expires_at"] for r in rows if r["expires_at"] > now})
    with db() as conn:
        conn.execute("DELETE FROM tokens WHERE expires_at<=?", (now,))
    yield


app = FastAPI(lifespan=lifespan)


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException):
    # Client checks body {"error": ...}; 401/400 status triggers token reset.
    return JSONResponse(
        status_code=exc.status_code, content={"error": str(exc.detail)}
    )


@app.post("/api/login")
def login(body: LoginBody):
    if body.type not in ("account",):
        return {"error": "Unsupported login type"}
    if not body.username or not body.password:
        return {"error": "Username or password missed"}
    with db() as conn:
        row = conn.execute(
            "SELECT pw_hash, email FROM users WHERE username=?", (body.username,)
        ).fetchone()
    if row is None or not verify_password(body.password, row["pw_hash"]):
        return {"error": "Wrong username or password"}
    token = secrets.token_hex(32)
    expires_at = int(time.time()) + TOKEN_TTL_SECONDS
    _token_cache[token] = expires_at
    with db() as conn:
        conn.execute(
            "INSERT INTO tokens(token,username,expires_at) VALUES(?,?,?)",
            (token, body.username, expires_at),
        )
        conn.execute(
            "INSERT OR IGNORE INTO address_book(username) VALUES(?)", (body.username,)
        )
    return {
        "access_token": token,
        "type": "access_token",
        "user": {"name": body.username, "email": row["email"] or ""},
    }


@app.post("/api/logout")
def logout(request: SimpleBody, authorization: str | None = Header(default=None)):
    try:
        token = auth_token(authorization)
    except HTTPException:
        return {}
    _token_cache.pop(token, None)
    with db() as conn:
        conn.execute("DELETE FROM tokens WHERE token=?", (token,))
    return {}


@app.post("/api/currentUser")
def current_user(request: SimpleBody, authorization: str | None = Header(default=None)):
    token = auth_token(authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM tokens WHERE token=?", (token,)
        ).fetchone()
    return {"name": row["username"]}


@app.post("/api/ab/get")
def ab_get(request: AbGetBody, authorization: str | None = Header(default=None)):
    token = auth_token(authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM tokens WHERE token=?", (token,)
        ).fetchone()
        ab = conn.execute(
            "SELECT data, updated_at FROM address_book WHERE username=?",
            (row["username"],),
        ).fetchone()
    if ab is None:
        return {"data": json.dumps({"peers": [], "tags": []}), "updated_at": 0}
    return {"data": ab["data"], "updated_at": ab["updated_at"]}


@app.post("/api/ab")
def ab_save(body: AbSaveBody, authorization: str | None = Header(default=None)):
    token = auth_token(authorization)
    json.loads(body.data)  # reject malformed payloads
    with db() as conn:
        row = conn.execute(
            "SELECT username FROM tokens WHERE token=?", (token,)
        ).fetchone()
        conn.execute(
            "INSERT INTO address_book(username,data,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(username) DO UPDATE SET data=excluded.data, "
            "updated_at=excluded.updated_at",
            (row["username"], body.data, int(time.time())),
        )
    return {}
