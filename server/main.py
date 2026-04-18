import os
import sqlite3
import secrets
import time
from html import escape
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

BOT_SECRET = os.getenv("BOT_SECRET", "")
APP_SECRET = os.getenv("APP_SECRET", "")
DB_PATH = os.getenv("DB_PATH", "codes.db")
CODE_TTL_SECONDS = int(os.getenv("CODE_TTL_SECONDS", "600"))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "600"))
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://api.pro-ver-ka.ru").rstrip("/")
ANDROID_APP_LINK = os.getenv("ANDROID_APP_LINK", "")

app = FastAPI(title="V7CK9LL Code Server")


def db():
    return sqlite3.connect(DB_PATH)


def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS codes (
                code TEXT PRIMARY KEY,
                user_id TEXT,
                expires_at INTEGER,
                used INTEGER DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                device_id TEXT,
                expires_at INTEGER
            )
            """
        )


@app.on_event("startup")
def _startup():
    init_db()


class IssueReq(BaseModel):
    user_id: Optional[str] = None


class VerifyReq(BaseModel):
    code: str
    device_id: str


class ValidateReq(BaseModel):
    session_token: str


def check_secret(given: Optional[str], expected: str, name: str):
    if not expected:
        raise HTTPException(status_code=500, detail=f"{name} not configured")
    if given != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


def gen_code() -> str:
    # V7-XXXX-XXXX
    a = secrets.token_hex(2).upper()
    b = secrets.token_hex(2).upper()
    return f"V7-{a}-{b}"


def android_activation_links(code: str) -> dict:
    safe_code = quote(code.strip().upper())
    return {
        "android_activation_url": f"{PUBLIC_BASE_URL}/android/activate?code={safe_code}",
        "android_scheme_url": f"v7ck9ll://activate?code={safe_code}",
    }


@app.post("/issue")
def issue(req: IssueReq, x_bot_secret: Optional[str] = Header(None)):
    check_secret(x_bot_secret, BOT_SECRET, "BOT_SECRET")
    code = gen_code()
    expires_at = int(time.time()) + CODE_TTL_SECONDS
    with db() as conn:
        conn.execute(
            "INSERT INTO codes(code, user_id, expires_at, used) VALUES(?, ?, ?, 0)",
            (code, req.user_id or "", expires_at),
        )
    return {"code": code, "expires_at": expires_at, **android_activation_links(code)}


@app.get("/android/activate", response_class=HTMLResponse)
def android_activate(code: str = ""):
    clean_code = code.strip().upper()
    scheme_url = android_activation_links(clean_code)["android_scheme_url"] if clean_code else "v7ck9ll://activate"
    escaped_code = escape(clean_code)
    escaped_scheme = escape(scheme_url, quote=True)
    escaped_app_link = escape(ANDROID_APP_LINK, quote=True)
    install_block = (
        f'<a class="button secondary" href="{escaped_app_link}">Скачать приложение</a>'
        if ANDROID_APP_LINK else ""
    )
    return f"""
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Активация V7CK9LL</title>
  <style>
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #080a12;
      color: #f5f7fb;
      font-family: sans-serif;
    }}
    main {{
      width: min(92vw, 440px);
      padding: 28px;
      border: 1px solid #26324f;
      border-radius: 20px;
      background: linear-gradient(160deg, #111827, #070914);
    }}
    .code {{
      padding: 12px 14px;
      border-radius: 12px;
      background: #050713;
      font-family: monospace;
      letter-spacing: .04em;
    }}
    .button {{
      display: block;
      margin-top: 16px;
      padding: 14px 16px;
      border-radius: 999px;
      background: #6ea8ff;
      color: #08101f;
      text-align: center;
      text-decoration: none;
      font-weight: 700;
    }}
    .secondary {{
      background: transparent;
      color: #d8e6ff;
      border: 1px solid #324466;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Активация Android</h1>
    <p>Если приложение уже установлено, нажмите кнопку ниже. Код подставится автоматически.</p>
    <p class="code">{escaped_code or "Код не передан"}</p>
    <a class="button" href="{escaped_scheme}">Открыть приложение</a>
    {install_block}
  </main>
  <script>
    if ("{escaped_code}") {{
      setTimeout(function () {{
        window.location.href = "{escaped_scheme}";
      }}, 250);
    }}
  </script>
</body>
</html>
"""


@app.post("/verify")
def verify(req: VerifyReq, x_app_secret: Optional[str] = Header(None)):
    check_secret(x_app_secret, APP_SECRET, "APP_SECRET")
    now = int(time.time())
    with db() as conn:
        row = conn.execute(
            "SELECT code, expires_at, used FROM codes WHERE code=?",
            (req.code,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="invalid_code")
        code, expires_at, used = row
        if used:
            raise HTTPException(status_code=400, detail="code_used")
        if expires_at < now:
            raise HTTPException(status_code=400, detail="code_expired")
        # mark used
        conn.execute("UPDATE codes SET used=1 WHERE code=?", (code,))

        token = secrets.token_urlsafe(32)
        session_expires = now + SESSION_TTL_SECONDS
        conn.execute(
            "INSERT INTO sessions(token, device_id, expires_at) VALUES(?, ?, ?)",
            (token, req.device_id, session_expires),
        )
    return {"ok": True, "session_token": token, "expires_at": session_expires}


@app.post("/validate")
def validate(req: ValidateReq, x_app_secret: Optional[str] = Header(None)):
    check_secret(x_app_secret, APP_SECRET, "APP_SECRET")
    now = int(time.time())
    with db() as conn:
        row = conn.execute(
            "SELECT token, expires_at FROM sessions WHERE token=?",
            (req.session_token,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="invalid_session")
        _, expires_at = row
        if expires_at < now:
            raise HTTPException(status_code=400, detail="session_expired")
    return {"ok": True, "expires_at": expires_at}
