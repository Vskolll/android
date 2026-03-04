# V7CK9LL Checker Code Server (FastAPI)

## What it does
- Issues **one-time codes** via bot (10-minute TTL).
- App verifies code and receives a **session token** valid for 10 minutes.

## Environment
Set these in Render (or `.env` locally):
```
BOT_SECRET=change_me_long_random
APP_SECRET=change_me_long_random
DB_PATH=/data/codes.db
CODE_TTL_SECONDS=600
SESSION_TTL_SECONDS=600
```

## Run locally
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints
- `POST /issue` (bot only)
  - Header: `X-Bot-Secret: <BOT_SECRET>`
  - Body: `{ "user_id": "12345" }`
  - Response: `{ "code": "V7-ABCD-1234", "expires_at": 1700000000 }`

- `POST /verify` (app)
  - Header: `X-App-Secret: <APP_SECRET>`
  - Body: `{ "code": "V7-ABCD-1234", "device_id": "android-id" }`
  - Response: `{ "ok": true, "session_token": "…", "expires_at": 1700000000 }`

- `POST /validate` (optional)
  - Header: `X-App-Secret: <APP_SECRET>`
  - Body: `{ "session_token": "…" }`
  - Response: `{ "ok": true, "expires_at": 1700000000 }`
