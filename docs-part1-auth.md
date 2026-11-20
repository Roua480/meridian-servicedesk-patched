# Part 1: authentication fixes and attack verification

Bearer tokens accept HS256 only, compare every signature in constant time, and
require a finite numeric expiry strictly in the future. Malformed tokens return
401. The signing key comes from MERIDIAN_TOKEN_KEY, with no source-code default.

Reset credentials use secrets.token_urlsafe(32), providing 256 bits of randomness.
Only a SHA-256 hash is stored in PasswordResetToken, bound to a user and an expiry
15 minutes after issuance. A new request replaces the previous credential.
Successful consumption deletes it in the same database transaction as the password
change; a user row lock serializes concurrent requests on PostgreSQL. Credentials
are emailed only to the active account's saved address and never appear in the
HTTP response. Empty or invalid passwords are rejected. Delivery failure deletes
the credential and retains the same HTTP response. Real and nonexistent usernames
receive identical response bodies and status codes. This does not promise equal
SMTP timing; production deployments should queue mail for asynchronous delivery.

## Running the stack

A random local key has been generated in lab/auth.env for this checkout. That file
is excluded from Git and Docker build context. On a fresh checkout, generate it:

```powershell
python -c "import secrets; from pathlib import Path; Path('lab/auth.env').write_text('MERIDIAN_TOKEN_KEY='+secrets.token_urlsafe(48)+'\n')"
docker compose -f lab/docker-compose.yml up --build
```

Startup applies migration 0042. Configure EMAIL_HOST and EMAIL_PORT to deliver
messages through SMTP. The existing lab default prints email to container logs;
use only locally for the lab. On non-Compose deployments, provision the signing
key through the environment or secret manager. Changing it invalidates old bearer
tokens. Never commit lab/auth.env.

## Verification

```powershell
.venv/Scripts/python -m django test tests.test_auth_security --settings=tests.auth_settings -v 1
```

Result: 8 tests passed against Django's HTTP test client and a migrated SQLite
test database. These repeat the attacks against the actual view functions:

- Forged alg=none token: 401; other algorithms and tampered signatures: 401.
- Missing, expired, boolean, nonnumeric, NaN and infinite expiry: 401.
- Malformed tokens: 401; correctly signed unexpired token: 200.
- Real and invented username at /auth/forgot/: identical 200 and JSON body.
- Computed MD5(username + "reset") token: 401, before and after requesting reset.
- Valid random reset: 200; replay, wrong user, superseded and expired tokens: 401.
- Delivery goes only to the saved address; database contains only the token hash.
- GET is refused; password validation and mail-failure handling are covered.

Live verification completed on 2026-11-20 after Docker became available. The
existing app container was recreated to load lab/auth.env; migration 0042 applied
successfully. Confirmed PostgreSQL is in use and the active admin account exists.

```powershell
.venv/Scripts/python tests/live_auth_attacks.py
```

All three live attacks passed through http://127.0.0.1:5001 (nginx/Gunicorn):
forged unsigned admin bearer token returned 401; admin and a unique nonexistent
username received identical 200 responses and JSON bodies from /auth/forgot/;
the computed MD5 reset token returned 401 from /auth/reset/. The script requests
a reset email but never submits a valid password reset.

Migration consistency checking reported unrelated existing changes to
attachment upload paths and queue logging_dir; no extra migration was generated.
The AGENTS.md reference .course/rules.md was absent in this checkout.
