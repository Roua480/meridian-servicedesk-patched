"""Repeat Part 1 attacks against the local nginx/Gunicorn/PostgreSQL stack.

Run: .venv/Scripts/python tests/live_auth_attacks.py
Only requests a reset email; never submits a valid password reset.
"""
import base64
import hashlib
import json
import time

import requests

BASE = "http://127.0.0.1:5001"


def segment(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def main():
    forged = segment({"alg": "none", "typ": "JWT"}) + "." + segment({
        "user": "admin", "is_staff": True, "exp": int(time.time()) + 3600,
    }) + "."
    response = requests.get(BASE + "/api/whoami/", headers={
        "Authorization": "Bearer " + forged,
    }, timeout=15)
    assert response.status_code == 401, (response.status_code, response.text[:200])
    print("PASS forged unsigned admin token: 401")
    real = requests.post(BASE + "/auth/forgot/", data={"username": "admin"}, timeout=15)
    fake = requests.post(BASE + "/auth/forgot/", data={
        "username": "part1-nonexistent-" + str(time.time_ns()),
    }, timeout=15)
    assert real.status_code == 200, (real.status_code, real.text[:200])
    assert (real.status_code, real.content) == (fake.status_code, fake.content)
    assert "reset_token" not in real.json()
    print("PASS enumeration: real and invented names return identical 200 and body")
    print(real.text)
    computed = hashlib.md5(b"adminreset").hexdigest()[:8]
    response = requests.post(BASE + "/auth/reset/", data={
        "username": "admin", "token": computed,
        "new_password": "This-password-must-never-be-applied-123!",
    }, timeout=15)
    assert response.status_code == 401, (response.status_code, response.text[:200])
    print("PASS computed reset token: 401")


if __name__ == "__main__":
    main()
