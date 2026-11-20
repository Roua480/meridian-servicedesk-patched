import hashlib
import json
import time
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from django.utils import timezone

from helpdesk.models import PasswordResetToken
from helpdesk.views.token_auth import _b64url, issue_token


class AuthenticationAttacks(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="real-user", password="Original-Password-123!",
            email="owner@example.test",
        )

    def bearer(self, token):
        return self.client.get("/api/whoami/", HTTP_AUTHORIZATION="Bearer " + token)

    def test_forged_unsigned_and_wrong_algorithm_tokens_are_refused(self):
        payload = _b64url(json.dumps({"user": "admin", "is_staff": True,
                                      "exp": time.time() + 3600}).encode())
        for alg in ("none", "HS512", "RS256"):
            header = _b64url(json.dumps({"alg": alg}).encode())
            self.assertEqual(self.bearer(f"{header}.{payload}.").status_code, 401)
        valid = issue_token({"user": "real-user", "exp": time.time() + 60})
        self.assertEqual(self.bearer(valid).status_code, 200)
        self.assertEqual(self.bearer(valid + "x").status_code, 401)

    def test_expiry_is_required_numeric_finite_and_in_the_future(self):
        for expiry in (None, 0, time.time()-1, "tomorrow", True, float("nan"), float("inf")):
            payload = {"user": "admin"}
            if expiry is not None:
                payload["exp"] = expiry
            self.assertEqual(self.bearer(issue_token(payload)).status_code, 401)

    def test_malformed_tokens_are_refused(self):
        for token in ("bad", "a.b.c", "W10.e30.x", "e30.W10.x", "💥.e30.x"):
            self.assertEqual(self.bearer(token).status_code, 401)

    def test_forgot_answers_are_identical_and_only_owner_receives_token(self):
        real = self.client.post("/auth/forgot/", {"username": self.user.username,
                                                 "email": "attacker@example.test"})
        fake = self.client.post("/auth/forgot/", {"username": "made-up-name"})
        self.assertEqual(real.status_code, 200)
        self.assertEqual((real.status_code, real.content), (fake.status_code, fake.content))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [self.user.email])
        self.assertNotIn("reset_token", real.json())

    def token(self):
        self.client.post("/auth/forgot/", {"username": self.user.username})
        return mail.outbox[-1].body.splitlines()[0].split(": ")[1]

    def reset(self, token, username="real-user", password="Replacement-Password-456!"):
        return self.client.post("/auth/reset/", {
            "username": username, "token": token, "new_password": password,
        })

    def test_computed_reset_token_fails(self):
        computed = hashlib.md5((self.user.username + "reset").encode()).hexdigest()[:8]
        self.assertEqual(self.reset(computed).status_code, 401)
        self.token()
        self.assertEqual(self.reset(computed).status_code, 401)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Original-Password-123!"))

    def test_random_token_is_hashed_bound_to_user_and_single_use(self):
        token = self.token()
        self.assertGreaterEqual(len(token), 43)
        stored = PasswordResetToken.objects.get(user=self.user)
        self.assertEqual(stored.token_hash, hashlib.sha256(token.encode()).hexdigest())
        self.assertNotEqual(stored.token_hash, token)
        self.assertEqual(self.reset(token, username="someone-else").status_code, 401)
        self.assertEqual(self.reset(token).status_code, 200)
        self.assertEqual(self.reset(token).status_code, 401)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Replacement-Password-456!"))

    def test_expired_and_superseded_tokens_fail(self):
        first = self.token()
        second = self.token()
        self.assertNotEqual(first, second)
        self.assertEqual(self.reset(first).status_code, 401)
        PasswordResetToken.objects.update(expires_at=timezone.now()-timedelta(seconds=1))
        self.assertEqual(self.reset(second).status_code, 401)

    def test_methods_password_validation_and_delivery_failure(self):
        for path in ("/auth/forgot/", "/auth/reset/"):
            self.assertEqual(self.client.get(path).status_code, 405)
        token = self.token()
        self.assertEqual(self.reset(token, password="").status_code, 400)
        with patch("helpdesk.views.token_auth.send_mail", side_effect=OSError("mail down")):
            real = self.client.post("/auth/forgot/", {"username": self.user.username})
            fake = self.client.post("/auth/forgot/", {"username": "made-up-name"})
        self.assertEqual(real.content, fake.content)
        self.assertFalse(PasswordResetToken.objects.exists())
