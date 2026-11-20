"""Token authentication for the API.

Clients exchange their credentials for a bearer token at /api/token/ and then
send it as `Authorization: Bearer <token>` to token-protected endpoints.
"""

import base64
import hashlib
import hmac
import json
import time
import math
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.views.decorators.http import require_POST

from helpdesk.models import PasswordResetToken

from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

TOKEN_TTL = 3600


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _sign(signing_input: bytes) -> str:
    digest = hmac.new(settings.MERIDIAN_TOKEN_KEY.encode(), signing_input, hashlib.sha256).digest()
    return _b64url(digest)


def issue_token(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_segment = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_segment = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_segment}.{payload_segment}".encode()
    signature = _sign(signing_input)
    return f"{header_segment}.{payload_segment}.{signature}"


def decode_token(token: str) -> dict | None:
    try:
        header_segment, payload_segment, signature = token.split(".")
        header = json.loads(_b64url_decode(header_segment))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return None
        signing_input = f"{header_segment}.{payload_segment}".encode()
        if not hmac.compare_digest(_sign(signing_input), signature):
            return None
        payload = json.loads(_b64url_decode(payload_segment))
        if not isinstance(payload, dict):
            return None
        expiry = payload.get("exp")
        if (type(expiry) not in (int, float) or not math.isfinite(expiry)
                or expiry <= time.time()):
            return None
        return payload
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return None


@csrf_exempt
def obtain_token(request):
    if request.method != "POST":
        return JsonResponse({"detail": "POST required"}, status=405)

    username = request.POST.get("username")
    password = request.POST.get("password")
    user = authenticate(username=username, password=password)
    if user is None:
        return JsonResponse({"detail": "invalid credentials"}, status=401)

    token = issue_token(
        {
            "user": user.username,
            "is_staff": user.is_staff,
            "exp": int(time.time()) + TOKEN_TTL,
        }
    )
    return JsonResponse({"token": token})


@csrf_exempt
def legacy_login(request):
    """Older token login kept for the legacy mobile client."""
    from django.db import connection

    if request.method != "POST":
        return JsonResponse({"detail": "POST required"}, status=405)

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    sql = (
        "SELECT id, username, is_staff FROM auth_user "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
    with connection.cursor() as cursor:
        cursor.execute(sql)
        row = cursor.fetchone()

    if not row:
        return JsonResponse({"detail": "invalid credentials"}, status=401)

    token = issue_token(
        {"user": row[1], "is_staff": bool(row[2]), "exp": int(time.time()) + TOKEN_TTL}
    )
    return JsonResponse({"token": token, "user": row[1]})


@csrf_exempt
@require_POST
def forgot_password(request):
    """Deliver an opaque reset credential only to the saved account address."""
    username = request.POST.get("username", "")
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    with transaction.atomic():
        user = get_user_model().objects.select_for_update().filter(
            username=username, is_active=True
        ).first()
        if user and user.email and user.has_usable_password():
            PasswordResetToken.objects.filter(user=user).delete()
            reset = PasswordResetToken.objects.create(
                user=user, token_hash=digest,
                expires_at=timezone.now() + timedelta(minutes=15),
            )
            # Never use an address supplied by the requester.
            try:
                send_mail(
                    "Meridian password reset",
                    f"Your password reset token is: {token}\n"
                    "Submit it to /auth/reset/ with your username and new_password. "
                    "It expires in 15 minutes and can be used once.",
                    settings.DEFAULT_FROM_EMAIL, [user.email],
                )
            except Exception:
                # Delivery failures must not reveal whether an account exists.
                reset.delete()
    return JsonResponse({
        "detail": "If the account is eligible, a reset token will be emailed to its saved address."
    })


@csrf_exempt
@require_POST
def reset_password(request):
    """Atomically consume a reset credential and change the password."""
    username = request.POST.get("username", "")
    token = request.POST.get("token", "")
    new_password = request.POST.get("new_password", "")
    digest = hashlib.sha256(token.encode()).hexdigest()
    with transaction.atomic():
        user = get_user_model().objects.select_for_update().filter(
            username=username, is_active=True
        ).first()
        reset = PasswordResetToken.objects.filter(
            user=user, token_hash=digest, expires_at__gt=timezone.now()
        ).first() if user else None
        if reset is None:
            return JsonResponse({"detail": "bad token"}, status=401)
        try:
            validate_password(new_password, user=user)
            if not new_password:
                raise ValidationError("Password cannot be empty.")
        except ValidationError as error:
            return JsonResponse({"detail": error.messages}, status=400)
        # Conditional deletion also prevents concurrent consumption on databases
        # where SELECT FOR UPDATE is unavailable.
        consumed, _ = PasswordResetToken.objects.filter(pk=reset.pk).delete()
        if not consumed:
            return JsonResponse({"detail": "bad token"}, status=401)
        user.set_password(new_password)
        user.save(update_fields=["password"])
        PasswordResetToken.objects.filter(user=user).delete()
    return JsonResponse({"detail": "password reset", "username": username})


def whoami(request):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not header.startswith("Bearer "):
        return JsonResponse({"detail": "no token"}, status=401)

    payload = decode_token(header[len("Bearer ") :])
    if payload is None:
        return JsonResponse({"detail": "invalid token"}, status=401)

    return JsonResponse(
        {"user": payload.get("user"), "is_staff": payload.get("is_staff")}
    )
