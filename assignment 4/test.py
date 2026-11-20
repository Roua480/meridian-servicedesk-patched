import hashlib
import zlib

known = {
    "jdoe": "e66c083e",
    "admin": "2e5f7dd9",   # <-- VERIFY THIS — the screenshot's 'i' isn't valid hex, likely 'f'
    "rmasri": "b458ae75",
}

hash_funcs = {
    "md5": lambda s: hashlib.md5(s.encode()).hexdigest(),
    "sha1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
    "sha256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
    "crc32": lambda s: format(zlib.crc32(s.encode()) & 0xffffffff, '08x'),
}

candidate_words = [
    "reset", "forgot", "token", "secret", "salt", "password",
    "meridian", "meridian-servicedesk", "servicedesk",
    "token_auth", "auth", "key", "pepper", ""
]

separators = ["", "_", "-", ":"]

found_any = False

for username, real_token in known.items():
    for word in candidate_words:
        for sep in separators:
            variants = {
                "user+sep+word": username + sep + word,
                "word+sep+user": word + sep + username,
                "lower_user+sep+word": username.lower() + sep + word,
                "upper_user+sep+word": username.upper() + sep + word,
            }
            for label, combined in variants.items():
                for hash_name, hash_func in hash_funcs.items():
                    digest = hash_func(combined)
                    if digest[:8] == real_token or digest == real_token:
                        print(f"MATCH for {username} ({label}): {hash_name}({combined!r}) -> {digest}")
                        found_any = True

if not found_any:
    print("No match found. Double-check the admin token (the 'i' character is invalid hex) and rerun.")