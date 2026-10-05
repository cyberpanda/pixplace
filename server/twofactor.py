# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CyberPanda (github.com/cyberpanda)

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30

WINDOW = 1

def new_secret(nbytes: int = 20) -> str:
    return base64.b32encode(os.urandom(nbytes)).decode().rstrip("=")

def _code_at(secret: str, counter: int, digits: int = DIGITS) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    val = struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF
    return str(val % (10 ** digits)).zfill(digits)

def code_now(secret: str, at: float | None = None) -> str:
    return _code_at(secret, int((at or time.time()) // PERIOD))

def verify(secret: str, code: str, at: float | None = None,
           last_counter: int | None = None) -> tuple[bool, int | None]:
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return False, None
    now = int((at or time.time()) // PERIOD)
    for off in range(-WINDOW, WINDOW + 1):
        ctr = now + off
        if last_counter is not None and ctr <= last_counter:
            continue

        if hmac.compare_digest(_code_at(secret, ctr), code):
            return True, ctr
    return False, None

def otpauth_uri(secret: str, account: str, issuer: str = "Pixplace") -> str:
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")

def new_recovery_codes(n: int = 8) -> list:
    out = []
    for _ in range(n):
        raw = base64.b32encode(os.urandom(7)).decode().rstrip("=")[:10].lower()
        out.append(raw[:5] + "-" + raw[5:])
    return out

def hash_recovery(code: str) -> str:
    norm = "".join(ch for ch in str(code or "").lower() if ch.isalnum())
    return hashlib.sha256(("pixplace-rc:" + norm).encode()).hexdigest()
