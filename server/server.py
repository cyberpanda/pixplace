#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CyberPanda (github.com/cyberpanda)

from __future__ import annotations

import sys

PP_VERSION = "1.0.0"

if sys.version_info < (3, 8):
    raise SystemExit(
        "Pixplace requires Python 3.8 or newer.\n"
        f"Found: Python {sys.version.split()[0]}\n"
        "Please install a current Python (e.g. from python.org "
        "or 'brew install python3') and start the server with it."
    )

import argparse
import asyncio
import base64
import collections
import hashlib
import hmac
import ipaddress
import secrets
import urllib.request
import urllib.parse
import json
import random
import os
import re
import ssl
import struct
import time
import uuid

try:
    import twofactor
    import qrgen
    TOTP_AVAILABLE = True
except Exception as _e:
    twofactor = None
    qrgen = None
    TOTP_AVAILABLE = False
    print("Two-factor modules not found:", _e)

class RateLimiter:
    def __init__(self, limit: int, window_s: float):
        self.limit = limit
        self.window = window_s
        self._hits: dict[str, collections.deque] = {}

    def allow(self, key: str, peek: bool = False) -> bool:
        now = time.monotonic()
        dq = self._hits.setdefault(key, collections.deque())
        while dq and dq[0] <= now - self.window:
            dq.popleft()
        if len(dq) >= self.limit:
            return False
        if not peek:
            dq.append(now)
        return True

    def retry_after(self, key: str) -> float:
        dq = self._hits.get(key)
        if not dq:
            return 0.0
        return max(0.0, self.window - (time.monotonic() - dq[0]))

RL_CONNECT = RateLimiter(limit=300, window_s=60)
RL_CHAT = RateLimiter(limit=12, window_s=8)
RL_UPLOAD = RateLimiter(limit=20, window_s=60)
RL_REGISTER = RateLimiter(limit=5, window_s=300)
RL_ADMIN_LOGIN = RateLimiter(limit=8, window_s=300)

RL_ADMIN_TOTAL = RateLimiter(limit=40, window_s=300)
RL_MEMBER_LOGIN = RateLimiter(limit=20, window_s=300)

class FailureTracker:
    def __init__(self, max_delay: float = 8.0, reset_s: float = 900.0):
        self.max_delay = max_delay
        self.reset = reset_s
        self._f: dict[str, list] = {}

    def delay_for(self, key: str) -> float:
        rec = self._f.get(key)
        if not rec:
            return 0.0
        n, ts = rec
        if time.monotonic() - ts > self.reset:
            self._f.pop(key, None)
            return 0.0
        if n < 3:
            return 0.0
        return min(self.max_delay, 0.5 * (2 ** (n - 3)))

    def fail(self, key: str):
        rec = self._f.get(key)
        n = (rec[0] + 1) if rec and time.monotonic() - rec[1] <= self.reset else 1
        self._f[key] = [n, time.monotonic()]

    def ok(self, key: str):
        self._f.pop(key, None)

    def count(self, key: str) -> int:
        rec = self._f.get(key)
        return rec[0] if rec else 0

FAILS = FailureTracker()

GOOD_IPS: dict[str, float] = {}
GOOD_IP_TTL = 14 * 24 * 3600

def ip_is_known_good(ip: str) -> bool:
    ts = GOOD_IPS.get(ip or "")
    if not ts:
        return False
    if time.time() - ts > GOOD_IP_TTL:
        GOOD_IPS.pop(ip, None)
        return False
    return True

def mark_ip_good(ip: str):
    if ip:
        GOOD_IPS[ip] = time.time()
        for k, v in list(GOOD_IPS.items()):
            if time.time() - v > GOOD_IP_TTL:
                GOOD_IPS.pop(k, None)

RL_ROLE_AUTH = RateLimiter(limit=6, window_s=300)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

BASE_DIR = os.environ.get("PIXPLACE_DATA") or os.path.dirname(
    os.path.abspath(__file__))

def dpath(name: str) -> str:
    return os.path.join(BASE_DIR, name)

MEDIA_DIR = dpath("media")
AVATAR_DIR = dpath("avatars")
ROOM_TPL_DIR = dpath("rooms")
LOG_DIR = dpath("logs")
MOD_DIR = dpath("moderation")
CONFIG_FILE = dpath("palace_config.json")
AVATARS_FILE = dpath("palace_avatars.json")
GROUPS_FILE = dpath("palace_groups.json")
MAX_UPLOAD = 3_000_000
MAX_WS_MSG = 64_000
MAX_CHAT_LEN = 500
MAX_PROPS = 12

AVATAR_BOX_MIN = 500
AVATAR_BOX_MAX = 1600
LOG_KEEP = 500
IMG_MAGIC = {b"\x89PNG": "png", b"\xff\xd8\xff": "jpg",
             b"GIF8": "gif", b"RIFF": "webp"}
os.makedirs(MEDIA_DIR, exist_ok=True)
os.makedirs(AVATAR_DIR, exist_ok=True)
os.makedirs(ROOM_TPL_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

START_TIME = time.time()
os.makedirs(MOD_DIR, exist_ok=True)

DEFAULT_NOTICE = (
    "Notice: This chat is logged for moderation and security purposes. "
    "All public messages AND private whispers "
    "are stored server-side with date, time, room and username "
    "and may be viewed by moderators. By clicking \"Agree\" "
    "you confirm that you accept this. Otherwise you can leave the "
    "chat."
)

CONFIG = {

    "owner_pass": "",
    "wizard_pass": "",

    "owner_pass_temp": True,

    "wizard_pass_temp": False,

    "test_mode": False,
    "test_key": "",

    "public_registration": True,

    "demo_mode": False,

    "private_mode": False,

    "admin_hidden": False,
    "admin_path": "admin",

    "admin_mask": "default",

    "trusted_proxies": ["127.0.0.1/32", "::1/128"],

    "smtp": {
        "host": "127.0.0.1", "port": 25,
        "user": "", "password": "",
        "from": "",
        "security": "none",
    },

    "admin_bind_ip": True,
    "hsts_enabled": True,
    "servername": "Pixplace",
    "autoannounce": "",
    "moderation_notice": DEFAULT_NOTICE,

    "moderation_mode": "full",
    "moderation_logging": True,

    "log_retention_days": 7,

    "privacy_mode": False,
    "privacy": {

        "store_ip": True,

        "chat_logs": True,

        "comments": True,

        "presence_public": True,
    },
    "grants": {},
    "permissions": {},
    "_rankscheme": 2,

    "legal": {},
    "oauth": {

        "public_url": "",
        "google": {"client_id": "", "client_secret": ""},
        "apple":  {"client_id": "", "team_id": "", "key_id": "",
                   "private_key": ""},
        "discord": {"client_id": "", "client_secret": ""},
        "github":  {"client_id": "", "client_secret": ""},
    },
}

ACCOUNTS_FILE = dpath("palace_accounts.json")
ACCOUNTS: dict[str, dict] = {}

ADMIN_TOKENS: dict[str, int] = {}
ADMIN_TTL_MS = 8 * 3600 * 1000

def load_config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            data = json.load(f)
        old_scheme = int(data.get("_rankscheme", 1))
        for k, v in data.items():
            CONFIG[k] = v
        CONFIG["grants"] = {str(k).lower(): int(v)
                            for k, v in (CONFIG.get("grants") or {}).items()}

        if old_scheme < 2:
            CONFIG["grants"] = {k: (RANK_OWNER if v == 2 else
                                    RANK_WIZARD if v == 1 else v)
                                for k, v in CONFIG["grants"].items()}
            CONFIG["_rankscheme"] = 2
            save_config()
    except FileNotFoundError:
        first_run_secrets()
        save_config()
    except Exception as e:
        print("Could not load configuration:", e)

    if not CONFIG.get("owner_pass") or not CONFIG.get("wizard_pass"):
        first_run_secrets()
        save_config()
    load_accounts()
    migrate_account_tokens()
    load_invites()
    load_media_index()
    load_reports()
    if ensure_mail_sender():
        save_config()

def gen_passphrase(nbytes: int = 12) -> str:
    alphabet = "abcdefghijkmnpqrstuvwxyz23456789ACDEFGHJKLMNPQRSTUVWXYZ"
    return "".join(secrets.choice(alphabet) for _ in range(nbytes))

NEW_SECRETS = {}

def ensure_mail_sender():
    changed = False
    sm = CONFIG.setdefault("smtp", {})
    sm.setdefault("host", "127.0.0.1")
    sm.setdefault("port", 25)
    sm.setdefault("security", "none")

    if sm.get("host") in ("127.0.0.1", "::1", "localhost") \
            and int(sm.get("port") or 0) == 25 \
            and sm.get("security") == "starttls":
        sm["security"] = "none"
        changed = True
        print("  Mail: security for the local server set to \"none\"")
    sm.setdefault("user", "")
    sm.setdefault("password", "")
    if sm.get("from"):
        return changed
    base = ((CONFIG.get("oauth") or {}).get("public_url") or "")
    host = base.split("//")[-1].split("/")[0].split(":")[0]
    parts = [x for x in host.split(".") if x]

    if len(parts) >= 3 and parts[0] in ("chat", "www", "app"):
        parts = parts[1:]
    if len(parts) < 2:
        return changed
    sm["from"] = (f"{CONFIG.get('servername', 'Pixplace')} "
                  f"<noreply@{'.'.join(parts)}>")
    print(f"  Mail sender set: {sm['from']}")
    return True

def first_run_secrets():
    if not CONFIG.get("owner_pass"):
        CONFIG["owner_pass"] = gen_passphrase()
        CONFIG["owner_pass_temp"] = True
        NEW_SECRETS["owner"] = CONFIG["owner_pass"]

    if not CONFIG.get("test_key"):
        CONFIG["test_key"] = gen_passphrase(18)
        NEW_SECRETS["test_key"] = CONFIG["test_key"]

def _protect(path):
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(CONFIG, f, ensure_ascii=False, indent=2)
        _protect(CONFIG_FILE)
    except Exception as e:
        print("Could not save configuration:", e)

def load_accounts():
    global ACCOUNTS
    try:
        with open(ACCOUNTS_FILE, encoding="utf-8") as f:
            ACCOUNTS = json.load(f)
    except FileNotFoundError:
        ACCOUNTS = {}
    except Exception as e:
        print("Could not load accounts:", e)
        ACCOUNTS = {}

def save_accounts():
    try:

        clean = {k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
                 for k, v in ACCOUNTS.items()}
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(clean, f, ensure_ascii=False, indent=2)
        _protect(ACCOUNTS_FILE)
    except Exception as e:
        print("Could not save accounts:", e)

INVITES_FILE = dpath("palace_invites.json")
INVITES: dict = {}
INVITE_DEFAULT_DAYS = 14

MEDIA_INDEX_FILE = dpath("palace_media.json")
MEDIA_INDEX: dict = {}

def load_media_index():
    global MEDIA_INDEX
    try:
        with open(MEDIA_INDEX_FILE, encoding="utf-8") as f:
            MEDIA_INDEX = json.load(f) or {}
    except FileNotFoundError:
        MEDIA_INDEX = {}
    except Exception as e:
        print("Media directory not readable:", e)
        MEDIA_INDEX = {}

def save_media_index():
    try:
        with open(MEDIA_INDEX_FILE, "w", encoding="utf-8") as f:
            json.dump(MEDIA_INDEX, f, ensure_ascii=False, indent=2)
        _protect(MEDIA_INDEX_FILE)
    except Exception as e:
        print("Media directory not writable:", e)

def note_upload(url: str, size: int, who: str, verified: bool, ip: str,
                kind: str = "image"):
    if not url:
        return
    name = url.rsplit("/", 1)[-1]
    MEDIA_INDEX[name] = {"url": url, "size": int(size or 0),
                         "by": str(who or "?"), "verified": bool(verified),
                         "ip": safe_ip(ip), "ts": now_ms(), "kind": kind}

    if len(MEDIA_INDEX) > 5000:
        for k in sorted(MEDIA_INDEX, key=lambda x: MEDIA_INDEX[x]["ts"])[:500]:
            MEDIA_INDEX.pop(k, None)
    save_media_index()
    mod_log("-", who or "?", "UPLOAD",
            f"{name} · {int(size or 0)//1024} KB · {kind}"
            f"{'' if verified else ' (name unverified)'}")

def load_invites():
    global INVITES
    try:
        with open(INVITES_FILE, encoding="utf-8") as f:
            INVITES = json.load(f) or {}
    except FileNotFoundError:
        INVITES = {}
    except Exception as e:
        print("Could not load invitations:", e)
        INVITES = {}

def save_invites():
    try:
        with open(INVITES_FILE, "w", encoding="utf-8") as f:
            json.dump(INVITES, f, ensure_ascii=False, indent=2)
        _protect(INVITES_FILE)
    except Exception as e:
        print("Could not save invitations:", e)

def new_invite(note: str = "", days: int = INVITE_DEFAULT_DAYS,
               rank: int | None = None) -> dict:
    code = secrets.token_urlsafe(20)

    inv = {"code": code, "note": str(note or "")[:120],
           "rank": int(RANK_MEMBER if rank is None else rank), "created": now_ms(),
           "expires": now_ms() + int(days) * 86400_000,
           "used_by": "", "used_at": 0, "disabled": False}
    INVITES[code] = inv
    save_invites()
    return inv

def invite_state(inv: dict) -> str:
    if inv.get("disabled"):
        return "blocked"
    if inv.get("used_by"):
        return "redeemed"
    if inv.get("expires", 0) < now_ms():
        return "expired"
    return "open"

def invite_usable(code: str) -> dict | None:
    inv = INVITES.get(str(code or ""))
    if not inv:
        return None
    return inv if invite_state(inv) == "open" else None

PW_ITERATIONS = 1_000_000

def hash_password(pw: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", str(pw).encode(), salt, PW_ITERATIONS)
    return "pbkdf2$%d$%s$%s" % (PW_ITERATIONS, salt.hex(), dk.hex())

def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt_hex, dk_hex = str(stored).split("$", 3)
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", str(pw).encode(),
                                 bytes.fromhex(salt_hex), int(it))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

RL_OTP = RateLimiter(limit=10, window_s=300)

DOC_TOKENS: dict = {}
DOC_TTL_MS = 12 * 3600 * 1000

def doc_token_new() -> str:
    tok = secrets.token_urlsafe(24)
    DOC_TOKENS[tok] = now_ms() + DOC_TTL_MS
    for k, exp in list(DOC_TOKENS.items()):
        if exp < now_ms():
            DOC_TOKENS.pop(k, None)
    return tok

def doc_cookie_value() -> str:
    return hmac.new(("pp-doc:" + str(CONFIG.get("test_key", ""))).encode(),
                    b"docs", hashlib.sha256).hexdigest()[:32]

def may_read_docs(target: str, headers) -> tuple:
    q = target.split("?", 1)[1] if "?" in target else ""
    for kv in q.split("&"):
        if kv.startswith("k="):
            tok = urllib.parse.unquote(kv[2:])
            exp = DOC_TOKENS.get(tok)
            if exp and exp > now_ms():
                return True, True
    raw = headers.get("cookie", "") or ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "pp_doc" and hmac.compare_digest(v, doc_cookie_value()):
            return True, False
    return False, False

def totp_on(acc: dict) -> bool:
    return bool(TOTP_AVAILABLE and acc and acc.get("totp_enabled")
                and acc.get("totp_secret"))

def totp_check(acc: dict, code: str) -> bool:
    if not acc:
        return False
    code = str(code or "").strip()
    if not code:
        return False

    ok, ctr = twofactor.verify(acc.get("totp_secret", ""), code,
                               last_counter=acc.get("totp_last"))
    if ok:
        acc["totp_last"] = ctr
        save_accounts()
        return True

    h = twofactor.hash_recovery(code)
    left = list(acc.get("totp_recovery") or [])
    for i, stored in enumerate(left):
        if hmac.compare_digest(str(stored), h):
            left.pop(i)
            acc["totp_recovery"] = left
            save_accounts()
            mod_log("-", acc.get("username", "?"), "2FA-RECOVERY",
                    f"Recovery code used, {len(left)} left")
            return True
    return False

def mail_ready() -> bool:
    c = CONFIG.get("smtp") or {}
    return bool(c.get("host") and c.get("from"))

def _send_mail_blocking(to: str, subject: str, body: str) -> None:
    import smtplib
    from email.message import EmailMessage
    c = CONFIG.get("smtp") or {}
    msg = EmailMessage()
    msg["From"] = c.get("from")
    msg["To"] = to
    msg["Subject"] = subject
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body)
    host, port = c.get("host"), int(c.get("port") or 587)
    sec = (c.get("security") or "starttls").lower()
    local = str(host) in ("127.0.0.1", "::1", "localhost")
    if sec == "ssl":
        srv = smtplib.SMTP_SSL(host, port, timeout=20)
    else:
        srv = smtplib.SMTP(host, port, timeout=20)
    try:
        srv.ehlo()
        if sec == "starttls":

            if srv.has_extn("starttls"):
                srv.starttls()
                srv.ehlo()
            elif not local:
                raise RuntimeError(
                    "Server does not offer STARTTLS – please set security "
                    "to \"none\" or \"SSL/TLS\".")

        if c.get("user") and not local:
            srv.login(c["user"], c.get("password") or "")
        srv.send_message(msg)
    finally:
        try:
            srv.quit()
        except Exception:
            pass

async def hash_password_async(pw: str) -> str:
    return await asyncio.get_running_loop().run_in_executor(
        None, hash_password, pw)

async def verify_password_async(pw: str, stored: str) -> bool:
    return await asyncio.get_running_loop().run_in_executor(
        None, verify_password, pw, stored)

async def send_mail(to: str, subject: str, body: str) -> bool:
    if not (mail_ready() and to):
        return False
    try:
        await asyncio.get_running_loop().run_in_executor(
            None, _send_mail_blocking, to, subject, body)
        return True
    except Exception as e:
        print("Mailversand fehlgeschlagen:", e)
        mod_log("-", "-", "MAIL-FAIL", f"an {mask_mail(to)}: {e}")
        return False

def mask_mail(a: str) -> str:
    a = str(a or "")
    if "@" not in a:
        return "-"
    n, d = a.split("@", 1)
    return (n[:1] + "***@" + d) if n else "***@" + d

def valid_mail(a: str) -> bool:
    a = str(a or "").strip()
    if not (3 <= len(a) <= 254) or a.count("@") != 1:
        return False
    n, d = a.split("@")
    return bool(n and "." in d and " " not in a and ".." not in a)

def account_by_login(login: str) -> dict | None:
    v = str(login or "").strip().lower()
    if not v:
        return None
    acc = ACCOUNTS.get(v)
    if acc:
        return acc
    if "@" in v:
        for a in ACCOUNTS.values():
            if str(a.get("email", "")).strip().lower() == v:
                return a
    return None

RESET_TOKENS: dict = {}
RESET_TTL_MS = 60 * 60 * 1000
RL_FORGOT = RateLimiter(limit=5, window_s=900)

def reset_token_new(username: str) -> str:
    tok = secrets.token_urlsafe(32)
    RESET_TOKENS[tok] = {"user": username, "exp": now_ms() + RESET_TTL_MS}
    for k, v in list(RESET_TOKENS.items()):
        if v["exp"] < now_ms():
            RESET_TOKENS.pop(k, None)
    return tok

def reset_token_use(tok: str) -> dict | None:
    rec = RESET_TOKENS.get(str(tok or ""))
    if not rec or rec["exp"] < now_ms():
        RESET_TOKENS.pop(str(tok or ""), None)
        return None
    RESET_TOKENS.pop(tok, None)
    return ACCOUNTS.get(str(rec["user"]).lower())

def public_url() -> str:
    return ((CONFIG.get("oauth") or {}).get("public_url") or "").rstrip("/")

REPORTS_FILE = dpath("palace_reports.json")
GDPR_LOG = dpath("palace_gdpr.log")
REPORTS: dict = {}

def load_reports():
    global REPORTS
    try:
        with open(REPORTS_FILE, encoding="utf-8") as f:
            REPORTS = json.load(f) or {}
    except Exception:
        REPORTS = {}

def save_reports():
    try:
        with open(REPORTS_FILE, "w", encoding="utf-8") as f:
            json.dump(REPORTS, f, ensure_ascii=False, indent=2)
        _protect(REPORTS_FILE)
    except Exception as e:
        print("Could not save reports:", e)

def gdpr_log(action: str, subject: str, actor: str, detail: str = ""):
    line = "%s | %s | %s | %s | %s\n" % (
        time.strftime("%Y-%m-%d %H:%M:%S"),
        str(action)[:40], str(subject)[:60], str(actor)[:60],
        re.sub(r"[\x00-\x1f]", " ", str(detail))[:400])
    try:
        with open(GDPR_LOG, "a", encoding="utf-8") as f:
            f.write(line)
        _protect(GDPR_LOG)
    except Exception as e:
        print("Legal log not writable:", e)
    mod_log("-", actor or "-", "GDPR-" + str(action).upper(),
            f"{subject}: {detail}"[:200])

def export_subject(name: str) -> dict:
    key = str(name or "").strip().lower()
    acc = account_by_login(name)
    uname = (acc or {}).get("username") or str(name or "")
    out = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "subject": uname,
        "note": "Access report under Art. 15 GDPR. Contains all data stored "
                   "about this person by this service.",
        "account": None, "media": [], "messages": [],
        "moderation": [], "groups": [], "reports": [],
    }
    if acc:
        a = dict(acc)
        for k in ("pw_hash", "token_hash", "token_hashes", "totp_secret",
                  "totp_pending", "totp_recovery", "_plain_token"):
            a.pop(k, None)
        a["_note"] = ("Password and access keys are stored only as "
                         "irreversible hashes.")
        out["account"] = a
    for fn, rec in MEDIA_INDEX.items():
        if str(rec.get("by", "")).lower().endswith(key) or \
                str(rec.get("by", "")).lower() == key:
            out["media"].append(rec)
    try:
        for f in sorted(os.listdir(LOG_DIR)):
            if not f.endswith(".jsonl"):
                continue
            with open(os.path.join(LOG_DIR, f), encoding="utf-8") as fh:
                for ln in fh:
                    try:
                        e = json.loads(ln)
                    except Exception:
                        continue
                    if str(e.get("name", "")).lower().lstrip("*") == key:
                        out["messages"].append(e)
    except Exception:
        pass
    try:
        for f in sorted(os.listdir(MOD_DIR)):
            with open(os.path.join(MOD_DIR, f), encoding="utf-8") as fh:
                for ln in fh:
                    if key and key in ln.lower():
                        out["moderation"].append(ln.rstrip("\n"))
    except Exception:
        pass
    for g in GROUPS.values():
        if key in [str(m).lower() for m in (g.get("members") or [])]:
            out["groups"].append({"name": g.get("name"),
                                   "role": ("Founder"
                                             if str(g.get("owner", "")).lower() == key
                                             else "Member")})
    for r in REPORTS.values():
        if str(r.get("target", "")).lower() == key or \
                str(r.get("by", "")).lower() == key:
            out["reports"].append(r)
    return out

def erase_subject(name: str, keep_media: bool = False) -> dict:
    key = str(name or "").strip().lower()
    res = {"account": False, "media": 0, "messages": 0,
           "moderation": 0, "groups": 0}
    acc = ACCOUNTS.pop(key, None)
    if acc:
        res["account"] = True
        save_accounts()
    if not keep_media:
        for fn in list(MEDIA_INDEX):
            rec = MEDIA_INDEX[fn]
            if str(rec.get("by", "")).lower() == key or \
                    str(rec.get("by", "")).lower().endswith(key):
                try:
                    os.remove(os.path.join(MEDIA_DIR, fn))
                except Exception:
                    pass
                MEDIA_INDEX.pop(fn, None)
                res["media"] += 1
        save_media_index()
    try:
        for f in sorted(os.listdir(LOG_DIR)):
            if not f.endswith(".jsonl"):
                continue
            path = os.path.join(LOG_DIR, f)
            keep = []
            for ln in open(path, encoding="utf-8"):
                try:
                    e = json.loads(ln)
                except Exception:
                    keep.append(ln)
                    continue
                if str(e.get("name", "")).lower().lstrip("*") == key:
                    res["messages"] += 1
                else:
                    keep.append(ln)
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(keep)
    except Exception:
        pass
    try:
        for f in sorted(os.listdir(MOD_DIR)):
            path = os.path.join(MOD_DIR, f)
            keep = []
            for ln in open(path, encoding="utf-8"):
                if key and key in ln.lower():
                    res["moderation"] += 1
                else:
                    keep.append(ln)
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(keep)
    except Exception:
        pass
    for g in GROUPS.values():
        ms = [m for m in (g.get("members") or [])
              if str(m).lower() != key]
        if len(ms) != len(g.get("members") or []):
            g["members"] = ms
            res["groups"] += 1
    if res["groups"]:
        save_groups()
    for fn in list(INVITES):
        if str(INVITES[fn].get("used_by", "")).lower() == key:
            INVITES[fn]["used_by"] = "[deleted]"
    save_invites()
    return res

def token_hash(token: str) -> str:
    return hashlib.sha256(("pp-tok:" + str(token or "")).encode()).hexdigest()

MAX_DEVICES = 4

def acc_tokens(acc: dict) -> list:
    v = acc.get("token_hashes")
    if isinstance(v, list):
        return v
    v = []
    if acc.get("token_hash"):
        v = [{"h": acc["token_hash"], "ts": int(acc.get("created") or 0)}]
    acc["token_hashes"] = v
    return v

def acc_add_token(acc: dict, tok: str) -> None:
    lst = acc_tokens(acc)
    lst.append({"h": token_hash(tok), "ts": now_ms()})
    del lst[:-MAX_DEVICES]
    acc["token_hashes"] = lst
    acc.pop("token_hash", None)
    save_accounts()

def acc_clear_tokens(acc: dict) -> None:
    acc["token_hashes"] = []
    acc.pop("token_hash", None)

def account_by_token(token: str) -> dict | None:
    if not token:
        return None
    want = token_hash(token)
    for acc in ACCOUNTS.values():
        for e in acc_tokens(acc):
            if hmac.compare_digest(str(e.get("h") or ""), want):
                e["ts"] = now_ms()
                return acc
    return None

def migrate_account_tokens():
    changed = False
    for acc in ACCOUNTS.values():
        if acc.get("token_hash") and not acc.get("token_hashes"):
            acc_tokens(acc)
            changed = True
        if acc.get("token") and not acc.get("token_hash"):
            acc["token_hash"] = token_hash(acc["token"])
            acc.pop("token", None)
            changed = True
        elif acc.get("token"):
            acc.pop("token", None)
            changed = True
    if changed:
        save_accounts()
        print("  Access keys migrated to hashes.")

def effective_rank(base: str, account: dict | None) -> int:
    r = account.get("rank", RANK_MEMBER) if account else RANK_USER
    g = CONFIG["grants"].get(base.lower())
    if g is not None:
        r = max(r, int(g))
    return r

def now_ms() -> int:
    return int(time.time() * 1000)

def purge_old_logs() -> int:
    try:
        days = int(CONFIG.get("log_retention_days") or 0)
    except Exception:
        days = 0
    if days <= 0:
        return 0
    cutoff = time.time() - days * 86400
    removed = 0
    try:
        for fn in os.listdir(MOD_DIR):
            if not fn.endswith(".txt"):
                continue
            p = os.path.join(MOD_DIR, fn)
            try:
                if os.path.getmtime(p) < cutoff:
                    os.remove(p)
                    removed += 1
            except Exception:
                continue
    except Exception:
        pass
    return removed

def mod_parse(line: str, day: str) -> dict | None:
    line = line.rstrip("\n")
    if not line:
        return None
    p = [x.strip() for x in line.split(" | ", 3)]
    if len(p) < 4:
        return None
    stamp, room, kind, rest = p
    user, _, text = rest.partition(": ")
    return {"date": day, "time": stamp[11:19] or stamp,
            "room": room, "kind": kind,
            "user": user.strip(), "text": text.strip()}

def privacy_off(key: str) -> bool:
    if CONFIG.get("privacy_mode"):
        return True

    if CONFIG.get("demo_mode") and key in ("store_ip", "chat_logs"):
        return True

    if CONFIG.get("private_mode") and key in ("comments", "presence_public"):
        return True
    p = CONFIG.get("privacy") or {}
    return not p.get(key, True)

def safe_ip(ip) -> str:
    if privacy_off("store_ip"):
        return "-"
    return str(ip or "?")

def mod_log(room_name: str, username: str, kind: str, text: str):
    mode = CONFIG.get("moderation_mode") or (
        "full" if CONFIG.get("moderation_logging") else "off")
    if mode == "off":
        return
    if mode == "events" and str(kind).upper() in (
            "CHAT", "WHISPER", "GROUPCHAT", "RMSG"):

        return
    t = time.localtime()
    day = time.strftime("%Y-%m-%d", t)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", t)

    def _1line(v, maxlen=2000):
        v = str(v if v is not None else "")
        v = "".join(" " if (ord(c) < 32 or ord(c) == 127) else c for c in v)
        return v[:maxlen]

    line = (f"{stamp} | {_1line(room_name or '-', 80)} | {_1line(kind, 40)}"
            f" | {_1line(username, 80)}: {_1line(text)}\n")
    try:
        with open(os.path.join(MOD_DIR, f"{day}.txt"), "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass

def detect_image(data: bytes) -> str | None:
    for magic, ext in IMG_MAGIC.items():
        if data.startswith(magic):
            return ext
    return None

def save_upload(data: bytes) -> str | None:
    ext = detect_image(data)
    if not ext or len(data) > MAX_UPLOAD:
        return None
    name = hashlib.sha256(data).hexdigest()[:20] + "." + ext
    path = os.path.join(MEDIA_DIR, name)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(data)
    return "/media/" + name

AVATARS: dict[str, dict] = {}

def load_avatars():
    global AVATARS
    try:
        with open(AVATARS_FILE, encoding="utf-8") as f:
            AVATARS = json.load(f)
    except FileNotFoundError:
        AVATARS = {}
    except Exception as e:
        print("Could not load avatar DB:", e)
        AVATARS = {}

def save_avatars():
    try:
        with open(AVATARS_FILE, "w", encoding="utf-8") as f:
            json.dump(AVATARS, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("Could not save avatar DB:", e)

def save_avatar(data: bytes, owner: str) -> str | None:
    ext = detect_image(data)
    if not ext or len(data) > MAX_UPLOAD:
        return None
    av_id = uuid.uuid4().hex
    fname = av_id + "." + ext
    try:
        with open(os.path.join(AVATAR_DIR, fname), "wb") as f:
            f.write(data)
    except Exception:
        return None
    AVATARS[av_id] = {"owner": owner or "guest", "ext": ext,
                      "file": fname, "created": now_ms()}
    save_avatars()
    return "/avatar/" + av_id

def avatar_file(av_id: str) -> str | None:
    rec = AVATARS.get(av_id)
    if not rec:
        return None
    p = os.path.join(AVATAR_DIR, rec.get("file", av_id + "." + rec.get("ext", "png")))
    return p if os.path.isfile(p) else None

GROUPS: dict[str, dict] = {}

def load_groups():
    global GROUPS
    try:
        with open(GROUPS_FILE, encoding="utf-8") as f:
            GROUPS = json.load(f)
    except FileNotFoundError:
        GROUPS = {}
    except Exception as e:
        print("Could not load groups:", e)
        GROUPS = {}

def save_groups():
    try:
        with open(GROUPS_FILE, "w", encoding="utf-8") as f:
            json.dump(GROUPS, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("Could not save groups:", e)

def group_of(base: str) -> dict | None:
    key = (base or "").lower()
    for g in GROUPS.values():
        if key in [m.lower() for m in g.get("members", [])]:
            return g
    return None

CLAN_RANKS = ["Recruit", "Member", "Veteran", "Officer", "Deputy", "Founder"]
CLAN_LEVEL = {r: i for i, r in enumerate(CLAN_RANKS)}

ASSIGNABLE_RANKS = ["Recruit", "Member", "Veteran", "Officer", "Deputy"]
GROUP_KINDS = ["Clan", "Guild", "Crew", "Club"]

GROUP_POLICIES = ["open", "request", "invite"]

CLAN_PERMS = {
    "invite":    "Invite members",
    "approve":   "Accept/decline requests",
    "kick":      "Remove members",
    "ranks":     "Assign ranks",
    "blurb":     "Edit promo text",
    "roomedit":  "Design the hall (background, drawing) – no doors/script",
    "announce":  "Announce to all members",
    "chat":      "Write in the guild chat",
    "perks":     "Spend treasury points on perks",
}

CLAN_DEFAULT_PERMS = {
    0: ["chat"],
    1: ["chat"],
    2: ["chat", "invite"],
    3: ["chat", "invite", "approve"],
    4: ["chat", "invite", "approve", "kick", "ranks", "blurb", "roomedit",
        "perks"],
    5: list(CLAN_PERMS.keys()),
}

def rank_names(g: dict) -> list:
    custom = (g or {}).get("rankNames") or {}
    out = []
    for i, std in enumerate(CLAN_RANKS):
        nm = str(custom.get(str(i), "") or "").strip()
        out.append(nm[:20] or std)
    return out

def rank_label(g: dict, base: str) -> str:
    return rank_names(g)[clan_level(g, base)]

def perms_of(g: dict, level: int) -> list:
    cfg = (g or {}).get("perms") or {}
    val = cfg.get(str(level))
    out = ([p for p in val if p in CLAN_PERMS] if isinstance(val, list)
           else list(CLAN_DEFAULT_PERMS.get(level, [])))
    if "chat" not in out:
        out.insert(0, "chat")
    return out

def has_perm(g: dict, base: str, perm: str) -> bool:
    if not g:
        return False
    if (g.get("owner") or "").lower() == (base or "").lower():
        return True
    return perm in perms_of(g, clan_level(g, base))

def clan_level(g: dict, base: str) -> int:
    return CLAN_LEVEL.get(clan_rank_of(g, base), 0)

def may_manage(g: dict, base: str, need: str = "Officer") -> bool:
    if not g:
        return False
    if need == "Deputy":
        return has_perm(g, base, "kick") or has_perm(g, base, "ranks") \
            or clan_level(g, base) >= CLAN_LEVEL["Deputy"]
    return has_perm(g, base, "approve") or has_perm(g, base, "invite") \
        or clan_level(g, base) >= CLAN_LEVEL.get(need, 3)

def group_kind(g: dict) -> str:
    k = (g or {}).get("kind") or "Clan"
    return k if k in GROUP_KINDS else "Clan"

def group_policy(g: dict) -> str:
    p = (g or {}).get("policy") or "open"
    return p if p in GROUP_POLICIES else "open"

def clan_rank_of(g: dict, base: str) -> str:
    if not g:
        return ""
    if (g.get("owner") or "").lower() == (base or "").lower():
        return "Founder"
    return (g.get("ranks") or {}).get((base or "").lower(), "Member")

def clan_points(g: dict, base: str) -> int:
    return int((g.get("points") or {}).get((base or "").lower(), 0))

def group_public(g: dict | None, base: str = "") -> dict | None:
    if not g:
        return None
    return {"name": g["name"], "logo": g.get("logo"),
            "tag": g.get("tag") or g["name"][:4],
            "room": g.get("room"),
            "rank": clan_rank_of(g, base) if base else "",
            "points": clan_points(g, base) if base else 0,
            "blurb": g.get("blurb", ""),
            "kind": group_kind(g),
            "level": clan_level(g, base) if base else 0,
            "rankLabel": rank_label(g, base) if base else "",
            "rankNames": rank_names(g),
            "perms": perms_of(g, clan_level(g, base)) if base else [],
            "permsAll": {str(i): perms_of(g, i) for i in range(len(CLAN_RANKS))},
            "permCatalog": CLAN_PERMS,
            "tier": clan_tier(clan_renown(g)["total"])[0][1],
            "tierIndex": clan_tier_index(g),
            "renown": clan_renown(g)["total"],
            "renownParts": clan_renown(g)["parts"],
            "bank": int(g.get("bank", 0)),
            "slots": group_slots(g),
            "perks": perk_list(g, "group"),
            "policy": group_policy(g),
            "total": int(g.get("total", 0)),
            "pending": len(g.get("requests", []) or []),
            "canManage": may_manage(g, base) if base else False,
            "canInvite": has_perm(g, base, "invite") if base else False,
            "roomPublic": bool(g.get("roomPublic")),
            "isFounder": (g.get("owner") or "").lower() == (base or "").lower(),
            "members": len(g.get("members", []))}

CLAN_REWARDS = [
    (0,     "Founded"),
    (150,   "Known"),
    (600,   "Established"),
    (1800,  "Respected"),
    (4500,  "Famous"),
    (10000, "Legendary"),
]

def clan_renown(g: dict) -> dict:
    if not g:
        return {"total": 0, "parts": {}}
    minutes = sum(int(v) for v in (g.get("minutes") or {}).values())
    members = len(g.get("members", []))
    invested = int(g.get("spent", 0))
    donated = int(g.get("donated", 0))
    parts = {
        "Online time": minutes,
        "Members": members * 120,
        "Invested": invested * 2,
        "Donated": donated // 2,
    }
    return {"total": sum(parts.values()), "parts": parts}

def clan_tier_index(g: dict) -> int:
    r = clan_renown(g)["total"]
    idx = 0
    for i, (need, _n) in enumerate(CLAN_REWARDS):
        if r >= need:
            idx = i
    return idx

PERK_DAYS = 30
GROUP_SLOTS_BASE = 5
GROUP_SLOTS_STEP = 5

PERKS = {

    "goldframe":  {"scope": "group", "cost": 300, "icon": "🥇", "days": 30,
                   "tier": 4,
                   "name": "Golden Frame",
                   "desc": "The group's logo and name appear in gold."},
    "onlinecall": {"scope": "group", "cost": 120, "icon": "📣", "days": 7,
                   "tier": 3,
                   "name": "Online announcement",
                   "desc": "Members are announced when they log in."},
    "publichall": {"scope": "group", "cost": 150, "icon": "🏛", "days": 30,
                   "tier": 2,
                   "name": "Open Hall",
                   "desc": "The hall may be made public."},
    "bigblurb":   {"scope": "group", "cost": 80,  "icon": "📝", "days": 7,
                   "tier": 1,
                   "name": "Large promo text",
                   "desc": "Promo text up to 600 instead of 280 characters."},
    "extraslots": {"scope": "group", "cost": 200, "icon": "👥", "tier": 0,
                   "stack": True, "days": 0,
                   "name": "More slots",
                   "desc": f"+{GROUP_SLOTS_STEP} slots permanently."},
    "banner":     {"scope": "group", "cost": 250, "icon": "🖼", "days": 30,
                   "tier": 5,
                   "name": "Hall Banner",
                   "desc": "Custom image in the header of the group overview."},

    "namecolor":  {"scope": "user", "cost": 80, "icon": "✨", "days": 7,
                   "tier": 0,
                   "name": "Glowing Name",
                   "desc": "Your name glows brightly and pulses."},
}

def perk_days(key: str) -> int:
    p = PERKS.get(key) or {}
    return int(p.get("days", PERK_DAYS))

def group_slots(g: dict) -> int:
    steps = int((g or {}).get("slotSteps", 0))
    return GROUP_SLOTS_BASE + steps * GROUP_SLOTS_STEP

def perk_tier_ok(g: dict, key: str) -> bool:
    need = int((PERKS.get(key) or {}).get("tier", 0))
    if need <= 0:
        return True
    return clan_tier_index(g) >= need

def perks_store(owner: dict) -> dict:
    return owner.setdefault("perks", {})

def perk_active(owner: dict, key: str) -> bool:
    if not owner:
        return False
    until = (owner.get("perks") or {}).get(key, 0)
    return bool(until) and until > now_ms()

def perk_list(owner: dict, scope: str | None = None) -> list:
    out = []
    store = (owner or {}).get("perks") or {}
    for key, p in PERKS.items():
        if scope and p["scope"] != scope:
            continue
        stack = bool(p.get("stack"))
        if stack:
            steps = int((owner or {}).get("slotSteps", 0))
            out.append({"key": key, "scope": p["scope"], "cost": p["cost"],
                        "icon": p["icon"], "name": p["name"], "desc": p["desc"],
                        "stack": True, "days": 0, "tier": 0, "locked": False,
                        "active": steps > 0, "steps": steps,
                        "slots": group_slots(owner or {}),
                        "maxed": False, "daysLeft": 0})
            continue
        until = store.get(key, 0)
        left = max(0, (until - now_ms()) / 86400000.0) if until else 0
        need = int(p.get("tier", 0))
        out.append({"key": key, "scope": p["scope"], "cost": p["cost"],
                    "icon": p["icon"], "name": p["name"], "desc": p["desc"],
                    "days": perk_days(key), "stack": False,
                    "tier": need,
                    "tierName": CLAN_REWARDS[need][1] if need else "",
                    "locked": (p["scope"] == "group" and need > 0
                               and not perk_tier_ok(owner, key)),
                    "active": bool(until and until > now_ms()),
                    "daysLeft": round(left, 1)})
    return out

def user_points(user) -> int:
    if user.account:
        return int(user.account.get("points", 0))
    return int(getattr(user, "session_points", 0))

def set_user_points(user, val: int):
    val = max(0, int(val))
    if user.account:
        user.account["points"] = val
        ACCOUNTS[user.account["username"].lower()]["points"] = val
        save_accounts()
    else:
        user.session_points = val

def clan_tier(total: int):
    cur, nxt = CLAN_REWARDS[0], None
    for i, row in enumerate(CLAN_REWARDS):
        if total >= row[0]:
            cur = row
            nxt = CLAN_REWARDS[i + 1] if i + 1 < len(CLAN_REWARDS) else None
    return cur, nxt

LOCK_DOOR_POS = [[14, 14], [58, 14], [58, 58], [14, 58]]

def ensure_lock_door(room) -> dict:
    for d in room.doors.values():
        if (d.get("action") or "") == "lock":
            return d
    did = uuid.uuid4().hex[:8]
    d = {"id": did, "action": "lock", "label": "", "target": "",
         "points": [list(p) for p in LOCK_DOOR_POS],
         "fill": "#2f3648", "text": "#ffffff", "opacity": 0.0}
    room.doors[did] = d
    return d

def may_lock_room(user, room) -> bool:
    if not room:
        return False
    if user.rank >= RANK_WIZARD or room.owner == user.id:
        return True
    g = group_by_room(room.name)
    return bool(g) and has_perm(g, user.base, "roomedit")

def clan_room_name(name: str) -> str:
    return f"{name} Hall"

def is_member(g: dict, base: str) -> bool:
    if not g:
        return False
    return (base or "").lower() in [m.lower() for m in g.get("members", [])]

def group_by_name(name: str) -> dict | None:
    if not name:
        return None
    return GROUPS.get(name) or next(
        (x for x in GROUPS.values() if x["name"].lower() == name.lower()), None)

def group_by_room(room_name: str) -> dict | None:
    for g in GROUPS.values():
        if (g.get("room") or "").lower() == (room_name or "").lower():
            return g
    return None

def clan_stats(g: dict) -> dict:
    if not g:
        return {}
    members = g.get("members", [])
    low = [m.lower() for m in members]
    online = sum(1 for u in all_users() if u.base.lower() in low)
    pts = g.get("points") or {}
    mins = g.get("minutes") or {}
    seen = g.get("lastseen") or {}
    on_now = {u.base.lower() for u in all_users()}
    rows = []
    for m in members:
        k = m.lower()
        rows.append({"name": m,
                     "rank": clan_rank_of(g, m),
                     "level": CLAN_LEVEL.get(clan_rank_of(g, m), 0),
                     "points": int(pts.get(k, 0)),
                     "minutes": int(mins.get(k, 0)),
                     "online": k in on_now,
                     "lastseen": int(seen.get(k, 0) or 0)})

    rows.sort(key=lambda r: (-r["level"], -r["minutes"], r["name"].lower()))
    top = sorted(rows, key=lambda r: -r["minutes"])[:5]
    return {"name": g["name"], "kind": group_kind(g),
            "members": len(members), "online": online,
            "total": int(g.get("total", 0)),
            "renown": clan_renown(g)["total"],
            "bank": int(g.get("bank", 0)),
            "slots": group_slots(g),
            "minutes": sum(int(mins.get(m.lower(), 0)) for m in members),
            "pending": len(g.get("requests", []) or []),
            "room": g.get("room") or "",
            "roomPublic": bool(g.get("roomPublic")),
            "policy": group_policy(g),
            "ranks": CLAN_RANKS,
            "rows": rows,
            "top": [{"name": r["name"], "points": r["points"],
                     "minutes": r["minutes"]} for r in top]}

def ensure_clan_room(g: dict, founder_id=None):
    rn = g.get("room") or clan_room_name(g["name"])
    g["room"] = rn
    if rn not in ROOMS:
        r = Room(rn, persistent=True, owner=founder_id)
        r.set_script(f'ON ENTER {{ "Welcome to the hall of {g["name"]}." SAY }}')
        ROOMS[rn] = r
        save_rooms()
    room = ROOMS[rn]

    old = [d["id"] for d in room.doors.values()
           if (d.get("action") or "") == "clanstats"]
    for did in old:
        room.doors.pop(did, None)

    ensure_lock_door(room)
    if old:
        save_rooms()
    return room

def add_clan_points(base: str, pts: int, minutes: int = 0):
    g = group_of(base)
    if not g or pts <= 0:
        return
    p = g.setdefault("points", {})
    k = (base or "").lower()
    p[k] = int(p.get(k, 0)) + int(pts)
    if minutes > 0:
        mins = g.setdefault("minutes", {})
        mins[k] = int(mins.get(k, 0)) + int(minutes)
    g["total"] = int(g.get("total", 0)) + int(pts)
    g["lastseen"] = g.setdefault("lastseen", {})
    g["lastseen"][k] = now_ms()
    save_groups()

CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css",
                 ".js": "text/javascript", ".png": "image/png",
                 ".jpg": "image/jpeg", ".gif": "image/gif",
                 ".webp": "image/webp"}

class ConnectionClosed(Exception):
    pass

async def read_headers(reader) -> tuple[str, dict, bytes]:
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
    text = raw.decode("latin1")
    lines = text.split("\r\n")
    start = lines[0]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return start, headers, b""

async def http_respond(writer, status, body=b"", ctype="text/plain",
                       extra=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    head = [f"HTTP/1.1 {status}",
            f"Content-Type: {ctype}",
            f"Content-Length: {len(body)}",
            "Connection: close"]
    ex = dict(extra or {})

    head.append("X-Content-Type-Options: nosniff")
    head.append("Referrer-Policy: strict-origin-when-cross-origin")
    head.append("X-Frame-Options: DENY")
    head.append("Permissions-Policy: geolocation=(), microphone=(), "
                "payment=(), usb=(), interest-cohort=()")
    if ctype.startswith("text/html"):

        head.append(
            "Content-Security-Policy: default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "media-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self' data:; "
            "frame-src https://www.youtube-nocookie.com https://www.youtube.com; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'none'")
    if CONFIG.get("hsts_enabled", True):
        head.append("Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains")

    if ex.pop("_cors", False):
        head.append("Access-Control-Allow-Origin: *")
    for k, v in ex.items():
        head.append(f"{k}: {v}")
    writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + body)
    await writer.drain()
    writer.close()

async def handle_http(reader, writer, start, headers, client_ip="?"):
    try:
        method, target, _ = start.split(" ", 2)
    except ValueError:
        return await http_respond(writer, "400 Bad Request", "bad request")

    _path = target.split("?")[0]
    if CONFIG.get("test_mode") and method in ("GET", "HEAD", "POST"):
        key = str(CONFIG.get("test_key") or "")

        if key and _path == "/preview/" + key:
            return await http_respond(
                writer, "302 Found", b"", "text/plain; charset=utf-8",
                extra={"Location": "/",
                       "Set-Cookie": (f"pp_preview={test_cookie_value()}; "
                                      "Path=/; Max-Age=2592000; HttpOnly; "
                                      "SameSite=Lax")})
        if _path == "/preview/logout":
            return await http_respond(
                writer, "302 Found", b"", "text/plain; charset=utf-8",
                extra={"Location": "/",
                       "Set-Cookie": "pp_preview=; Path=/; Max-Age=0"})

        allowed = (is_admin_path(_path)
                   or _path.startswith("/join/")
                   or _path in ("/api/invite/check", "/api/invite/redeem",
                                "/manual", "/wiki", "/admin-wiki",
                                "/api/doc-pass", "/viewtest", "/viewtest.css",
                                "/viewtest.js", "/viewapple", "/viewapple.css",
                                "/viewapple.js"))
        if not allowed and not has_test_pass(headers):
            return await http_respond(writer, "503 Service Unavailable",
                                      maintenance_page(),
                                      "text/html; charset=utf-8",
                                      extra={"Retry-After": "3600"})

    if CONFIG.get("private_mode") and method in ("GET", "HEAD"):

        hidden = ("/imprint", "/privacy",
                  "/terms", "/status",
                  "/api/status", "/api/online", "/api/comments")
        if _path in hidden:
            return await http_respond(writer, "404 Not Found", "not found")

        if _path in ("/", "/index.html"):
            return await http_respond(writer, "200 OK", private_landing(),
                                      "text/html; charset=utf-8")

    if method == "OPTIONS":
        return await http_respond(writer, "204 No Content", "", extra={
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"})

    if method == "POST" and target == "/upload":
        if not RL_UPLOAD.allow(client_ip):
            return await http_respond(writer, "429 Too Many Requests",
                '{"error":"Too many uploads. Please wait a moment."}', "application/json")
        length = int(headers.get("content-length", "0") or "0")
        if length <= 0 or length > MAX_UPLOAD + 1000:
            return await http_respond(writer, "413 Payload Too Large",
                                      '{"error":"too large"}',
                                      "application/json")
        body = await asyncio.wait_for(reader.readexactly(length), 30)
        ctype = headers.get("content-type", "")
        if ctype.startswith("application/json") or body[:1] == b"{":
            try:
                payload = json.loads(body)
                data = base64.b64decode(payload["data"].split(",")[-1])
            except Exception:
                return await http_respond(writer, "400 Bad Request",
                                          '{"error":"bad json"}',
                                          "application/json")
        else:
            data = body
        url = save_upload(data)

        _who, _verified = "Guest", False
        try:
            _pl = payload if isinstance(locals().get("payload"), dict) else {}
        except Exception:
            _pl = {}
        _acc = account_by_token(str(_pl.get("token") or ""))
        if _acc:
            _who, _verified = _acc.get("username", "?"), True
        elif _pl.get("name"):
            _who = "Guest: " + clean_base_name(str(_pl.get("name")))[:24]
        note_upload(url, len(data), _who, _verified, client_ip,
                    str(_pl.get("kind") or "image"))
        if not url:
            return await http_respond(writer, "415 Unsupported Media Type",
                                      '{"error":"not an image"}',
                                      "application/json")
        return await http_respond(writer, "200 OK",
                                  json.dumps({"url": url}), "application/json")

    if method == "GET" and target.startswith("/media/"):
        fname = os.path.basename(target[len("/media/"):].split("?")[0])
        path = os.path.join(MEDIA_DIR, fname)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = f.read()
            ext = os.path.splitext(fname)[1]
            return await http_respond(writer, "200 OK", data,
                                      CONTENT_TYPES.get(ext, "application/octet-stream"),
                                      extra={"Cache-Control": "public, max-age=31536000",
                                             "Content-Disposition": "inline",
                                             "_cors": True})
        return await http_respond(writer, "404 Not Found", "not found")

    if method == "POST" and target == "/avatar":
        if not RL_UPLOAD.allow(client_ip):
            return await http_respond(writer, "429 Too Many Requests",
                '{"error":"Too many uploads. Please wait a moment."}', "application/json")
        length = int(headers.get("content-length", "0") or "0")
        if length <= 0 or length > MAX_UPLOAD + 1000:
            return await http_respond(writer, "413 Payload Too Large",
                                      '{"error":"too large"}', "application/json")
        body = await asyncio.wait_for(reader.readexactly(length), 30)
        owner = "guest"
        data = body
        if headers.get("content-type", "").startswith("application/json") or body[:1] == b"{":
            try:
                payload = json.loads(body)
                data = base64.b64decode(payload["data"].split(",")[-1])
                acc = account_by_token(payload.get("token", ""))
                if acc:
                    owner = acc["username"]
            except Exception:
                return await http_respond(writer, "400 Bad Request",
                                          '{"error":"bad json"}', "application/json")
        url = save_avatar(data, owner)
        if not url:
            return await http_respond(writer, "415 Unsupported Media Type",
                                      '{"error":"not an image"}', "application/json")
        av_id = url.rsplit("/", 1)[-1]

        if owner != "guest" and owner.lower() in ACCOUNTS:
            ACCOUNTS[owner.lower()]["avatar"] = url
            save_accounts()
        return await http_respond(writer, "200 OK",
            json.dumps({"url": url, "uuid": av_id, "owner": owner}),
            "application/json")

    if method == "GET" and target.startswith("/avatar/"):
        av_id = os.path.basename(target[len("/avatar/"):].split("?")[0])
        av_id = av_id.split(".")[0]
        p = avatar_file(av_id)
        if p:
            with open(p, "rb") as f:
                data = f.read()
            ext = os.path.splitext(p)[1]
            return await http_respond(writer, "200 OK", data,
                                      CONTENT_TYPES.get(ext, "application/octet-stream"),
                                      extra={"Cache-Control": "public, max-age=31536000"})
        return await http_respond(writer, "404 Not Found", "not found")

    if method == "GET" and _path.startswith("/join/"):
        code = _path[len("/join/"):].split("/")[0]
        return await http_respond(writer, "200 OK",
                                  invite_page(code), "text/html; charset=utf-8",
                                  extra={"Cache-Control": "no-store"})

    async def _read_body(limit=20000):
        ln = int(headers.get("content-length", "0") or "0")
        if ln <= 0 or ln > limit:
            return b"{}"
        try:
            return await asyncio.wait_for(reader.readexactly(ln), 15)
        except Exception:
            return b"{}"

    if method == "POST" and _path == "/api/login":
        try:
            d = json.loads(await _read_body())
        except Exception:
            d = {}
        login = str(d.get("login", "")).strip()
        pw = str(d.get("password", ""))
        otp = str(d.get("otp", "") or "")
        ipx = client_ip
        if not RL_MEMBER_LOGIN.allow(ipx) and not ip_is_known_good(ipx):
            return await http_respond(writer, "429 Too Many Requests",
                json.dumps({"error": "Too many attempts. Please wait a moment."}),
                "application/json")
        key = "member:" + login.lower()
        wait = 0.0 if ip_is_known_good(ipx) else FAILS.delay_for(key)
        if wait > 2.0:
            return await http_respond(writer, "429 Too Many Requests",
                json.dumps({"error": "Too many attempts. Please wait a moment."}),
                "application/json")
        if wait:
            await asyncio.sleep(wait)
        acc = account_by_login(login)
        if not (acc and acc.get("pw_hash")
                and await verify_password_async(pw, acc["pw_hash"])):
            FAILS.fail(key)
            return await http_respond(writer, "401 Unauthorized",
                json.dumps({"error": "Wrong name or password."}),
                "application/json")
        if totp_on(acc):
            if not otp:
                return await http_respond(writer, "200 OK",
                    json.dumps({"otpRequired": True}), "application/json",
                    extra={"Cache-Control": "no-store"})
            if not totp_check(acc, otp):
                FAILS.fail(key)
                return await http_respond(writer, "401 Unauthorized",
                    json.dumps({"error": "The code is incorrect.",
                                "otpRequired": True}), "application/json")
        FAILS.ok(key)
        mark_ip_good(ipx)
        tok = uuid.uuid4().hex + uuid.uuid4().hex
        acc_add_token(acc, tok)
        acc["token_expires"] = now_ms() + INVITE_DEFAULT_DAYS * 86400_000
        save_accounts()
        return await http_respond(writer, "200 OK",
            json.dumps({"ok": True, "username": acc["username"], "token": tok,
                        "pwTemp": bool(acc.get("pw_temp"))}),
            "application/json", extra={"Cache-Control": "no-store"})

    if method == "POST" and _path == "/api/forgot":
        try:
            d = json.loads(await _read_body())
        except Exception:
            d = {}
        login = str(d.get("login", "")).strip()
        ok_rl = RL_FORGOT.allow(client_ip)
        acc = account_by_login(login) if ok_rl else None
        if acc and acc.get("email") and mail_ready():
            tok = reset_token_new(acc["username"])
            link = f"{public_url()}/reset/{tok}"
            await send_mail(
                acc["email"],
                f"{CONFIG.get('servername','Pixplace')}: Reset your password",
                f"Hello {acc['username']},\n\n"
                f"use this link to set a new password:\n\n"
                f"{link}\n\n"
                f"The link is valid for one hour and can be used only once.\n"
                f"If you did not request this, please ignore this "
                f"message – your password remains unchanged.\n")
            mod_log("-", acc["username"], "PW-RESET-REQUEST",
                    f"Link sent to {mask_mail(acc['email'])} (from {safe_ip(client_ip)})")

        return await http_respond(writer, "200 OK",
            json.dumps({"ok": True}), "application/json",
            extra={"Cache-Control": "no-store"})

    if method == "GET" and _path.startswith("/reset/"):
        return await http_respond(writer, "200 OK",
            reset_page(_path[len("/reset/"):].split("/")[0]),
            "text/html; charset=utf-8", extra={"Cache-Control": "no-store"})

    if method == "POST" and _path == "/api/reset":
        try:
            d = json.loads(await _read_body())
        except Exception:
            d = {}
        pw = str(d.get("password", ""))
        if len(pw) < 8:
            return await http_respond(writer, "400 Bad Request",
                json.dumps({"error": "Mindestens 8 Zeichen."}), "application/json")
        acc = reset_token_use(d.get("token", ""))
        if not acc:
            return await http_respond(writer, "400 Bad Request",
                json.dumps({"error": "The link has expired or was already used."}),
                "application/json")
        acc["pw_hash"] = await hash_password_async(pw)
        acc.pop("pw_temp", None)

        acc_clear_tokens(acc)
        acc["token_expires"] = now_ms() + INVITE_DEFAULT_DAYS * 86400_000
        save_accounts()
        mod_log("-", acc["username"], "PW-RESET-DONE",
                f"new password set (from {safe_ip(client_ip)})")
        return await http_respond(writer, "200 OK",
            json.dumps({"ok": True, "username": acc["username"]}),
            "application/json", extra={"Cache-Control": "no-store"})

    if method == "POST" and _path == "/api/invite/check":
        try:
            d = json.loads(await _read_body())
        except Exception:
            d = {}
        inv = invite_usable(d.get("code", ""))
        if not inv:
            return await http_respond(writer, "200 OK",
                json.dumps({"ok": False}), "application/json",
                extra={"Cache-Control": "no-store"})
        return await http_respond(writer, "200 OK",
            json.dumps({"ok": True, "note": inv.get("note", "")}),
            "application/json", extra={"Cache-Control": "no-store"})

    if method == "POST" and _path == "/api/invite/redeem":
        if not RL_REGISTER.allow(client_ip):
            return await http_respond(writer, "429 Too Many Requests",
                json.dumps({"error": "Too many attempts."}), "application/json")
        try:
            d = json.loads(await _read_body())
        except Exception:
            d = {}
        inv = invite_usable(d.get("code", ""))
        if not inv:
            return await http_respond(writer, "400 Bad Request",
                json.dumps({"error": "This invitation is no longer valid."}),
                "application/json")
        uname = clean_base_name(d.get("username", ""))
        pw = str(d.get("password", ""))
        email = str(d.get("email", "")).strip()
        if not valid_mail(email):
            return await http_respond(writer, "400 Bad Request",
                json.dumps({"error": "Please enter a valid e-mail address."}),
                "application/json")

        if any(str(a.get("email","")).strip().lower() == email.lower()
               for a in ACCOUNTS.values()):
            return await http_respond(writer, "409 Conflict",
                json.dumps({"error": "An account already exists for this address."}),
                "application/json")
        if not uname or len(uname) < 2:
            return await http_respond(writer, "400 Bad Request",
                json.dumps({"error": "Please enter a name with at least 2 characters."}),
                "application/json")
        if len(pw) < 8:
            return await http_respond(writer, "400 Bad Request",
                json.dumps({"error": "The password needs at least 8 characters."}),
                "application/json")
        if not name_free(uname) or uname.lower() in ACCOUNTS:
            return await http_respond(writer, "409 Conflict",
                json.dumps({"error": "This name is already taken."}),
                "application/json")
        tok = uuid.uuid4().hex + uuid.uuid4().hex
        acc = {"username": uname,
               "token_hash": token_hash(tok),
               "pw_hash": await hash_password_async(pw),
               "email": email,
               "rank": int(inv.get("rank", RANK_MEMBER)),
               "created": now_ms(), "points": 0,
               "invite": inv["code"],

               "token_expires": now_ms() + INVITE_DEFAULT_DAYS * 86400_000}
        ACCOUNTS[uname.lower()] = acc
        save_accounts()
        mod_log("-", uname, "ACCOUNT-CREATE", "via registration in chat")
        inv["used_by"] = uname
        inv["used_at"] = now_ms()
        save_invites()
        mod_log("-", uname, "INVITE-REDEEM", f"Invitation {inv['code'][:6]}… redeemed")
        extra = {"Cache-Control": "no-store"}
        if CONFIG.get("test_mode"):

            extra["Set-Cookie"] = (f"pp_preview={test_cookie_value()}; Path=/; "
                                   "Max-Age=2592000; HttpOnly; SameSite=Lax")
        return await http_respond(writer, "200 OK",
            json.dumps({"ok": True, "username": uname, "token": tok}),
            "application/json", extra=extra)

    if method == "POST" and target == "/register":
        if not RL_REGISTER.allow(client_ip):
            return await http_respond(writer, "429 Too Many Requests",
                json.dumps({"error": "Too many registrations. Please try again later."}),
                "application/json")
        length = int(headers.get("content-length", "0") or "0")
        body = b""
        if 0 < length < 10_000:
            try:
                body = await asyncio.wait_for(reader.readexactly(length), 15)
            except Exception:
                body = b""
        try:
            uname = clean_base_name(json.loads(body).get("username", ""))
        except Exception:
            uname = ""
        if not uname or len(uname) < 2:
            return await http_respond(writer, "400 Bad Request",
                json.dumps({"error": "Please choose a name with at least 2 characters."}),
                "application/json")
        key = uname.lower()
        if key in ACCOUNTS:
            return await http_respond(writer, "409 Conflict",
                json.dumps({"error": f"\"{uname}\" is already taken."}),
                "application/json")
        _tok = uuid.uuid4().hex + uuid.uuid4().hex
        acc = {"username": uname, "token_hash": token_hash(_tok),
               "rank": RANK_MEMBER, "created": now_ms()}
        ACCOUNTS[key] = acc
        save_accounts()
        return await http_respond(writer, "200 OK",
            json.dumps({"username": uname, "token": _tok,
                        "rank": RANK_MEMBER}), "application/json")

    if target in ("/version", "/api/version"):
        return await http_respond(writer, "200 OK", json.dumps({
            "name": "Pixplace", "version": PP_VERSION,
            "server": CONFIG.get("servername", "Pixplace"),
        }), "application/json")

    if target == "/lang/list":
        return await http_respond(writer, "200 OK",
                                  json.dumps({"langs": lang_list()}),
                                  "application/json")
    if target.startswith("/lang/") and target.endswith(".lang"):
        code = target[6:-5]
        if re.fullmatch(r"[a-z]{2}(-[A-Za-z]{2})?", code or ""):
            p = os.path.join(LANG_DIR, code + ".lang")
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    return await http_respond(writer, "200 OK", f.read(),
                        "text/plain; charset=utf-8",
                        extra={"Cache-Control": "public, max-age=600"})
        return await http_respond(writer, "404 Not Found", "unknown language")

    if target == "/auth/providers":
        return await http_respond(writer, "200 OK", json.dumps({
            "providers": [{"id": p, "name": OAUTH_PROVIDERS[p]["name"]}
                          for p in OAUTH_PROVIDERS if oauth_enabled(p)]
        }), "application/json")

    if target.startswith("/auth/") and target[6:] in OAUTH_PROVIDERS:
        prov = target[6:]
        if not oauth_enabled(prov):
            return await http_respond(writer, "404 Not Found",
                                      "Sign-in with this provider is "
                                      "not configured.", "text/plain")
        st = uuid.uuid4().hex
        OAUTH_STATES[st] = {"provider": prov, "ts": now_ms()}
        for k, v in list(OAUTH_STATES.items()):
            if now_ms() - v["ts"] > 600_000:
                OAUTH_STATES.pop(k, None)
        meta = OAUTH_PROVIDERS[prov]
        q = {"client_id": oauth_cfg(prov)["client_id"],
             "redirect_uri": oauth_redirect_uri(),
             "response_type": "code", "scope": meta["scope"], "state": st}
        if prov == "apple":
            q["response_mode"] = "form_post"
        url = meta["auth"] + "?" + urllib.parse.urlencode(q)
        writer.write(("HTTP/1.1 302 Found\r\nLocation: " + url +
                      "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                     .encode())
        await writer.drain()
        return

    if target.startswith("/auth/callback"):

        params = {}
        if "?" in target:
            params = dict(urllib.parse.parse_qsl(target.split("?", 1)[1]))

        if method == "POST":
            try:
                ln = int(headers.get("content-length", "0") or "0")
                if 0 < ln < 20_000:
                    raw = await asyncio.wait_for(reader.readexactly(ln), 15)
                    params.update(dict(urllib.parse.parse_qsl(
                        raw.decode("utf-8", "replace"))))
            except Exception:
                pass
        st = OAUTH_STATES.pop(params.get("state", ""), None)
        if not st:
            return await http_respond(writer, "400 Bad Request",
                                      oauth_result_page(None,
                                          "The sign-in has expired. "
                                          "Please try again."),
                                      "text/html; charset=utf-8")
        prov = st["provider"]
        code = params.get("code", "")
        if not code:
            return await http_respond(writer, "400 Bad Request",
                                      oauth_result_page(None,
                                          "The provider cancelled "
                                          "the sign-in."),
                                      "text/html; charset=utf-8")
        try:
            secret = (_apple_client_secret() if prov == "apple"
                      else oauth_cfg(prov)["client_secret"])
            data = urllib.parse.urlencode({
                "code": code, "client_id": oauth_cfg(prov)["client_id"],
                "client_secret": secret, "grant_type": "authorization_code",
                "redirect_uri": oauth_redirect_uri()}).encode()
            tok = await _http_json(
                OAUTH_PROVIDERS[prov]["token"], data,
                {"Content-Type": "application/x-www-form-urlencoded",

                 "Accept": "application/json",
                 "User-Agent": "Pixplace"})
            if OAUTH_PROVIDERS[prov].get("userinfo"):
                claims = await oauth_userinfo(prov, tok.get("access_token", ""))
            else:
                claims = await oauth_verify_id_token(prov, tok.get("id_token", ""))
        except Exception as e:
            print("OAuth error:", e)
            claims = None
        if not claims:
            return await http_respond(writer, "400 Bad Request",
                                      oauth_result_page(None,
                                          "The sign-in could not "
                                          "be verified."),
                                      "text/html; charset=utf-8")
        acc = oauth_account_for(prov, str(claims.get("sub")),
                                str(claims.get("email") or ""),
                                str(claims.get("name") or ""))
        mod_log("-", acc["username"], "OAUTH-LOGIN", prov)
        return await http_respond(writer, "200 OK",
                                  oauth_result_page(acc, None),
                                  "text/html; charset=utf-8")

    _p = target.split("?")[0]
    if _p == "/imprint":
        return await http_respond(writer, "200 OK",
                                  legal_page("imprint", page_lang(target)),
                                  "text/html; charset=utf-8")
    if _p == "/privacy":
        return await http_respond(writer, "200 OK",
                                  legal_page("privacy", page_lang(target)),
                                  "text/html; charset=utf-8")
    if _p == "/terms":
        return await http_respond(
            writer, "200 OK",
            legal_page("terms", page_lang(target)),
            "text/html; charset=utf-8")

    if _path == "/api/doc-pass":
        ok, _ = may_read_docs(target, headers)
        if not ok:
            return await http_respond(writer, "404 Not Found", "not found")
        return await http_respond(
            writer, "200 OK", json.dumps({"ok": True}), "application/json",
            extra={"Cache-Control": "no-store",
                   "Set-Cookie": (f"pp_doc={doc_cookie_value()}; Path=/; "
                                  "Max-Age=43200; HttpOnly; SameSite=Lax")})

    _dp = target.split("?")[0]
    if _dp in ("/manual", "/wiki", "/admin-wiki"):
        admin_page = _dp in ("/wiki", "/admin-wiki")
        okdoc, setck = may_read_docs(target, headers)
        if admin_page and not okdoc:
            return await http_respond(writer, "404 Not Found", "not found")
        ex = {"Cache-Control": "no-store"}
        if setck:
            ex["Set-Cookie"] = (f"pp_doc={doc_cookie_value()}; Path=/; "
                                "Max-Age=43200; HttpOnly; SameSite=Lax")
        return await http_respond(writer, "200 OK",
                                  pps_doc_page(admin_page, page_lang(target)),
                                  "text/html; charset=utf-8", extra=ex)

    _ap = target.split("?")[0]

    if CONFIG.get("admin_hidden") and admin_base() != "admin" \
            and (_ap == "/admin" or _ap.startswith("/admin/")):
        return await http_respond(writer, "404 Not Found", "not found")
    if is_admin_path(_ap):
        length = int(headers.get("content-length", "0") or "0")
        body = b""
        if length > 0 and length < 200_000:
            try:
                body = await asyncio.wait_for(reader.readexactly(length), 15)
            except Exception:
                body = b""
        return await handle_admin(writer, method, target, headers, body, client_ip)

    if (target.split("?")[0] in ("/manifest.json", "/sw.js", "/icon-192.png",
                                 "/icon-512.png", "/api/online", "/api/comments",
                                 "/status", "/api/status")):
        length = int(headers.get("content-length", "0") or "0")
        pbody = b""
        if 0 < length < 50_000:
            try:
                pbody = await asyncio.wait_for(reader.readexactly(length), 15)
            except Exception:
                pbody = b""
        res = await handle_portal_http(writer, method, target, headers, pbody, client_ip)
        if res is not None:
            return res

    def _serve_file(cand):
        here = os.path.dirname(os.path.abspath(__file__))
        for d in (here, os.path.join(os.path.dirname(here), "client")):
            p = os.path.join(d, cand)
            if os.path.isfile(p):
                return p
        return None

    if method == "GET" and target in ("/", "/index.html", "/portal"):
        return await http_respond(writer, "200 OK", PORTAL_HTML,
                                  "text/html; charset=utf-8",
                                  extra={"Cache-Control": "no-cache, must-revalidate"})

    if method == "GET" and _dp in ("/viewtest.css", "/viewtest.js",
                                   "/viewapple.css", "/viewapple.js"):
        _vp = _serve_file(_dp.lstrip("/"))
        if _vp:
            with open(_vp, "rb") as f:
                _vd = f.read()
            _ct = ("text/css; charset=utf-8" if _dp.endswith(".css")
                   else "application/javascript; charset=utf-8")
            return await http_respond(writer, "200 OK", _vd, _ct,
                extra={"Cache-Control": "no-cache, must-revalidate"})
        return await http_respond(writer, "404 Not Found", "not found")

    if method == "GET" and _dp in ("/viewtest", "/viewapple"):
        _vp = _serve_file(_dp.lstrip("/") + ".html")
        if _vp:
            with open(_vp, "rb") as f:
                _vd = f.read()
            return await http_respond(writer, "200 OK", _vd,
                "text/html; charset=utf-8",
                extra={"Cache-Control": "no-cache, must-revalidate"})
        return await http_respond(writer, "404 Not Found", "not found")

    if method == "GET" and target in ("/app", "/app.html", "/client.html"):
        p = _serve_file("client.html")
        if p:
            with open(p, "rb") as f:
                data = f.read()

            return await http_respond(
                writer, "200 OK", data, "text/html; charset=utf-8",
                extra={"Cache-Control": "no-cache, must-revalidate",
                       "ETag": '"%s"' % hashlib.sha256(data).hexdigest()[:16]})
        return await http_respond(writer, "200 OK",
            "Pixplace server is running. Put client.html next to server.py.")

    return await http_respond(writer, "404 Not Found", "not found")

class MiniWS:
    def __init__(self, reader, writer, key):
        self.r, self.w = reader, writer
        self.remote = writer.get_extra_info("peername")
        self.fwd_ip = None
        self.closed = False
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        writer.write(("HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())

    @property
    def ip(self):
        return self.fwd_ip or (self.remote[0] if self.remote else "?")

    async def _rx(self, n):
        return await self.r.readexactly(n)

    async def recv(self):
        buf = b""
        while True:
            try:
                h = await self._rx(2)
            except Exception:
                raise ConnectionClosed
            fin, op = h[0] & 0x80, h[0] & 0x0F
            masked, ln = h[1] & 0x80, h[1] & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", await self._rx(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", await self._rx(8))[0]
            if ln > MAX_WS_MSG:
                await self.close(); raise ConnectionClosed
            mask = await self._rx(4) if masked else b"\0\0\0\0"
            pl = await self._rx(ln) if ln else b""
            if masked:
                pl = bytes(b ^ mask[i % 4] for i, b in enumerate(pl))
            if op == 0x8:
                await self.close(); raise ConnectionClosed
            if op == 0x9:
                await self._frame(0xA, pl); continue
            if op == 0xA:
                continue
            buf += pl
            if fin:
                try:
                    return buf.decode("utf-8")
                except UnicodeDecodeError:
                    buf = b""

    async def _frame(self, op, pl):
        if self.closed:
            return
        h = bytes([0x80 | op])
        n = len(pl)
        if n < 126:
            h += bytes([n])
        elif n < 65536:
            h += bytes([126]) + struct.pack(">H", n)
        else:
            h += bytes([127]) + struct.pack(">Q", n)
        try:
            self.w.write(h + pl)
            await self.w.drain()
        except Exception:
            self.closed = True
            raise ConnectionClosed

    MAXQ = 300

    def _ensure_writer(self):
        if getattr(self, "_outq", None) is None:
            self._outq = asyncio.Queue(maxsize=self.MAXQ)
            self._writer = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            while True:
                data = await self._outq.get()
                if data is None:
                    break
                await self._frame(0x1, data.encode("utf-8"))
        except Exception:
            pass
        finally:
            try:
                await self.close()
            except Exception:
                pass

    def enqueue(self, text) -> bool:
        if self.closed:
            return False
        self._ensure_writer()
        try:
            self._outq.put_nowait(text)
            return True
        except asyncio.QueueFull:
            return False

    async def send(self, text):

        await self._frame(0x1, text.encode("utf-8"))

    async def close(self):
        if not self.closed:
            try:
                await self._frame(0x8, b"")
            except Exception:
                pass
            self.closed = True
            try:
                self.w.close()
            except Exception:
                pass

TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\{|\}|\S+')

PPS_EVENTS = ("ENTER", "LEAVE", "SAY", "CHAT", "DOOR", "TIMER")

PPS_ALIAS = {"SAY": "CHAT"}
PPS_CMDS = ("SAY", "WHISPER", "TOAST", "GOTO", "SET", "ADD", "IF", "ELSE",
            "END", "LOCK", "UNLOCK", "MOVE", "POINTS", "ANNOUNCE", "STOP")
PPS_MAXLINES = 400

def pps_is_new_style(src: str) -> bool:
    for ln in (src or "").splitlines():
        t = ln.strip()
        if t.upper().startswith("ON ") and "{" not in t:
            return True
    return False

def pps_split(line: str):
    out, cur, q = [], "", False
    for ch in line:
        if ch == '"':
            q = not q
            cur += ch
        elif ch.isspace() and not q:
            if cur:
                out.append(cur); cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out

def pps_unquote(v: str) -> str:
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v

def pps_parse(src: str):
    handlers, errors = {}, []
    cur, cur_ev, depth = None, None, 0
    lines = (src or "").splitlines()[:PPS_MAXLINES]
    for no, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = pps_split(line)
        head = parts[0].upper()
        if head == "ON":
            if cur is not None:
                errors.append(f"Line {no}: \"ON\" inside a block.")
                continue
            ev = (parts[1].upper() if len(parts) > 1 else "")
            if ev not in PPS_EVENTS:
                errors.append(f"Line {no}: unknown event \"{ev}\". "
                              f"Allowed: {', '.join(PPS_EVENTS)}")
                continue
            ev = PPS_ALIAS.get(ev, ev)
            cur_ev = ev
            cur = []
            match = pps_unquote(parts[2]) if len(parts) > 2 else ""

            handlers.setdefault(ev, []).append({"match": match, "body": cur})
            depth = 0
            continue
        if cur is None:
            errors.append(f"Line {no}: \"{parts[0]}\" is outside an ON block.")
            continue
        if head == "END":
            if depth > 0:
                depth -= 1
                cur.append(("ENDIF", [], no))
            else:
                cur, cur_ev = None, None
            continue
        if head not in PPS_CMDS:
            errors.append(f"Line {no}: unknown command \"{parts[0]}\".")
            continue
        if head == "IF":
            depth += 1
            if len(parts) < 4:
                errors.append(f"Line {no}: IF needs \"IF value comparison value\".")
            cur.append(("IF", parts[1:], no))
            continue
        if head == "ELSE":
            cur.append(("ELSE", [], no))
            continue
        cur.append((head, parts[1:], no))
    if cur is not None:
        errors.append("Missing \"END\" for the last ON block.")
    return handlers, errors

def pps_expand(text: str, ctx) -> str:
    u, r = ctx.user, ctx.room
    g = group_of(u.base) if u else None
    rep = {
        "user": u.base if u else "",
        "name": u.name if u else "",
        "room": r.name if r else "",
        "roomid": r.room_id() if r else "",
        "rank": RANK_NAME.get(u.rank, "user") if u else "user",
        "group": (g or {}).get("name", ""),
        "grouprank": rank_label(g, u.base) if (g and u) else "",
        "users": str(len(r.users)) if r else "0",
        "text": getattr(ctx, "chatstr", "") or "",
    }
    out = str(text)
    for k, v in rep.items():
        out = out.replace("{" + k + "}", str(v))

    def var_sub(m):
        return str((r.vars.get(m.group(1)) if r else "") or "")
    out = re.sub(r"\{var\.([\w\-]+)\}", var_sub, out)
    return out

def pps_value(tok: str, ctx):
    v = pps_expand(pps_unquote(tok), ctx)
    return v

def pps_cmp(a: str, op: str, b: str) -> bool:
    RANKORD = {"user": 0, "member": 1, "wizard": 2, "owner": 3}
    la, lb = a.lower(), b.lower()
    if la in RANKORD and lb in RANKORD:
        a_n, b_n = RANKORD[la], RANKORD[lb]
    else:
        try:
            a_n, b_n = float(a), float(b)
        except Exception:
            a_n = b_n = None
    if op in ("==", "="):
        return la == lb
    if op == "!=":
        return la != lb
    if op.upper() == "CONTAINS":
        return lb in la
    if a_n is None:
        return False
    return {">": a_n > b_n, "<": a_n < b_n,
            ">=": a_n >= b_n, "<=": a_n <= b_n}.get(op, False)

def pps_run(body, ctx, max_ops=500):
    i, ops, skip = 0, 0, []
    while i < len(body) and ops < max_ops:
        cmd, args, no = body[i]
        ops += 1
        i += 1
        if cmd == "IF":
            cond = False
            if len(args) >= 3:
                cond = pps_cmp(pps_value(args[0], ctx), args[1],
                               pps_value(args[2], ctx))
            skip.append(not cond)
            continue
        if cmd == "ELSE":
            if skip:
                skip[-1] = not skip[-1]
            continue
        if cmd == "ENDIF":
            if skip:
                skip.pop()
            continue
        if any(skip):
            continue
        arg = " ".join(args)
        if cmd == "SAY":
            ctx.say.append(pps_expand(pps_unquote(arg), ctx))
        elif cmd == "TOAST":
            ctx.toast.append(pps_expand(pps_unquote(arg), ctx))
        elif cmd == "WHISPER":
            ctx.whisper.append(pps_expand(pps_unquote(arg), ctx))
        elif cmd == "GOTO":
            ctx.goto = pps_expand(pps_unquote(arg), ctx)
        elif cmd == "SET" and len(args) >= 2 and ctx.room is not None:
            ctx.room.vars[args[0]] = pps_expand(pps_unquote(" ".join(args[1:])), ctx)
        elif cmd == "ADD" and len(args) >= 2 and ctx.room is not None:
            try:
                old = float(ctx.room.vars.get(args[0], 0) or 0)
                val = old + float(pps_value(args[1], ctx))
                ctx.room.vars[args[0]] = (str(int(val)) if val == int(val)
                                          else str(round(val, 3)))
            except Exception:
                pass
        elif cmd == "MOVE" and len(args) >= 2:
            try:
                ctx.setpos = (int(float(pps_value(args[0], ctx))),
                              int(float(pps_value(args[1], ctx))))
            except Exception:
                pass
        elif cmd == "LOCK" and ctx.room is not None:
            ctx.room.operatorsonly = True
        elif cmd == "UNLOCK" and ctx.room is not None:
            ctx.room.operatorsonly = False
        elif cmd == "POINTS":
            try:
                ctx.points += int(float(pps_value(args[0], ctx))) if args else 0
            except Exception:
                pass
        elif cmd == "ANNOUNCE":
            ctx.announce.append(pps_expand(pps_unquote(arg), ctx))
        elif cmd == "STOP":
            ctx.suppress = True
            break
    return ctx

def parse_handlers(src: str):
    toks = TOKEN_RE.findall(src or "")
    handlers, i = {}, 0
    while i < len(toks):
        if toks[i].upper() == "ON" and i + 2 < len(toks) and toks[i + 2] == "{":
            ev = toks[i + 1].upper()
            depth, j, body = 1, i + 3, []
            while j < len(toks) and depth:
                if toks[j] == "{":
                    depth += 1
                elif toks[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                body.append(toks[j]); j += 1
            handlers[ev] = body; i = j + 1
        else:
            i += 1
    return handlers

class SC:
    def __init__(self, user, room, chatstr=""):
        self.user, self.room, self.chatstr = user, room, chatstr
        self.say, self.goto, self.setpos, self.suppress = [], None, None, False

        self.toast, self.whisper, self.announce = [], [], []
        self.points = 0

def run_script(tokens, ctx, rvars, max_ops=2000):
    import random
    stack, i, ops = [], 0, 0
    pop = lambda d=0: stack.pop() if stack else d

    def skip(k):
        depth = 0
        while k < len(tokens):
            if tokens[k] == "{":
                depth += 1
            elif tokens[k] == "}":
                depth -= 1
                if depth == 0:
                    return k + 1
            k += 1
        return k

    while i < len(tokens) and ops < max_ops:
        ops += 1
        t = tokens[i]; u = t.upper()
        if t.startswith('"'):
            stack.append(json.loads(t)); i += 1; continue
        try:
            stack.append(float(t) if "." in t else int(t)); i += 1; continue
        except ValueError:
            pass
        if u == "IF":
            cond = pop(); i += 1
            if i < len(tokens) and tokens[i] == "{":
                end = skip(i)
                if cond:
                    i += 1
                else:
                    i = end
                    if i < len(tokens) and tokens[i].upper() == "ELSE":
                        i += 1
                        if i < len(tokens) and tokens[i] == "{":
                            i += 1
            continue
        if u == "ELSE":
            i += 1
            if i < len(tokens) and tokens[i] == "{":
                i = skip(i)
            continue
        if t in ("{", "}", "ENDIF"):
            i += 1; continue
        if u == "SAY":
            ctx.say.append(str(pop("")))
        elif u == "GOTOROOM":
            ctx.goto = str(pop(""))
        elif u == "SETPOS":
            y, x = pop(), pop()
            try: ctx.setpos = (int(x), int(y))
            except Exception: pass
        elif u == "SUPPRESS":
            ctx.suppress = True
        elif u == "&":
            b, a = pop(""), pop(""); stack.append(f"{a}{b}")
        elif u in ("+", "-", "*", "/", "==", "!=", ">", "<", ">=", "<="):
            b, a = pop(), pop()
            try:
                stack.append({"+":a+b,"-":a-b,"*":a*b,"/":a/b if b else 0,
                              "==":int(a==b),"!=":int(a!=b),">":int(a>b),
                              "<":int(a<b),">=":int(a>=b),"<=":int(a<=b)}[u])
            except TypeError:
                stack.append(0)
        elif u == "RANDOM":
            n = pop(1)
            try: stack.append(random.randrange(max(1, int(n))))
            except Exception: stack.append(0)
        elif u == "ME":
            stack.append(ctx.user.name if ctx.user else "")
        elif u == "CHATSTR":
            stack.append(ctx.chatstr)
        elif u == "ROOMNAME":
            stack.append(ctx.room.name if ctx.room else "")
        elif u == "USERCOUNT":
            stack.append(len(ctx.room.users) if ctx.room else 0)
        elif u == "SET":
            val = pop(""); rvars[str(pop(""))] = val
        elif u == "GET":
            stack.append(rvars.get(str(pop("")), 0))
        i += 1
    return ctx

RANK_USER = RANK_GUEST = 0
RANK_MEMBER = 1
RANK_WIZARD = 2
RANK_OWNER = 3
RANK_NAME = {0: "user", 1: "member", 2: "wizard", 3: "owner"}
RANK_STAR = {0: "", 1: "", 2: "*", 3: "**"}

PERM_DEFS = [
    ("create_room", "Create rooms"),
    ("edit_room", "Change background/script"),
    ("moderate", "Moderation (gag/kill/ban)"),
]
DEFAULT_PERMS = {

    "create_room": {0: False, 1: True, 2: True, 3: True},
    "edit_room":   {0: False, 1: False, 2: True, 3: True},
    "moderate":    {0: False, 1: False, 2: True, 3: True},
}

def perms() -> dict:
    return CONFIG.setdefault("permissions", {})

def can(user, cap: str) -> bool:
    if user.rank >= RANK_OWNER:
        return True
    table = perms().get(cap) or DEFAULT_PERMS.get(cap, {})
    return bool(table.get(str(user.rank), table.get(user.rank, False)))

def name_owner(name: str) -> str | None:
    key = (name or "").strip().lower()
    if not key:
        return None
    for k, acc in ACCOUNTS.items():
        if (acc.get("username") or "").lower() == key:
            return k
        for old in (acc.get("heldNames") or []):
            if str(old).lower() == key:
                return k
    return CONFIG.get("reserved", {}).get(key)

def name_free(name: str, for_account: dict | None = None) -> bool:
    holder = name_owner(name)
    if not holder:
        return True
    if for_account and holder == (for_account.get("username") or "").lower():
        return True
    return False

def hold_name(acc: dict, name: str):
    if not acc:
        return
    lst = acc.setdefault("heldNames", [])
    low = [str(x).lower() for x in lst]
    if name.lower() not in low:
        lst.append(name)

def release_name(acc: dict, name: str):
    if not acc or not name:
        return
    lst = acc.get("heldNames") or []
    acc["heldNames"] = [x for x in lst if str(x).lower() != name.lower()]

def rename_everywhere(old: str, new: str) -> list:
    lo, ln = old.lower(), new.lower()
    if lo == ln:
        return []
    touched = []

    for g in GROUPS.values():
        changed = False

        mem = g.get("members") or []
        for i, m in enumerate(mem):
            if str(m).lower() == lo:
                mem[i] = new
                changed = True

        if (g.get("owner") or "").lower() == lo:
            g["owner"] = new
            changed = True

        for field in ("ranks", "points", "minutes", "lastseen"):
            d = g.get(field)
            if isinstance(d, dict) and lo in d:
                d[ln] = d.pop(lo)
                changed = True

        reqs = g.get("requests")
        if isinstance(reqs, list):
            for i, r in enumerate(reqs):
                if isinstance(r, str) and r.lower() == lo:
                    reqs[i] = new
                    changed = True
                elif isinstance(r, dict) and str(r.get("base", "")).lower() == lo:
                    r["base"] = new
                    changed = True
        if changed:
            touched.append("Group " + g.get("name", "?"))
    if touched:
        save_groups()

    grants = CONFIG.get("grants") or {}
    if lo in grants:
        grants[ln] = grants.pop(lo)
        touched.append("Role")
        save_config()

    try:
        if lo in BANS.get("names", set()):
            BANS["names"].discard(lo)
            BANS["names"].add(ln)
            touched.append("Sperrliste")
    except Exception:
        pass
    return touched

def release_name(name: str) -> bool:
    key = (name or "").strip().lower()
    freed = False
    for k, acc in list(ACCOUNTS.items()):
        lst = acc.get("heldNames") or []
        keep = [x for x in lst if str(x).lower() != key]
        if len(keep) != len(lst):
            acc["heldNames"] = keep
            freed = True
    CONFIG.setdefault("reserved", {}).pop(key, None)
    if freed:
        save_accounts()
    return freed

GUEST_WORDS = ["Nova", "Pixel", "Echo", "Zimt", "Luna", "Kobo", "Miro", "Taro",
               "Fips", "Wolke", "Nebel", "Funke", "Kiwi", "Momo", "Rubi",
               "Sunny", "Tiko", "Yuki", "Bolt", "Kori"]

def guest_name() -> str:
    for _ in range(60):
        nm = random.choice(GUEST_WORDS) + str(random.randint(2, 99))
        if name_free(nm) and not any(
                u.base.lower() == nm.lower() for u in all_users()):
            return nm
    return "Guest" + str(random.randint(100, 9999))

def clean_base_name(s: str, maxlen: int = 22) -> str:
    s = re.sub(r"[*]", "", str(s))
    s = re.sub(r"[^\w\-\. äöüÄÖÜß]", "", s).strip()
    return s[:maxlen]

def clean_group_name(s: str, maxlen: int = 24) -> str:
    s = re.sub(r"[*]", "", str(s))
    s = re.sub(r"[^\w\-\.\'&+ äöüÄÖÜß]", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:maxlen]

def display_name(base: str, rank: int) -> str:
    return RANK_STAR.get(rank, "") + base

class User:
    def __init__(self, ws: MiniWS):
        self.ws = ws
        self.id = uuid.uuid4().hex[:8]
        self.base = "Guest"
        self.rank = RANK_USER
        self.avatar = None
        self.props = []
        self.x, self.y = 300, 300
        self.room = None

        self.gagged = False
        self.propgagged = False
        self.pinned = False
        self.hidden = False

        self.whisper_policy = "all"
        self.ip = getattr(ws, "ip", "?")
        self.signed_on = False
        self.idle = False
        self.idle_text = ""
        self.idle_since = 0
        self.last_script_points = 0
        self.muted = set()
        self.account = None
        self.observer = False
        self.box = AVATAR_BOX_MIN
        self.layout = "grid"
        self.name_color = ""
        self.bubble_color = ""

    @property
    def name(self):
        return display_name(self.base, self.rank)

    def public(self):
        return {"id": self.id, "name": self.name, "base": self.base,
                "rank": self.rank, "rankName": RANK_NAME[self.rank],
                "avatar": self.avatar,
                "props": [] if self.propgagged else self.props,
                "x": self.x, "y": self.y, "pinned": self.pinned,
                "gagged": self.gagged, "hidden": self.hidden,
                "whisperPolicy": self.whisper_policy,
                "idle": self.idle, "idleText": self.idle_text,
                "perkGlow": perk_active(self.account or {}, "namecolor"),
                "idleSince": self.idle_since,
                "box": self.box, "layout": self.layout,
                "nameColor": self.name_color, "bubbleColor": self.bubble_color,
                "group": group_public(group_of(self.base), self.base)}

def room_by_ref(ref: str):
    v = str(ref or "").strip()
    if not v:
        return None
    for r in ROOMS.values():
        if r.room_id() == v:
            return r
    return ROOMS.get(v)

def start_room() -> str:
    r = room_by_ref(CONFIG.get("start_room_id") or "")
    if r:
        return r.name
    r = ROOMS.get("Lobby")
    if r:
        CONFIG["start_room_id"] = room_ref(r)
        return r.name
    for x in sorted(ROOMS.values(), key=lambda z: (getattr(z, "order", 0), z.name)):
        if not x.hidden:
            return x.name
    return "Lobby"

def room_ref(room) -> str:
    return room.room_id() if room else ""

class Room:
    def __init__(self, name, hidden=False, password=None, bg=None, owner=None,
                 persistent=False):

        self.rid = uuid.uuid4().hex[:8]
        self.order = 0
        self.name = name
        self.hidden = hidden
        self.password = password or None
        self.bg = bg
        self.bg_fit = "fill"
        self.room_w = 900
        self.room_h = 560
        self.owner = owner
        self.operatorsonly = False
        self.persistent = persistent
        self.perm_requested = False
        self.loose_props = {}
        self.rid = uuid.uuid4().hex[:8]
        self.parent = ""
        self.landing = False
        self.loose_allowed = True
        self.doors = {}
        self.seeded = False
        self.blocked_wizards = set()

        self.draw_allowed = True
        self.strokes = []
        self.users: dict[str, User] = {}
        self.script_src = ""
        self.handlers = {}
        self.vars = {}
        self.log = []
        self.yt_viewers = {}
        self.yt = {"videoId": None, "playing": False, "time": 0.0,
                   "updated": now_ms()}
        self._load_log()

    def _log_path(self):
        return os.path.join(LOG_DIR, re.sub(r"[^\w\-]", "_", self.name) + ".jsonl")

    def _load_log(self):
        try:
            with open(self._log_path(), encoding="utf-8") as f:
                self.log = [json.loads(l) for l in f.readlines()[-LOG_KEEP:]]
        except Exception:
            self.log = []

    def add_log(self, name, text):
        e = {"ts": now_ms(), "name": name, "text": text}
        self.log.append(e); self.log = self.log[-LOG_KEEP:]

        if privacy_off("chat_logs"):
            return
        try:
            with open(self._log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def set_script(self, src):
        self.script_src = src or ""

        if pps_is_new_style(self.script_src):
            hs, errs = pps_parse(self.script_src)
            self.handlers = hs
            self.script_lang = "pps"
            self.script_errors = errs
        else:
            self.handlers = parse_handlers(self.script_src)
            self.matches = {}
            self.script_lang = "legacy"
            self.script_errors = []

    def yt_now(self):
        y = dict(self.yt)
        if y["playing"]:
            y["time"] += (now_ms() - y["updated"]) / 1000.0
        return {"videoId": y["videoId"], "playing": y["playing"],
                "time": y["time"], "shared": bool(y.get("shared")),
                "mode": y.get("mode", "video"), "sharedBy": y.get("by")}

    def room_id(self):
        if not getattr(self, "rid", None):
            self.rid = uuid.uuid4().hex[:8]
        return self.rid

    def info(self):
        g = group_by_room(self.name)
        return {"id": self.room_id(), "name": self.name, "users": len(self.users),
                "order": int(getattr(self, "order", 0) or 0),
                "bg": (self.bg if valid_media_url(self.bg) else None),
                "hidden": self.hidden, "locked": bool(self.password),
                "operatorsonly": self.operatorsonly,
                "persistent": self.persistent,
                "permRequested": self.perm_requested,
                "looseAllowed": self.loose_allowed,
                "drawAllowed": self.draw_allowed,

                "parent": getattr(self, "parent", "") or "",
                "landing": bool(getattr(self, "landing", False)),
                "group": (g or {}).get("name") or "",
                "kind": (group_kind(g) if g else "")}

    def to_dict(self) -> dict:
        return {"name": self.name, "hidden": self.hidden,
                "rid": getattr(self, "rid", None),
                "parent": getattr(self, "parent", "") or "",
                "landing": bool(getattr(self, "landing", False)),
                "password": self.password, "bg": self.bg, "bgFit": self.bg_fit,
                "roomW": self.room_w, "roomH": self.room_h,
                "owner": self.owner, "operatorsonly": self.operatorsonly,
                "script": self.script_src, "vars": self.vars, "persistent": True,
                "looseAllowed": self.loose_allowed,
                "drawAllowed": self.draw_allowed,
                "strokes": self.strokes[:4000],
                "looseProps": list(self.loose_props.values())[:120],
                "doors": list(self.doors.values())[:40],
                "rid": self.room_id(),
                "order": int(getattr(self, "order", 0) or 0),
                "blockedWizards": sorted(getattr(self, "blocked_wizards", None) or []),
                "seeded": bool(getattr(self, "seeded", False))}

    @classmethod
    def from_dict(cls, d: dict) -> "Room":
        r = cls(d["name"], hidden=bool(d.get("hidden")),
                password=d.get("password"), bg=d.get("bg"), owner=d.get("owner"),
                persistent=bool(d.get("persistent", True)))
        r.bg_fit = d.get("bgFit") or d.get("bg_fit") or "fill"
        try:
            r.room_w = max(320, min(2000, int(d.get("roomW", 900))))
            r.room_h = max(240, min(1400, int(d.get("roomH", 560))))
        except Exception:
            pass
        r.operatorsonly = bool(d.get("operatorsonly"))
        r.rid = d.get("rid") or uuid.uuid4().hex[:8]
        r.parent = str(d.get("parent") or "")
        r.landing = bool(d.get("landing"))
        r.vars = dict(d.get("vars") or {})
        r.loose_allowed = bool(d.get("looseAllowed", True))
        r.draw_allowed = bool(d.get("drawAllowed", True))
        r.strokes = [s for s in (d.get("strokes") or []) if isinstance(s, dict)][:4000]
        for p in (d.get("looseProps") or []):
            if isinstance(p, dict) and p.get("id"):
                r.loose_props[p["id"]] = p
        for dr in (d.get("doors") or []):
            dd = sanitize_door(dr, dr.get("id"))
            if dd:
                r.doors[dd["id"]] = dd
        r.blocked_wizards = {str(b).lower() for b in (d.get("blockedWizards") or [])
                             if str(b).strip()}
        r.seeded = bool(d.get("seeded"))

        r.rid = str(d.get("rid") or d.get("id") or "") or uuid.uuid4().hex[:8]
        r.order = int(d.get("order") or 0)
        if d.get("script"):
            r.set_script(d["script"])
        return r

ROOMS: dict[str, Room] = {}
BANS = {"names": set(), "ips": set()}
LAST_PAGE = {"user_id": None, "room": None}
SERVER = {"stop": None}
OFFERS: dict[str, dict] = {}

ROOMS_FILE = dpath("palace_rooms.json")
BUILTIN_ROOMS = {"Lobby", "Lounge"}

def save_rooms():
    try:
        data = [r.to_dict() for r in ROOMS.values() if r.persistent]
        with open(ROOMS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("Could not save rooms:", e)

def load_rooms():
    try:
        with open(ROOMS_FILE, encoding="utf-8") as f:
            saved = json.load(f)
    except FileNotFoundError:
        return
    except Exception as e:
        print("Could not load rooms:", e)
        return
    for d in saved:
        name = d.get("name")
        if not name:
            continue
        was_template = name in ROOMS and getattr(ROOMS[name], "from_template", False)
        try:
            ROOMS[name] = Room.from_dict(d)
        except Exception as e:
            print(f"Room {name} could not be loaded:", e)
            continue
        if was_template:
            ROOMS[name].from_template = True

def link_doors_by_id():
    changed = 0
    for r in ROOMS.values():
        for d in (r.doors or {}).values():
            if d.get("targetId") or not d.get("target"):
                continue
            t = ROOMS.get(str(d["target"]))
            if t:
                d["targetId"] = t.room_id()
                changed += 1
    if changed:
        save_rooms()
        print(f"  {changed} door targets converted to IDs.")

def _starter_template():
    def door(pts, label, target=None, script="", fill="#a855f7"):
        return {"points": pts, "label": label, "target": target,
                "script": script, "fill": fill, "text": "#ffffff", "opacity": 0.4}
    back = lambda: door([[40, 470], [190, 470], [190, 520], [40, 520]],
                        "← back to Plaza", "Plaza", fill="#a855f7")
    return [
        {"name": "Plaza", "hidden": False, "bgFit": "fill", "drawAllowed": True,
         "script": 'ON ENTER { "Welcome to the Plaza! Click a door to move on." SAY }',
         "doors": [
            door([[110, 90], [320, 90], [320, 180], [110, 180]],
                 "🎬 Cinema – watch together", "Cinema", fill="#c77dff"),
            door([[360, 90], [560, 90], [560, 180], [360, 180]],
                 "🎨 Studio – paint together", "Studio", fill="#e0a63a"),
            door([[600, 90], [790, 90], [790, 180], [600, 180]],
                 "🛋 Lounge", "Lounge", fill="#a855f7"),
            door([[110, 220], [320, 220], [320, 310], [110, 310]],
                 "🖼 Gallery", "Gallery", fill="#8b5cf6"),
            door([[600, 240], [770, 235], [795, 330], [685, 385], [590, 320]],
                 "Your sign here", None,
                 script='"Interested in this space? Talk to the owner." SAY',
                 fill="#ff7ba9"),
         ]},
        {"name": "Cinema", "hidden": False, "drawAllowed": False,
         "script": 'ON ENTER { "Start a YouTube video from the MEDIA menu above – it plays in sync for everyone." SAY }',
         "doors": [back()]},
        {"name": "Studio", "hidden": False, "drawAllowed": True,
         "script": 'ON ENTER { "Let\'s go! Open the drawing tools below and draw together." SAY }',
         "doors": [back()]},
        {"name": "Gallery", "hidden": False, "drawAllowed": True,
         "script": 'ON ENTER { "Welcome to the gallery – drop pictures as loose props." SAY }',
         "doors": [back()]},
    ]

def load_room_templates():
    made = False
    try:
        files = [f for f in os.listdir(ROOM_TPL_DIR) if f.endswith(".json")]
    except FileNotFoundError:
        files = []
    if not files:
        for rm in _starter_template():
            try:
                fn = re.sub(r"[^\w\-]", "_", rm["name"]).lower() + ".json"
                with open(os.path.join(ROOM_TPL_DIR, fn), "w", encoding="utf-8") as f:
                    json.dump(rm, f, ensure_ascii=False, indent=2)
                files.append(fn)
            except Exception:
                pass
        made = True
    for fn in files:
        try:
            with open(os.path.join(ROOM_TPL_DIR, fn), encoding="utf-8") as f:
                d = json.load(f)
            name = d.get("name") or os.path.splitext(fn)[0]
            d["name"] = name
            d["persistent"] = True
            if name not in ROOMS:
                ROOMS[name] = Room.from_dict(d)
                ROOMS[name].from_template = True
        except Exception as e:
            print(f"Room template {fn} skipped:", e)
    if made:
        print(f"Starter rooms created in {ROOM_TPL_DIR}/ (Plaza, Cinema, Studio, Gallery)")

def default_rooms():
    ROOMS["Lobby"] = Room("Lobby", persistent=True)
    ROOMS["Lounge"] = Room("Lounge", persistent=True)
    ROOMS["Lobby"].set_script('ON ENTER { "Welcome to Pixplace, " ME & SAY }')
    load_room_templates()
    load_rooms()
    link_doors_by_id()

    bi = CONFIG.setdefault("builtin_ids", {})
    _ch = False
    for nm in list(BUILTIN_ROOMS) + ["Plaza"]:
        rid = bi.get(nm)
        if rid:
            known = room_by_ref(rid)
            dup = ROOMS.get(nm)
            if known and dup is not None and dup is not known \
                    and not dup.users and not dup.doors:
                ROOMS.pop(nm, None)
                _ch = True
        elif ROOMS.get(nm):
            bi[nm] = ROOMS[nm].room_id()
            _ch = True
    if _ch:
        save_config()
    if not CONFIG.get("start_room_id"):
        _sr = ROOMS.get("Lobby") or next(
            (r for r in ROOMS.values() if not r.hidden), None)
        if _sr:
            CONFIG["start_room_id"] = _sr.room_id()
            save_config()
    load_avatars()
    load_comments()
    load_groups()
    for _g in GROUPS.values():
        try: ensure_clan_room(_g, None)
        except Exception as e: print("Clan hall:", e)

    if "Plaza" in ROOMS:
        ROOMS["Plaza"].landing = True
        for nm in ("Lobby", "Lounge", "Gallery", "Studio", "Cinema"):
            if nm in ROOMS and not getattr(ROOMS[nm], "parent", ""):
                ROOMS[nm].parent = "Plaza"
        save_rooms()

    if "Plaza" in ROOMS:
        changed = False
        for nm in ("Lobby", "Lounge"):
            r = ROOMS.get(nm)
            if not r or getattr(r, "seeded", False):
                continue
            d = sanitize_door({"points": [[350, 380], [560, 380],
                                          [560, 470], [350, 470]],
                               "label": "→ To the Plaza", "target": "Plaza",
                               "fill": "#a855f7", "opacity": 0.42})
            if d:
                r.doors[d["id"]] = d
            r.seeded = True
            changed = True
        if changed:
            save_rooms()

def all_users():
    out = []
    for r in list(ROOMS.values()):
        out.extend(list(r.users.values()))
    return out

def find_user(query: str) -> User | None:
    q = query.strip().lstrip("*").lower()
    cands = list(all_users())
    for u in cands:
        if u.base.lower() == q:
            return u
    for u in cands:
        if u.base.lower().startswith(q):
            return u
    return None

SEND_TIMEOUT = 5.0

def _deliver_now(u: User, data: str) -> None:
    try:
        if not u.ws.enqueue(data):

            asyncio.create_task(u.ws.close())
    except Exception:
        pass

async def _deliver(u: User, data: str):
    _deliver_now(u, data)

async def send(u: User, msg: dict):
    await _deliver(u, json.dumps(msg, ensure_ascii=False))

async def broadcast(room: Room, msg: dict, skip: User | None = None):
    data = json.dumps(msg, ensure_ascii=False)
    for u in list(room.users.values()):
        if u is not skip:
            _deliver_now(u, data)

async def to_wizards(msg: dict):
    data = json.dumps(msg, ensure_ascii=False)
    for u in all_users():
        if u.rank >= RANK_WIZARD:
            _deliver_now(u, data)

def room_list():
    rows = [r.info() for r in ROOMS.values() if not r.hidden]
    landing = next((r for r in rows if r.get("landing")), None)

    def key(r):
        if landing and r["name"] == landing["name"]:
            return (0, "")
        if landing and r.get("parent") == landing["name"]:
            return (1, r["name"].lower())
        if r.get("group"):
            return (3, r["name"].lower())
        return (2, r["name"].lower())

    if any(r.get("order") for r in rows):
        rows.sort(key=lambda r: (r.get("order") or 10**6, key(r)))
    else:
        rows.sort(key=key)
    return rows

async def push_rooms():
    for u in all_users():
        await send(u, {"t": "rooms", "list": room_list()})

async def sysline(room: Room, text: str, key: str = "", **params):
    room.add_log("System", text)
    pack = {"t": "chat", "from": "System", "id": "sys",
            "rank": RANK_OWNER, "text": text, "system": True}
    if key:
        pack["key"] = key
        if params:
            pack["p"] = {k: str(v) for k, v in params.items()}
    await broadcast(room, pack)

async def run_event(event, user, room, chatstr=""):
    if not room or event not in room.handlers:
        return None
    ctx = SC(user, room, chatstr)
    try:
        if getattr(room, "script_lang", "legacy") == "pps":
            blocks = room.handlers.get(event) or []
            ran = False
            for blk in blocks:
                want = blk.get("match") or ""
                if want and want.lower() not in (chatstr or "").lower():
                    continue
                pps_run(blk.get("body") or [], ctx)
                ran = True
            if not ran:
                return None
        else:
            run_script(room.handlers[event], ctx, room.vars)
    except Exception as e:
        print("Skriptfehler in", room.name, ":", e)
        return None
    for line in ctx.toast[:3]:
        if user:
            await send(user, {"t": "sysmsg", "text": line})
    for line in ctx.whisper[:3]:
        if user:
            await send(user, {"t": "whisper", "from": "✦ " + room.name,
                              "id": "room", "to": user.id, "rank": 0,
                              "text": line})
    if ctx.points and user:

        last = getattr(user, "last_script_points", 0)
        if now_ms() - last >= 60_000:
            user.last_script_points = now_ms()
            add_clan_points(user.base, min(10, max(0, ctx.points)))
    for line in ctx.announce[:2]:
        g = group_of(user.base) if user else None
        if g:
            for u in all_users():
                if is_member(g, u.base):
                    await send(u, {"t": "groupChat", "from": "✦ " + room.name,
                                   "id": "room", "rank": 0, "text": line,
                                   "group": g["name"], "kind": group_kind(g),
                                   "logo": g.get("logo"), "tag": g.get("tag"),
                                   "room": room.name, "remote": False})
    for line in ctx.say[:5]:
        room.add_log("✦ " + room.name, line)
        await broadcast(room, {"t": "chat", "from": "✦ " + room.name,
                               "id": "room", "rank": 0, "text": line,
                               "system": True})
    if ctx.setpos and user and not user.pinned:
        user.x, user.y = ctx.setpos
        await broadcast(room, {"t": "move", "id": user.id, "x": user.x, "y": user.y})
    return ctx

async def leave_room(user: User, quitting: bool = False):
    room = user.room
    if not room:
        return
    room.users.pop(user.id, None)
    if hasattr(room, "yt_viewers"):
        room.yt_viewers.pop(user.id, None)
    user.room = None
    await broadcast(room, {"t": "leave", "id": user.id, "name": user.name})
    await run_event("LEAVE", user, room)
    if not user.hidden:

        await broadcast(room, {"t": "chat", "id": "room", "from": "System",
                               "rank": 0, "sys": True,
                               "event": "signoff" if quitting else "leave",
                               "text": (f"{user.base} is now offline."
                                        if quitting else
                                        f"{user.base} left the room.")},
                        skip=user)
    mod_log(room.name, user.base, "SIGNOFF" if quitting else "LEAVE",
            "signed off (offline)" if quitting else "leaves room")

    if (room.operatorsonly and room.owner == user.id
            and room.name not in BUILTIN_ROOMS):
        room.operatorsonly = False
        await broadcast(room, {"t": "roomLock", "on": False,
                               "by": "(Ersteller verlassen)"})
        await sysline(room, "🔓 Room open")
        mod_log(room.name, user.base, "ROOM-LOCK",
                "opened automatically (creator left)")
        await push_rooms()
    await push_presence()

    if (room.name not in BUILTIN_ROOMS and not room.persistent
            and not room.users):
        ROOMS.pop(room.name, None)
        await push_rooms()

async def join_room(user: User, name: str, password=None):

    room = room_by_ref(name)
    if not room:
        return await send(user, {"t": "error", "msg": f"Room {name} does not exist."})
    if room.operatorsonly and user.rank < RANK_WIZARD:
        return await send(user, {"t": "error", "code": "locked",
                                 "msg": "🔒 Room locked"})

    g_room = group_by_room(room.name)
    if g_room and not is_member(g_room, user.base) \
            and not g_room.get("roomPublic") and user.rank < RANK_WIZARD:
        return await send(user, {"t": "error",
                                 "msg": f"\"{room.name}\" is for members only "
                                        f"of {group_kind(g_room)} "
                                        f"\"{g_room['name']}\"."})
    if room.password and password != room.password and user.rank < RANK_WIZARD \
            and user.id != room.owner:
        return await send(user, {"t": "error", "msg": "Wrong password.",
                                 "code": "pw", "room": name})
    await leave_room(user)
    user.room = room
    if not user.pinned:
        user.x = 120 + int(uuid.uuid4().int % 560)
        user.y = 260 + int(uuid.uuid4().int % 220)
    room.users[user.id] = user
    await send(user, {
        "t": "joined",
        "room": {"name": room.name, "bg": room.bg, "bgFit": room.bg_fit,
                 "roomW": room.room_w, "roomH": room.room_h,
                 "hidden": room.hidden,
                 "operatorsonly": room.operatorsonly,
                 "owner": room.owner == user.id,
                 "persistent": room.persistent,
                 "permRequested": room.perm_requested,
                 "isOwner": room.owner == user.id,
                 "script": room.script_src if (user.id == room.owner or
                                               user.rank >= RANK_WIZARD) else ""},
        "users": [u.public() for u in room.users.values()
                  if not u.hidden or user.rank >= RANK_WIZARD],
        "looseProps": list(room.loose_props.values()),
        "looseAllowed": room.loose_allowed,
        "doors": list(room.doors.values()),
        "clanStats": clan_stats(group_by_room(room.name)),
        "locked": bool(room.operatorsonly),
        "canLock": may_lock_room(user, room),
        "drawAllowed": room.draw_allowed,
        "strokes": room.strokes[-2000:],
        "you": user.id, "yt": room.yt_now(),
        "ytAuto": bool(room.yt.get("shared") and room.yt.get("videoId")),
        "points": user_points(user),
        "ytViewers": [{"id": i, "name": v["name"], "mode": v.get("mode", "video")}
                      for i, v in getattr(room, "yt_viewers", {}).items()
                      if i in room.users]})
    await broadcast(room, {"t": "join", "user": user.public()}, skip=user)

    first = not getattr(user, "signed_on", False)
    user.signed_on = True

    _g = group_of(user.base)
    if first and _g and perk_active(_g, "onlinecall") and not user.hidden:

        recruiting = group_policy(_g) in ("open", "request")
        pack = {"t": "chat", "id": "room", "from": "System",
                "rank": 0, "sys": True, "event": "guildcall",
                "group": _g["name"],
                "text": f"📣 {rank_label(_g, user.base)} {user.base} of "
                        f"{group_kind(_g)} \"{_g['name']}\" is online."
                        + (" – open to join." if recruiting else "")}
        for u2 in list(room.users.values()):
            if u2.id == user.id:
                continue
            if recruiting or is_member(_g, u2.base):
                await send(u2, pack)
    if not user.hidden:
        await broadcast(room, {"t": "chat", "id": "room", "from": "System",
                               "rank": 0, "sys": True,
                               "event": "signon" if first else "enter",
                               "text": (f"{user.base} is online." if first
                                        else f"{user.base} entered the room.")},
                        skip=user)
    mod_log(room.name, user.base, "SIGNON" if first else "JOIN",
            f"{'signed on' if first else 'enters room'} "
            f"(ip={safe_ip(getattr(user, 'ip', None))}"
            f"{', member' if user.account else ''})")
    await push_presence()
    ctx = await run_event("ENTER", user, room)
    if CONFIG["autoannounce"]:
        await send(user, {"t": "chat", "from": "System", "id": "sys",
                          "rank": RANK_OWNER, "text": CONFIG["autoannounce"],
                          "system": True})
    if ctx and ctx.goto and ctx.goto in ROOMS:
        await join_room(user, ctx.goto, ROOMS[ctx.goto].password)

CMD_PREFIX = "::"

def is_command(text: str) -> bool:
    if text.startswith(CMD_PREFIX) and len(text) > len(CMD_PREFIX):
        return True
    return len(text) > 1 and text[0] in "`'/~"

def strip_cmd_prefix(text: str) -> str:
    if text.startswith(CMD_PREFIX):
        return text[len(CMD_PREFIX):]
    return text[1:]

async def notify(u: User, text: str, key: str = "", **params):
    pack = {"t": "sysmsg", "text": text}
    if key:
        pack["key"] = key
        if params:
            pack["p"] = {k: str(v) for k, v in params.items()}
    await send(u, pack)

async def cmd_kill(actor, target, room, arg):
    await send(target, {"t": "killed", "msg": f"You were disconnected by {actor.name}."})
    await notify(actor, f"{target.name} was disconnected (kill).")
    await asyncio.sleep(0.05)
    try:
        await target.ws.close()
    except Exception:
        pass

async def handle_command(user: User, text: str):
    parts = strip_cmd_prefix(text).strip().split(None, 1)
    if not parts:
        return
    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    room = user.room
    R = user.rank

    if cmd == "help":
        base = ["::help",
                "::name <neu>", "::goto <raum>", "::who", "::roomid",
                "::makepermanent  (make room permanent – wizard approves)",
                "::rmsg <text>", "::hide", "::unhide", "::mute <user>",
                "::unmute <user>", "::page <text>", "::clean",
                "::offer <user>   (offer your own avatar)",
                "::invite <user>  (invite to guild/clan, officer and up)",
                "::accept / ::decline  (answer an offer or invitation)",
                "::gc <text>      (guild/clan chat, members only)",
                "::newroom <name> [password]  (own temporary room)",
                "::showroom / ::hideroom      (make your own room visible/hidden)"]
        wiz = ["::list", "::glist", "::gag/`ungag <user>",
               "::propgag/`unpropgag <user>", "::pin/`unpin <user>",
               "::kill <user>", "::er", "::repage <text>", "::announce <text>",
               "::requests", "::approve <raum>", "::deny <raum>"]
        own = ["::grant <user> member|wizard|owner|user  (permanent)",
               "::delroom <room>  (delete a saved room)",
               "::ban/`unban <user>",
               "::banlist", "::gmsg <text>", "::operatorsonly on|off",
               "::servername <name>", "::ownerpass <pw>", "::wizardpass <pw>",
               "::moderation on|off", "::shutdown",
               "Admin web interface: /admin"]

        g = group_of(user.base)
        grp = []
        if g:
            kind = group_kind(g)
            grp = [f"— {kind} \"{g['name']}\" (members only) —",
                   "::gc <text>        group chat",
                   "::ginfo            group stats",
                   "::gwho             who is online",
                   "::ghall            go to your hall",
                   "::gleave           leave the group"]
            if has_perm(g, user.base, "invite"):
                grp.append("::invite <user>    invite")
            if has_perm(g, user.base, "approve"):
                grp += ["::grequests        open requests",
                        "::gaccept <user>   accept request",
                        "::gdeny <user>     decline request"]
            if has_perm(g, user.base, "kick"):
                grp.append("::gkick <user>     remove from group")
            if has_perm(g, user.base, "ranks"):
                grp.append("::grank <user> <rank>   assign rank")
            if has_perm(g, user.base, "blurb"):
                grp.append("::gblurb <text>    set promo text")
            if has_perm(g, user.base, "announce"):
                grp.append("::gann <text>      announce to all members")
        lines = ["— Commands for everyone —"] + base
        if grp:
            lines += [""] + grp
        if R >= RANK_WIZARD:
            lines += ["", "— Wizard —"] + wiz + [
                "::sannounce <text>  announcement in ALL rooms",
                "::roomvis           room visible/hidden"]
        if R >= RANK_OWNER:
            lines += ["", "— Owner —"] + own + [
                "::gjoin <group>     put yourself into a group",
                "::gpart             remove yourself from the group",
                "::gforcerank <user> <rank>   set rank (no limits)",
                "::glistall          all groups with treasury and points",
                "::grename <group> <new>      rename group",
                "::gdelete <group>            dissolve group",
                "::gbank <group> <n>          add points to the treasury",
                "::gbanktake <group> <n>      take points from the treasury",
                "::gbankset <gruppe> <n>      Kassenstand festsetzen",
                "::points <user> <n>          points to a person",
                "::names                      show reserved names",
                "::freename <name>            release a name again"]
        return await notify(user, "\n".join(lines))

    if cmd in ("owner", "wizard") and not arg:

        return await send(user, {"t": "authPrompt", "role": cmd})
    if cmd == "login":
        role = arg.lower().strip()
        if role in ("owner", "wizard"):
            return await send(user, {"t": "authPrompt", "role": role})
        return await notify(user, "Usage: `login owner   or   `login wizard")

    if cmd in ("makepermanent", "requestpermanent", "keep"):
        if not room:
            return
        if room.name in BUILTIN_ROOMS or room.persistent:
            return await notify(user, "This room is already permanent.")
        if room.owner not in (None, user.id) and user.rank < RANK_WIZARD:
            return await notify(user, "Only the room creator can request this.")
        room.perm_requested = True
        await to_wizards({"t": "permRequest", "room": room.name,
                          "by": user.name,
                          "text": f"📌 {user.name} asks to make the room "
                                  f"\"{room.name}\" permanent."})
        await broadcast(room, {"t": "roomstate", "persistent": room.persistent,
                               "permRequested": True})
        return await notify(user, "Request sent to the wizards. A wizard "
                                  "can now make the room permanent.")

    if cmd == "name":
        newbase = clean_base_name(arg)
        if not newbase:
            return await notify(user, "Usage: ::name <new name>")

        if not name_free(newbase, user.account):
            return await notify(user, f"The name \"{newbase}\" is already "
                                      f"taken.")

        if any(u is not user and u.base.lower() == newbase.lower()
               for u in all_users()):
            return await notify(user, f"\"{newbase}\" is currently in use.")
        oldbase = user.base
        if user.account:

            key = user.account["username"].lower()
            acc = ACCOUNTS.get(key)
            if acc:

                release_name(acc, oldbase)
                hold_name(acc, newbase)
                acc["username"] = newbase
                ACCOUNTS.pop(key, None)
                ACCOUNTS[newbase.lower()] = acc
                user.account = acc
                save_accounts()

            moved = rename_everywhere(oldbase, newbase)
            mod_log(room.name if room else "-", oldbase, "MEMBER-RENAME",
                    f"'{oldbase}' → '{newbase}'"
                    + (" | mitgezogen: " + ", ".join(moved) if moved else ""))
        user.base = newbase
        mod_log(room.name if room else "-", oldbase, "RENAME",
                f"'{oldbase}' → '{newbase}' (ip={safe_ip(getattr(user, 'ip', None))})")
        if room:
            await broadcast(room, {"t": "rename", "id": user.id,
                                   "name": user.name, "base": user.base})
            await broadcast(room, {"t": "chat", "id": "room", "from": "System",
                                   "rank": 0, "sys": True, "event": "rename",
                                   "text": f"{oldbase} is now called {newbase}."})
        return await notify(user, f"You are now called {user.name}.")

    if cmd in ("goto", "g"):
        if arg in ROOMS:
            return await join_room(user, arg, ROOMS[arg].password)
        return await notify(user, f"No room named {arg}.")

    if cmd == "roomid":
        return await notify(user, f"Current room: {room.name if room else '—'}")

    if cmd in ("who", "users"):
        if not room:
            return
        names = ", ".join(u.name for u in room.users.values())
        return await notify(user, f"In the room ({len(room.users)}): {names}")

    if cmd == "rmsg":
        if room and arg:
            return await broadcast(room, {"t": "chat", "from": user.name,
                                          "id": user.id, "rank": user.rank,
                                          "text": arg, "system": True})
        return

    if cmd == "hide":
        user.hidden = True
        if room:
            await broadcast(room, {"t": "leave", "id": user.id,
                                   "name": user.name})
        return await notify(user, "You are now hidden.")
    if cmd == "unhide":
        user.hidden = False
        if room:
            await broadcast(room, {"t": "join", "user": user.public()}, skip=user)
        return await notify(user, "You are visible again.")

    if cmd.startswith("g") and cmd in (
            "ginfo", "gwho", "ghall", "gleave", "grequests", "gaccept",
            "gdeny", "gkick", "grank", "gblurb", "gann", "gjoin", "gpart",
            "gforcerank"):
        g = group_of(user.base)

        if cmd == "gjoin":
            if R < RANK_OWNER:
                return await notify(user, "Owner only.", "msg.owneronly")
            tg = GROUPS.get(arg) or next((x for x in GROUPS.values()
                                          if x["name"].lower() == arg.lower()), None)
            if not tg:
                return await notify(user, "Group not found.", "msg.groupnotfound")
            if g:
                g["members"] = [m for m in g.get("members", [])
                                if m.lower() != user.base.lower()]
            tg.setdefault("members", []).append(user.base)
            tg.setdefault("ranks", {})[user.base.lower()] = "Founder"
            save_groups()
            await broadcast_group_change(user)
            await broadcast_group_update(tg)
            mod_log(room.name if room else "-", user.base, "OWNER-GJOIN", tg["name"])
            return await notify(user, f"You are now in \"{tg['name']}\".")
        if cmd == "gpart":
            if R < RANK_OWNER:
                return await notify(user, "Owner only.", "msg.owneronly")
            if not g:
                return await notify(user, "You are not in a group.", "msg.nogroup2")
            nm = g["name"]
            g["members"] = [m for m in g.get("members", [])
                            if m.lower() != user.base.lower()]
            (g.get("ranks") or {}).pop(user.base.lower(), None)
            save_groups()
            await broadcast_group_change(user)
            await broadcast_group_update(g)
            mod_log(room.name if room else "-", user.base, "OWNER-GPART", nm)
            return await notify(user, f"You left \"{nm}\".")
        if cmd == "gforcerank":
            if R < RANK_OWNER:
                return await notify(user, "Owner only.", "msg.owneronly")
            p = arg.split()
            if len(p) < 2 or not g:
                return await notify(user, "Usage: ::gforcerank <user> <rank>")
            who, rk = p[0], " ".join(p[1:])
            if rk not in CLAN_RANKS:
                return await notify(user, "Ranks: " + ", ".join(CLAN_RANKS))
            g.setdefault("ranks", {})[who.lower()] = rk
            if not is_member(g, who):
                g.setdefault("members", []).append(who)
            save_groups()
            await broadcast_group_update(g)
            for u in all_users():
                if u.base.lower() == who.lower():
                    await broadcast_group_change(u)
            return await notify(user, f"{who} is now {rk}.")

        if not g:
            return await notify(user, "You are not in a guild or clan.", "msg.nogroup")

        hall_only = ("grequests", "gaccept", "gdeny", "gkick", "grank",
                     "gblurb", "gann")
        if cmd in hall_only:
            in_hall = bool(room and (g.get("room") or "").lower()
                           == room.name.lower())
            if not in_hall and R < RANK_OWNER:
                return await notify(user, f"This only works in \"{g.get('room')}\" "
                                          f"– your own hall.")

        if cmd == "ginfo":
            st = clan_stats(g)
            ren = clan_renown(g)
            cur, nxt = clan_tier(ren["total"])
            parts = " · ".join(f"{k} {v}" for k, v in ren["parts"].items() if v)
            txt = (f"{group_kind(g)} \"{g['name']}\" · Tier {cur[1]}\n"
                   f"Renown {ren['total']}  ({parts})\n"
                   f"Members {st['members']}/{group_slots(g)} · "
                   f"online {st['online']} · Treasury {int(g.get('bank', 0))} 🪙 · "
                   f"Online time {st['minutes']} min\n"
                   f"Join: {group_policy(g)} · Hall: {g.get('room') or '—'}"
                   + (" (public)" if g.get("roomPublic") else " (members only)"))
            if nxt:
                txt += f"\nNext tier \"{nxt[1]}\" at {nxt[0]} renown."
            return await notify(user, txt)
        if cmd == "gwho":
            on = [u.base + " (" + rank_label(g, u.base) + ")"
                  for u in all_users() if is_member(g, u.base)]
            return await notify(user, "Online: " + (", ".join(on) or "niemand"))
        if cmd == "ghall":
            rn = g.get("room")
            if rn and rn in ROOMS:
                return await join_room(user, rn, ROOMS[rn].password)
            return await notify(user, "This group has no hall.", "msg.group.nohall")
        if cmd == "gleave":
            return await handle(user, {"t": "groupLeave"})
        if cmd == "grequests":
            return await handle(user, {"t": "groupRequests"})
        if cmd == "gaccept":
            return await handle(user, {"t": "groupApprove", "member": arg})
        if cmd == "gdeny":
            return await handle(user, {"t": "groupDeny", "member": arg})
        if cmd == "gkick":
            return await handle(user, {"t": "groupKick", "member": arg})
        if cmd == "grank":
            p = arg.split()
            if len(p) < 2:
                return await notify(user, "Usage: ::grank <user> <rank>")
            return await handle(user, {"t": "groupRank", "member": p[0],
                                       "rank": " ".join(p[1:])})
        if cmd == "gblurb":
            return await handle(user, {"t": "groupBlurb", "text": arg})
        if cmd == "gann":
            return await handle(user, {"t": "groupAnnounce", "text": arg})

    if cmd in ("gbank", "gbankset", "gbanktake") and R >= RANK_OWNER:

        p = arg.rsplit(None, 1)
        if len(p) < 2:
            return await notify(user, f"Usage: ::{cmd} <group> <amount>")
        mode = {"gbank": "add", "gbankset": "set", "gbanktake": "take"}[cmd]
        return await handle(user, {"t": "groupBank", "group": p[0],
                                   "amount": p[1], "mode": mode})

    if cmd == "grename" and R >= RANK_OWNER:

        p = arg.rsplit(None, 1)
        if len(p) < 2:
            return await notify(user, "Usage: ::grename <group> <new name>")
        return await handle(user, {"t": "groupRename", "group": p[0],
                                   "name": p[1]})

    if cmd == "gdelete" and R >= RANK_OWNER:
        if not arg:
            return await notify(user, "Usage: ::gdelete <group>")
        return await handle(user, {"t": "groupDelete", "name": arg})

    if cmd == "glistall" and R >= RANK_OWNER:
        if not GROUPS:
            return await notify(user, "There are no groups yet.")
        rows = [f"{g['name']} ({group_kind(g)}) · "
                f"{len(g.get('members', []))} Mitgl. · "
                f"Treasury {int(g.get('bank', 0))} · "
                f"gesamt {int(g.get('total', 0))} · "
                f"Founder {g.get('owner') or '—'}"
                for g in GROUPS.values()]
        return await notify(user, "Groups:\n" + "\n".join(rows))

    if cmd in ("freename", "namefree") and R >= RANK_OWNER:
        if not arg:
            return await notify(user, "Usage: ::freename <name>")
        holder = name_owner(arg)
        if not holder:
            return await notify(user, f"\"{arg}\" is already free.")
        acc = ACCOUNTS.get(holder)
        if acc and (acc.get("username") or "").lower() == arg.lower():
            return await notify(user, f"\"{arg}\" is the main name of "
                                      f"\"{holder}\" – rename it there first.")

        online = any(u.base.lower() == arg.lower() for u in all_users())
        release_name(arg)
        mod_log(room.name if room else "-", user.base, "NAME-FREE", arg)
        if online:
            await notify(user, f"Note: \"{arg}\" is currently in use – "
                               f"the name is freed only after logout.")
        return await notify(user, f"Name \"{arg}\" is free again.")

    if cmd == "names" and R >= RANK_OWNER:
        rows = []
        for k, acc in ACCOUNTS.items():
            held = acc.get("heldNames") or []
            extra = " (+ " + ", ".join(held) + ")" if held else ""
            rows.append(f"{acc.get('username')}{extra}")
        return await notify(user, "Reserved names:\n" +
                                  ("\n".join(rows) if rows else "none"))

    if cmd == "points" and R >= RANK_OWNER:
        p = arg.split()
        if len(p) < 2:
            return await notify(user, "Usage: ::points <user> <amount>")
        return await handle(user, {"t": "grantPoints", "member": p[0],
                                   "amount": p[1]})

    if cmd in ("afk", "idle", "away"):
        return await handle(user, {"t": "idle", "on": True, "text": arg})
    if cmd in ("back",):
        return await handle(user, {"t": "idle", "on": False})

    if cmd in ("newroom", "raum"):

        parts2 = arg.split()
        if not parts2:
            return await notify(user, "Usage: ::newroom <name> [password]")
        nm = " ".join(parts2[:-1]) if len(parts2) > 1 else parts2[0]
        pw = parts2[-1] if len(parts2) > 1 else None
        return await handle(user, {"t": "createRoom", "room": nm, "password": pw})

    if cmd in ("roomvis", "showroom", "hideroom"):

        if not room:
            return
        if not (room.owner == user.id or user.rank >= RANK_WIZARD):
            return await notify(user, "Only the room creator "
                                      "or a wizard can do that.")
        if cmd == "showroom":
            room.hidden = False
        elif cmd == "hideroom":
            room.hidden = True
        else:
            room.hidden = not room.hidden
        if room.persistent:
            save_rooms()
        await push_rooms()
        mod_log(room.name, user.base, "ROOM-VIS",
                "hidden" if room.hidden else "visible")
        await broadcast(room, {"t": "roomVis", "hidden": room.hidden})
        return await notify(user, "Room is now " +
                                  ("hidden 🕶" if room.hidden else "visible 👁"))

    if cmd in ("offer", "avatar"):

        t = find_user(arg)
        if not t or t.id == user.id:
            return await notify(user, "Benutze: ::offer <Name>")
        if not valid_media_url(user.avatar):
            return await notify(user, "You have no avatar to offer.")
        oid = uuid.uuid4().hex[:10]
        OFFERS[oid] = {"kind": "avatar", "from": user.id, "fromName": user.base,
                       "to": t.id, "url": user.avatar, "ts": now_ms()}
        await send(t, {"t": "avatarOffer", "offerId": oid, "from": user.base,
                       "fromId": user.id, "url": user.avatar})
        await notify(t, f"🎭 {user.base} offers you an avatar "
                        f"(::accept or ::decline).")
        return await notify(user, f"Avatar offered to {t.base}.")

    if cmd in ("accept", "decline"):

        mine = [(k, v) for k, v in OFFERS.items() if v.get("to") == user.id]
        if not mine:
            return await notify(user, "Nothing is pending for you.")
        oid, off = max(mine, key=lambda kv: kv[1].get("ts", 0))
        kind = off.get("kind")
        act = ("Accept" if cmd == "accept" else "Decline")
        fake = {"offerId": oid}
        if kind == "avatar":
            return await handle(user, {"t": "avatar" + act, **fake})
        if kind == "invite":
            return await handle(user, {"t": "invite" + act, **fake})
        return await notify(user, "Unknown offer.")

    if cmd == "invite":

        t = find_user(arg)
        if not t:
            return await notify(user, "Benutze: ::invite <Name>")
        return await handle(user, {"t": "groupInvite", "to": t.id})

    if cmd in ("gc", "clan", "guild"):
        return await handle(user, {"t": "groupSay", "text": arg})

    if cmd == "mute":
        t = find_user(arg)
        if t:
            user.muted.add(t.id)
            await send(user, {"t": "muted", "id": t.id, "on": True, "name": t.base})
            return await notify(user, f"{t.name} muted (picture & chat, for you only).")
        return await notify(user, "User not found.")
    if cmd == "unmute":
        t = find_user(arg)
        if t and t.id in user.muted:
            user.muted.discard(t.id)
            await send(user, {"t": "muted", "id": t.id, "on": False, "name": t.base})
            return await notify(user, f"{t.name} is no longer muted.")
        return

    if cmd == "page":
        LAST_PAGE["user_id"] = user.id
        LAST_PAGE["room"] = room.name if room else None
        await to_wizards({"t": "sysmsg",
                          "text": f"📟 Page from {user.name}"
                                  f"{' in '+room.name if room else ''}: {arg}"})
        return await notify(user, "Your page was sent to the wizards.")

    if cmd == "clean":
        if room:
            await broadcast(room, {"t": "clean"})
        return

    WIZ = {"list", "glist", "gag", "ungag", "propgag", "unpropgag",
           "pin", "unpin", "kill", "er", "repage", "announce",
           "approve", "deny", "requests"}
    OWN = {"wizard", "unwizard", "grant", "ban", "unban", "banlist", "gmsg",
           "operatorsonly", "servername", "ownerpass", "wizardpass",
           "moderation", "delroom", "shutdown"}

    if cmd in WIZ and not can(user, "moderate"):
        return await notify(user, "You lack the moderation right for that.")
    if cmd in OWN and R < RANK_OWNER:
        return await notify(user, "This command is for owners only.")

    if cmd in ("list", "glist"):
        scope = room.users.values() if cmd == "list" and room else all_users()
        rows = [f"[{RANK_STAR[u.rank] or '·'}] {u.base}  "
                f"({RANK_NAME[u.rank]}, ip {u.ws.ip})"
                + ("  GAG" if u.gagged else "") + ("  PIN" if u.pinned else "")
                for u in scope]
        return await notify(user, "\n".join(rows) or "(empty)")

    if cmd in ("gag", "ungag", "propgag", "unpropgag", "pin", "unpin", "kill"):
        target = find_user(arg)
        if not target:
            return await notify(user, "User not found.")
        if target.rank >= R and target is not user:
            return await notify(user, "You cannot discipline anyone of equal or higher rank.")

        mod_log(room.name if room else "-", user.base, "MOD-" + cmd.upper(),
                f"against \"{target.base}\"")
        if cmd == "gag":
            target.gagged = True; await notify(user, f"{target.name} is gagged.")
            await notify(target, "You have been gagged and cannot speak.")
            if target.room:
                await broadcast(target.room, {"t": "gagged", "id": target.id, "on": True})
        elif cmd == "ungag":
            target.gagged = False; await notify(user, f"{target.name} may speak again.")
            await notify(target, "Your gag was removed.")
            if target.room:
                await broadcast(target.room, {"t": "gagged", "id": target.id, "on": False})
        elif cmd == "propgag":
            target.propgagged = True
            if target.room:
                await broadcast(target.room, {"t": "props", "id": target.id, "props": []})
            await notify(user, f"{target.name}'s props were taken away.")
        elif cmd == "unpropgag":
            target.propgagged = False
            if target.room:
                await broadcast(target.room, {"t": "props", "id": target.id,
                                              "props": target.props})
            await notify(user, f"{target.name} may wear props again.")
        elif cmd == "pin":
            target.pinned = True; target.x, target.y = 40, 60
            if target.room:
                await broadcast(target.room, {"t": "move", "id": target.id,
                                              "x": 40, "y": 60})
                await broadcast(target.room, {"t": "pinned", "id": target.id, "on": True})
            await notify(user, f"{target.name} is pinned.")
        elif cmd == "unpin":
            target.pinned = False
            if target.room:
                await broadcast(target.room, {"t": "pinned", "id": target.id, "on": False})
            await notify(user, f"{target.name} is released.")
        elif cmd == "kill":
            await cmd_kill(user, target, room, arg)
        return

    if cmd == "er":
        if LAST_PAGE["room"] and LAST_PAGE["room"] in ROOMS:
            await to_wizards({"t": "sysmsg",
                              "text": f"{user.name} is handling the last page."})
            return await join_room(user, LAST_PAGE["room"])
        return await notify(user, "No open page.")

    if cmd == "repage":
        t = users_by_id(LAST_PAGE["user_id"])
        if t:
            await send(t, {"t": "sysmsg", "text": f"↩ {user.name} (Wizard): {arg}"})
            await to_wizards({"t": "sysmsg",
                              "text": f"{user.name} replied to the page."})
            return await notify(user, "Reply sent.")
        return await notify(user, "The page sender is no longer online.")

    if cmd == "announce":
        if R < RANK_WIZARD:
            return await notify(user, "Wizards and owners only.", "msg.wizonly")
        return await handle(user, {"t": "announce", "text": arg, "scope": "room"})

    if cmd in ("sannounce", "serverannounce"):
        if R < RANK_WIZARD:
            return await notify(user, "Wizards and owners only.", "msg.wizonly")
        return await handle(user, {"t": "announce", "text": arg, "scope": "all"})

    if cmd == "requests":
        pend = [r.name for r in ROOMS.values() if r.perm_requested]
        return await notify(user, "Open requests: " + (", ".join(pend) or "none"))

    if cmd in ("approve", "deny"):
        target = ROOMS.get(arg.strip()) or (room if not arg else None)
        if not target:
            return await notify(user, "Usage: `approve <room>  (room not found)")
        if target.name in BUILTIN_ROOMS:
            return await notify(user, "Default rooms are already permanent.")
        if cmd == "approve":
            target.persistent = True
            target.perm_requested = False
            save_rooms()
            await broadcast(target, {"t": "roomstate", "persistent": True,
                                     "permRequested": False})
            await sysline(target, f"📌 Room was made permanent by {user.name}.")
            return await notify(user, f"Room \"{target.name}\" is now permanent.")
        else:
            target.perm_requested = False
            await broadcast(target, {"t": "roomstate",
                                     "persistent": target.persistent,
                                     "permRequested": False})
            return await notify(user, f"Request for \"{target.name}\" declined.")

    if cmd == "gmsg":
        if not arg:
            return await notify(user, "Usage: ::gmsg <text>")
        for u in all_users():
            await send(u, {"t": "chat", "from": "System", "id": "sys",
                           "rank": RANK_OWNER, "text": "📢 " + arg,
                           "system": True, "sys": True, "event": "gmsg"})
        mod_log(room.name if room else "-", user.base, "GMSG", arg)
        return await notify(user, "Server message sent.", "msg.gmsg.sent")

    if cmd == "grant":

        p = arg.rsplit(None, 1)
        if len(p) != 2:
            return await notify(user, "Usage: `grant <user> user|member|wizard|owner")
        who, role = p[0].strip().lstrip("*"), p[1].lower()
        rank = {"user": RANK_USER, "member": RANK_MEMBER,
                "wizard": RANK_WIZARD, "owner": RANK_OWNER}.get(role)
        if rank is None:
            return await notify(user, "Role: user, member, wizard or owner.")
        if rank == RANK_USER:
            CONFIG["grants"].pop(who.lower(), None)
        else:
            CONFIG["grants"][who.lower()] = rank
        save_config()
        tgt = find_user(who)
        if tgt:
            tgt.rank = rank
            await send(tgt, {"t": "rank", "rank": rank,
                             "rankName": RANK_NAME[rank], "name": tgt.name,

                          **({"docKey": doc_token_new()}
                                if rank >= RANK_WIZARD else {})})
            if tgt.room:
                await broadcast(tgt.room, {"t": "rename", "id": tgt.id,
                                           "name": tgt.name, "base": tgt.base,
                                           "rank": rank})
        return await notify(user, f"{who} → {RANK_NAME[rank]} (saved permanently).")

    if cmd == "moderation":
        CONFIG["moderation_logging"] = arg.lower() in ("on", "1", "true")
        save_config()
        return await notify(user, f"Moderation logging = "
                                  f"{CONFIG['moderation_logging']}")

    if cmd == "delroom":
        name = arg.strip()
        if name in BUILTIN_ROOMS:
            return await notify(user, "Default rooms cannot be deleted.")
        rm = ROOMS.get(name)
        if not rm:
            return await notify(user, f"No room named {name}.")
        mod_log(name, user.base, "ROOM-DELETE",
                f"{len(rm.users)} present users moved to the lobby")
        for u in list(rm.users.values()):
            await join_room(u, start_room())
        ROOMS.pop(name, None)
        save_rooms()
        await push_rooms()
        return await notify(user, f"Room {name} deleted.")

    if cmd in ("wizard", "unwizard"):
        target = find_user(arg)
        if not target:
            return await notify(user, "User not found.")
        mod_log("-", user.base,
                "GRANT-WIZARD" if cmd == "wizard" else "REVOKE-WIZARD",
                f"\"{target.base}\" (previous rank {target.rank})")
        target.rank = RANK_WIZARD if cmd == "wizard" else RANK_USER

        if cmd == "wizard":
            CONFIG["grants"][target.base.lower()] = RANK_WIZARD
        else:
            CONFIG["grants"].pop(target.base.lower(), None)
        save_config()
        await send(target, {"t": "rank", "rank": target.rank,
                            "rankName": RANK_NAME[target.rank], "name": target.name,
                            **({"docKey": doc_token_new()}
                               if target.rank >= RANK_WIZARD else {})})
        if target.room:
            await broadcast(target.room, {"t": "rename", "id": target.id,
                                          "name": target.name, "base": target.base,
                                          "rank": target.rank})
        return await notify(user, f"{target.base} is now {RANK_NAME[target.rank]} "
                                  f"(saved permanently).")

    if cmd == "ban":
        target = find_user(arg)
        if target:
            mod_log(room.name if room else "-", user.base, "BAN",
                    f"\"{target.base}\" (name + IP {safe_ip(target.ws.ip)})")
            BANS["names"].add(target.base.lower()); BANS["ips"].add(target.ws.ip)
            await cmd_kill(user, target, room, arg)
            return await notify(user, f"{target.base} banned (name + IP).")
        mod_log("-", user.base, "BAN", f"\"{arg}\" (name only, not online)")
        BANS["names"].add(arg.lower().lstrip("*"))
        return await notify(user, f"{arg} banned.")
    if cmd == "unban":
        mod_log("-", user.base, "UNBAN", f"'{arg}'")
        a = arg.lower().lstrip("*")
        BANS["names"].discard(a); BANS["ips"].discard(arg)
        return await notify(user, f"Ban for {arg} lifted.")
    if cmd == "banlist":
        return await notify(user, "Banned names: " +
                            (", ".join(sorted(BANS["names"])) or "—") +
                            "\nBanned IPs: " + (", ".join(sorted(BANS["ips"])) or "—"))

    if cmd == "operatorsonly":
        if room:
            room.operatorsonly = arg.lower() in ("on", "1", "true")
            if room.persistent:
                save_rooms()
            await push_rooms()
            return await notify(user, f"operatorsonly = {room.operatorsonly}")
        return
    if cmd == "servername":
        CONFIG["servername"] = arg[:40] or CONFIG["servername"]
        return await notify(user, f"Servername: {CONFIG['servername']}")
    if cmd == "ownerpass":
        CONFIG["owner_pass"] = arg; save_config()
        return await notify(user, "Owner password changed.")
    if cmd == "wizardpass":
        CONFIG["wizard_pass"] = arg; save_config()
        return await notify(user, "Wizard password changed.")
    if cmd == "shutdown":
        for u in all_users():
            await send(u, {"t": "chat", "from": "📢 Server", "id": "sys",
                           "rank": RANK_OWNER, "text": "Server is shutting down.",
                           "system": True})
        if SERVER["stop"] and not SERVER["stop"].done():
            SERVER["stop"].set_result(True)
        return

    await notify(user, f"Unknown command: ::{cmd}  (::help for a list)")

def users_by_id(uid):
    for u in all_users():
        if u.id == uid:
            return u
    return None

def valid_media_url(u):
    return (isinstance(u, str) and ".." not in u
            and (u.startswith("/media/") or u.startswith("/avatar/")))

DOOR_ACTIONS = ("lock", "clanstats")

def sanitize_door(d: dict, existing_id=None) -> dict | None:
    if not isinstance(d, dict):
        return None
    clean = []
    for p in (d.get("points") or [])[:16]:
        try:
            clean.append([max(0, min(2000, int(p[0]))),
                          max(0, min(2000, int(p[1])))])
        except Exception:
            pass
    if len(clean) < 3:
        return None
    try:
        opacity = float(d.get("opacity", 0.35))
    except Exception:
        opacity = 0.35
    tgt = d.get("target")
    return {
        "id": existing_id or d.get("id") or uuid.uuid4().hex[:8],
        "points": clean,
        "label": str(d.get("label", ""))[:80],
        "image": d.get("image") if valid_media_url(d.get("image")) else None,
        "target": (str(tgt)[:40] if tgt else None),

        "targetId": (room_ref(room_by_ref(str(tgt))) if tgt
                     else str(d.get("targetId") or "")),
        "script": str(d.get("script", ""))[:2000],
        "fill": str(d.get("fill", "#a855f7"))[:9],
        "text": str(d.get("text", "#ffffff"))[:9],
        "opacity": max(0.0, min(1.0, opacity)),

        "action": (str(d.get("action")) if d.get("action") in DOOR_ACTIONS
                   else None),
    }

def is_fixed_room(room) -> bool:
    if not room:
        return False
    if room.name in BUILTIN_ROOMS or getattr(room, "from_template", False):
        return True
    return bool(room.persistent and room.owner is None)

def wizard_room_blocked(user, room) -> bool:
    if not room or user.rank >= RANK_OWNER:
        return False
    return user.base.lower() in (getattr(room, "blocked_wizards", None) or set())

def can_edit_doors(user, room) -> bool:
    return (bool(room) and user.rank >= RANK_WIZARD
            and not wizard_room_blocked(user, room))

def group_card(g: dict, viewer, member_base: str = "") -> dict | None:
    if not g:
        return None
    vb = getattr(viewer, "base", "") or ""
    viewer_member = is_member(g, vb)
    return {"name": g["name"], "tag": g.get("tag"), "logo": g.get("logo"),
            "kind": group_kind(g), "policy": group_policy(g),
            "blurb": g.get("blurb", ""),
            "members": len(g.get("members", [])),
            "room": g.get("room") or "",
            "roomPublic": bool(g.get("roomPublic")),
            "total": int(g.get("total", 0)),

            "rank": rank_label(g, member_base) if member_base else "",
            "rankStd": clan_rank_of(g, member_base) if member_base else "",
            "level": clan_level(g, member_base) if member_base else 0,
            "rankNames": rank_names(g),
            "tier": clan_tier(clan_renown(g)["total"])[0][1],
            "renown": clan_renown(g)["total"],
            "bank": int(g.get("bank", 0)),
            "gold": perk_active(g, "goldframe"),
            "memberBase": member_base,

            "viewerMember": viewer_member,
            "canEnter": bool(g.get("room")) and
                        (viewer_member or bool(g.get("roomPublic"))
                         or getattr(viewer, "rank", 0) >= RANK_WIZARD),
            "canJoin": (not group_of(vb)) and group_policy(g) == "open",
            "canRequest": (not group_of(vb)) and group_policy(g) == "request",
            "requested": vb.lower() in
                         [r.lower() for r in (g.get("requests") or [])]}

async def broadcast_group_update(g: dict):
    if not g:
        return
    for u in all_users():
        try:
            await send(u, {"t": "groupUpdate", "card": group_card(g, u)})
        except Exception:
            pass

async def broadcast_group_change(user):
    g = group_public(group_of(user.base), user.base)
    await send(user, {"t": "myGroup", "group": g})
    if user.room:
        await broadcast(user.room, {"t": "groupInfo", "id": user.id, "group": g})

async def drop_ghost_sessions(user, base, account):
    mine = []
    for other in list(all_users()):
        if other is user or other.observer:
            continue
        same = False
        if account and other.account:
            same = (other.account.get("username", "").lower()
                    == account.get("username", "").lower())
        elif not account and not other.account:
            same = (other.base.lower() == (base or "").lower()
                    and other.ws.ip == user.ws.ip)
        if same:
            mine.append(other)

    drop = mine

    for other in drop:
        if True:
            try:

                await other.ws.send(json.dumps({"t": "replaced",
                    "msg": "Signed in elsewhere. "
                           "This session was ended."},
                    ensure_ascii=False))
                await leave_room(other)
                await other.ws.close()
            except Exception:
                pass

async def handle(user: User, msg: dict):
    t = msg.get("t")
    room = user.room

    if t == "register":
        if user.account:
            return await notify(user, "You are already a member.")

        if (CONFIG.get("private_mode")
                or not CONFIG.get("public_registration")) and user.rank < RANK_WIZARD:
            return await send(user, {"t": "registered", "ok": False,
                "error": "Registration is currently closed."})
        uname = clean_base_name(msg.get("username") or user.base)
        if not name_free(uname, user.account):
            return await notify(user, f"The name \"{uname}\" is already taken.")
        if not uname or len(uname) < 2:
            return await send(user, {"t": "registered", "ok": False,
                                     "error": "Choose a name with at least 2 characters."})
        key = uname.lower()
        if key in ACCOUNTS:
            return await send(user, {"t": "registered", "ok": False,
                                     "error": f"\"{uname}\" is already taken."})
        _tok = uuid.uuid4().hex + uuid.uuid4().hex
        acc = {"username": uname, "token_hash": token_hash(_tok),
               "rank": RANK_MEMBER, "created": now_ms()}
        if valid_media_url(user.avatar):
            acc["avatar"] = user.avatar
        ACCOUNTS[key] = acc
        save_accounts()

        user.account = acc
        user.base = uname

        user.rank = max(user.rank, effective_rank(uname, acc))
        await send(user, {"t": "registered", "ok": True, "username": uname,
                          "token": _tok, "rank": user.rank,
                          "rankName": RANK_NAME[user.rank]})
        await send(user, {"t": "rank", "rank": user.rank,
                          "rankName": RANK_NAME[user.rank]})
        if room:
            await broadcast(room, {"t": "rename", "id": user.id, "name": user.name,
                                   "base": user.base, "rank": user.rank})
        await push_presence()
        return await notify(user, f"Welcome as a member, {uname}! "
                                  f"Your name is now reserved.")

    if t == "globalUsers":
        out = []
        for u in all_users():
            if u.hidden and user.rank < RANK_WIZARD:
                continue

            r_hidden = bool(u.room and getattr(u.room, "hidden", False))
            show_room = (not r_hidden) or user.rank >= RANK_WIZARD
            out.append({"id": u.id, "name": u.name, "base": u.base,
                        "rank": u.rank, "rankName": RANK_NAME[u.rank],
                        "avatar": u.avatar,

                        "idle": u.idle, "idleText": u.idle_text,
                        "idleSince": u.idle_since,
                        "group": group_public(group_of(u.base), u.base),
                        "roomHidden": r_hidden,
                        "room": (u.room.name if (u.room and show_room)
                                 else ("hidden" if r_hidden else None))})
        out.sort(key=lambda x: ((x["room"] or "").lower(), x["base"].lower()))
        return await send(user, {"t": "globalUsers", "list": out})

    if t == "summon":
        if not can(user, "moderate"):
            return await notify(user, "You lack the moderation right for that.")
        target = users_by_id(msg.get("id")) or find_user(str(msg.get("name", "")))
        if not target:
            return await notify(user, "User not found.")
        if target.rank > user.rank:
            return await notify(user, "You cannot summon higher-ranked users.")
        mod_log(room.name if room else "-", user.base, "SUMMON",
                f"summons {target.base} (rank {RANK_NAME[user.rank]})")
        if not room:
            return
        if target.room is room:
            return await notify(user, f"{target.base} is already here.")
        await notify(target, f"{user.name} summoned you to the room "
                             f"\"{room.name}\".")
        await join_room(target, room.name, room.password or "")
        return await notify(user, f"{target.base} was summoned.")

    if t == "approveRoom":
        if not can(user, "moderate"):
            return await notify(user, "You lack the right for that.")
        target = ROOMS.get(str(msg.get("room", "")))
        if not target:
            return await notify(user, "Room not found.", "msg.roomnotfound")
        if target.persistent:
            target.perm_requested = False
            return await notify(user, "The room is already permanent.")
        target.persistent = True
        target.perm_requested = False
        save_rooms()
        await broadcast(target, {"t": "roomstate", "persistent": True,
                                 "permRequested": False})
        await broadcast(target, {"t": "sysmsg",
            "text": f"📌 \"{target.name}\" is now permanent (by {user.name})."})
        await push_rooms()
        return await notify(user, f"\"{target.name}\" was saved permanently.")

    if t == "style":
        def col(v):
            v = str(v or "")[:9]
            return v if re.fullmatch(r"#[0-9a-fA-F]{3,8}", v) else ""
        user.name_color = col(msg.get("nameColor"))
        user.bubble_color = col(msg.get("bubbleColor"))
        if room:
            await broadcast(room, {"t": "style", "id": user.id,
                                   "nameColor": user.name_color,
                                   "bubbleColor": user.bubble_color})
        return

    if t == "groups":
        return await send(user, {"t": "groups", "list": [
            {"name": g["name"], "tag": g.get("tag"), "logo": g.get("logo"),
             "blurb": g.get("blurb", ""), "kind": group_kind(g),
             "policy": group_policy(g), "room": g.get("room") or "",
             "roomPublic": bool(g.get("roomPublic")),
             "total": int(g.get("total", 0)),
             "requested": user.base.lower() in
                          [r.lower() for r in (g.get("requests") or [])],
             "members": len(g.get("members", [])), "owner": g.get("owner")}
            for g in GROUPS.values()], "mine": group_public(group_of(user.base), user.base)})

    if t == "groupCreate":
        if not user.account and user.rank < RANK_MEMBER:
            return await notify(user, "Only members can found a group.")
        raw = str(msg.get("name", ""))
        name = clean_group_name(raw)
        if len(name) < 2:
            return await notify(user, "The name contains too few usable "
                                      "characters. Allowed are letters, digits, "
                                      "spaces and - . ' & +")
        if name.lower() in [k.lower() for k in GROUPS]:
            return await notify(user, f"\"{name}\" already exists – please choose "
                                      f"another name.")
        if group_of(user.base):
            g_old = group_of(user.base)
            return await notify(user, f"You are already in "
                                      f"{group_kind(g_old)} \"{g_old['name']}\". "
                                      f"Leave first, then found a new one.")
        kind = msg.get("kind") if msg.get("kind") in GROUP_KINDS else "Clan"
        policy = msg.get("policy") if msg.get("policy") in GROUP_POLICIES else "open"
        mod_log(room.name if room else "-", user.base, "GROUP-CREATE",
                f"\"{name}\" ({kind}, join={policy})")
        GROUPS[name] = {"name": name, "tag": clean_base_name(msg.get("tag", name[:4]), 6),
                        "logo": msg.get("logo") if valid_media_url(msg.get("logo")) else None,
                        "kind": kind, "policy": policy, "requests": [],
                        "slotSteps": 0,
                        "bank": 0,
                        "owner": user.base, "members": [user.base],
                        "ranks": {user.base.lower(): "Founder"},
                        "points": {user.base.lower(): 0},
                        "joined": {user.base.lower(): now_ms()},
                        "created": now_ms()}

        ensure_clan_room(GROUPS[name], user.id)
        save_groups()
        await push_rooms()
        await broadcast_group_change(user)
        await broadcast_group_update(GROUPS[name])
        pol = {"open": "anyone may join", "request": "join on request",
               "invite": "invitation only"}[policy]
        return await notify(user, f"{kind} \"{name}\" founded. 🛡  "
                                  f"{pol}. {GROUP_SLOTS_BASE} slots. "
                                  f"Own room: {GROUPS[name]['room']}")

    if t == "groupRank":

        g = group_of(user.base)
        if not g or not has_perm(g, user.base, "ranks"):
            return await notify(user, "You lack the right to assign ranks.", "msg.noright.ranks")
        who = str(msg.get("member", "")).strip()
        rank = str(msg.get("rank", "Member"))
        if rank not in ASSIGNABLE_RANKS:
            return await notify(user, "Unknown rank.")
        mylvl = clan_level(g, user.base)
        if CLAN_LEVEL[rank] >= mylvl and mylvl < CLAN_LEVEL["Founder"]:
            return await notify(user, "You cannot assign a rank at or above your own level.")
        if clan_level(g, who) >= mylvl and mylvl < CLAN_LEVEL["Founder"]:
            return await notify(user, "This person is not below you.")
        if who.lower() not in [m.lower() for m in g.get("members", [])]:
            return await notify(user, "This person is not in the clan.")
        if who.lower() == (g.get("owner") or "").lower():
            return await notify(user, "The leadership keeps the Founder rank.")
        g.setdefault("ranks", {})[who.lower()] = rank
        save_groups()
        mod_log(room.name if room else "-", user.base, "GROUP-RANK",
                f"'{g['name']}': {who} → {rank}")
        await broadcast_group_update(g)
        for u in all_users():
            if u.base.lower() == who.lower():
                await broadcast_group_change(u)
        for u in all_users():
            if u.base.lower() == who.lower():
                await broadcast_group_change(u)
        return await notify(user, f"{who} is now {rank}.")

    if t == "groupLogo":
        g = group_of(user.base)
        if not g or g.get("owner", "").lower() != user.base.lower():
            return await notify(user, "Only the group leadership can change the logo.")
        logo = msg.get("logo")
        if logo is None:
            g["logo"] = None
        elif valid_media_url(logo):
            g["logo"] = logo
        else:
            return await notify(user, "Invalid image.", "msg.badimage")
        save_groups()
        await broadcast_group_update(g)

        for u in all_users():
            if group_of(u.base) is g and u.room:
                await broadcast(u.room, {"t": "groupInfo", "id": u.id,
                                         "group": group_public(g, u.base)})
        return await notify(user, "Group logo updated.")

    if t == "perks":

        g = group_of(user.base)
        acct = user.account or {"perks": getattr(user, "session_perks", {})}
        return await send(user, {
            "t": "perks", "myPoints": user_points(user),
            "member": bool(user.account),
            "group": (g or {}).get("name"),
            "groupBank": int((g or {}).get("bank", 0)),
            "canManage": bool(g and has_perm(g, user.base, "perks")),
            "days": PERK_DAYS,
            "renown": ({
                "total": clan_renown(g)["total"],
                "parts": clan_renown(g)["parts"],
                "tier": clan_tier(clan_renown(g)["total"])[0][1],
                "curNeed": clan_tier(clan_renown(g)["total"])[0][0],
                "next": ({"points": clan_tier(clan_renown(g)["total"])[1][0],
                          "name": clan_tier(clan_renown(g)["total"])[1][1]}
                         if clan_tier(clan_renown(g)["total"])[1] else None),
            } if g else None),
            "slots": group_slots(g) if g else 0,

            "tierList": ([{
                "points": pts, "name": nm, "index": i,
                "reached": (clan_renown(g)["total"] >= pts),
                "unlocks": [f"{p['icon']} {p['name']}"
                            for p in PERKS.values()
                            if int(p.get("tier", 0)) == i],
            } for i, (pts, nm) in enumerate(CLAN_REWARDS)] if g else []),
            "members": len(g.get("members", [])) if g else 0,
            "groupPerks": perk_list(g, "group") if g else [],
            "userPerks": perk_list(acct, "user")})

    if t == "groupBank":

        if user.rank < RANK_OWNER:
            return await notify(user, "Owner only.", "msg.owneronly")
        g = group_by_name(str(msg.get("group") or "")) or group_of(user.base)
        if not g:
            return await notify(user, "Group not found.", "msg.groupnotfound")
        try:
            amount = int(msg.get("amount") or 0)
        except Exception:
            return await notify(user, "Please enter a number.")
        mode = str(msg.get("mode") or "add")
        old = int(g.get("bank", 0))
        if mode == "set":
            g["bank"] = max(0, amount)
        elif mode == "take":
            g["bank"] = max(0, old - abs(amount))
        else:
            g["bank"] = max(0, old + amount)
        save_groups()
        await broadcast_group_update(g)
        for u in all_users():
            if is_member(g, u.base):
                await send(u, {"t": "perksDirty"})
                await send(u, {"t": "sysmsg",
                               "text": f"💰 Treasury of \"{g['name']}\": "
                                       f"{old} → {g['bank']} points."})
        mod_log(room.name if room else "-", user.base, "GROUP-BANK",
                f"{g['name']}: {old} → {g['bank']} ({mode} {amount})")
        return await notify(user, f"Treasury \"{g['name']}\": {old} → {g['bank']}.")

    if t == "grantPoints":

        if user.rank < RANK_OWNER:
            return await notify(user, "Owner only.", "msg.owneronly")
        who = str(msg.get("member") or "").strip()
        try:
            amount = int(msg.get("amount") or 0)
        except Exception:
            return
        target = find_user(who) if who else user
        if not target:
            return await notify(user, "Person not found.", "msg.usernotfound")
        set_user_points(target, user_points(target) + amount)
        await send(target, {"t": "points", "points": user_points(target)})
        await notify(target, f"🪙 You received {amount} points.")
        mod_log(room.name if room else "-", user.base, "GRANT-POINTS",
                f"{amount} → {target.base}")
        return await notify(user, f"{target.base} now has "
                                  f"{user_points(target)} points.")

    if t == "perkDonate":
        g = group_of(user.base)
        if not g:
            return await notify(user, "You are not in a guild or clan.", "msg.nogroup")
        try:
            amount = int(msg.get("amount") or 0)
        except Exception:
            return
        have = user_points(user)
        if have < 1:
            return await notify(user, "You haven't collected any points yet.", "msg.nopoints")
        amount = max(1, min(amount, have))
        set_user_points(user, have - amount)
        g["bank"] = int(g.get("bank", 0)) + amount
        g["donated"] = int(g.get("donated", 0)) + amount
        save_groups()
        await broadcast_group_update(g)
        for u in all_users():
            if is_member(g, u.base):
                await send(u, {"t": "sysmsg",
                               "text": f"💰 {user.base} put {amount} points "
                                       f"into the treasury ({g['bank']} total)."})
                await send(u, {"t": "perksDirty"})
        mod_log(room.name if room else "-", user.base, "PERK-DONATE",
                f"{amount} → {g['name']}")
        return

    if t == "perkBuy":
        key = str(msg.get("key") or "")
        p = PERKS.get(key)
        if not p:
            return await notify(user, "Unknown perk.", "msg.perk.unknown")
        cost = int(p["cost"])
        if p["scope"] == "group":
            g = group_of(user.base)
            if not g:
                return await notify(user, "You are not in a group.", "msg.nogroup2")
            if not has_perm(g, user.base, "perks"):
                return await notify(user, "You lack the right to redeem perks "
                                          "for the group.")
            if not perk_tier_ok(g, key):
                need = int(p.get("tier", 0))
                return await notify(user, f"The group needs tier "
                                          f"\"{CLAN_REWARDS[need][1]}\" "
                                          f"(from {CLAN_REWARDS[need][0]} renown).")
            bank = int(g.get("bank", 0))
            if bank < cost:
                return await notify(user, f"The treasury has {bank} of "
                                          f"{cost} points.")
            g["spent"] = int(g.get("spent", 0)) + cost
            if p.get("stack"):

                g["bank"] = bank - cost
                g["slotSteps"] = int(g.get("slotSteps", 0)) + 1
            else:
                g["bank"] = bank - cost
                store = perks_store(g)
                store[key] = max(now_ms(), int(store.get(key, 0))) \
                    + perk_days(key) * 86400000
            save_groups()
            await broadcast_group_update(g)
            note = (f"{p['icon']} \"{p['name']}\": now {group_slots(g)} slots."
                    if p.get("stack") else
                    f"{p['icon']} \"{p['name']}\" runs for {perk_days(key)} days.")
            for u in all_users():
                if is_member(g, u.base):
                    await send(u, {"t": "sysmsg", "text": note})
                    await send(u, {"t": "perksDirty"})
            mod_log(room.name if room else "-", user.base, "PERK-BUY",
                    f"{key} for {g['name']} ({cost})")
            return
        have = user_points(user)
        if have < cost:
            return await notify(user, f"You have {have} of {cost} points.")
        set_user_points(user, have - cost)
        if user.account:
            store = perks_store(user.account)
        else:
            if not hasattr(user, "session_perks"):
                user.session_perks = {}
            store = user.session_perks
        store[key] = max(now_ms(), int(store.get(key, 0))) \
            + perk_days(key) * 86400000
        if user.account:
            ACCOUNTS[user.account["username"].lower()]["perks"] = store
            save_accounts()
        await send(user, {"t": "perksDirty"})
        mod_log(room.name if room else "-", user.base, "PERK-BUY",
                f"{key} personal ({cost})")
        return await notify(user, f"{p['icon']} \"{p['name']}\" now runs for "
                                  f"{perk_days(key)} days.")

    if t == "groupRankNames":

        g = group_of(user.base)
        if not g or (g.get("owner") or "").lower() != user.base.lower():
            return await notify(user, "Only the founder can change rank names.", "msg.founderonly.ranknames")
        names = msg.get("names") or {}
        store = g.setdefault("rankNames", {})
        for i in range(len(CLAN_RANKS)):
            v = str(names.get(str(i), "") or "").strip()[:20]
            if v:
                store[str(i)] = v
            else:
                store.pop(str(i), None)
        save_groups()
        mod_log(room.name if room else "-", user.base, "GROUP-RANKNAMES",
                f"'{g['name']}': {rank_names(g)}")
        for u in all_users():
            if group_of(u.base) is g:
                await broadcast_group_change(u)
        await broadcast_group_update(g)
        return await notify(user, "Rank names saved: " +
                                  ", ".join(rank_names(g)))

    if t == "groupPerms":

        g = group_of(user.base)
        if not g or (g.get("owner") or "").lower() != user.base.lower():
            return await notify(user, "Only the founder can change rights.", "msg.founderonly.perms")
        try:
            lvl = int(msg.get("level"))
        except Exception:
            return
        if not (0 <= lvl < len(CLAN_RANKS)):
            return
        want = [p for p in (msg.get("perms") or []) if p in CLAN_PERMS]
        g.setdefault("perms", {})[str(lvl)] = want
        save_groups()
        mod_log(room.name if room else "-", user.base, "GROUP-PERMS",
                f"\"{g['name']}\" tier {lvl}: {want}")
        for u in all_users():
            if group_of(u.base) is g:
                await broadcast_group_change(u)
        await broadcast_group_update(g)
        return await notify(user, f"Rights for \"{rank_names(g)[lvl]}\" saved.")

    if t == "groupAnnounce":

        g = group_of(user.base)
        if not g or not has_perm(g, user.base, "announce"):
            return await notify(user, "You lack the right to make announcements.", "msg.noright.announce")
        text = str(msg.get("text", "")).strip()[:400]
        if not text:
            return
        for u in all_users():
            if is_member(g, u.base):
                await send(u, {"t": "groupChat", "from": user.name, "id": user.id,
                               "rank": user.rank, "text": "📣 " + text,
                               "group": g["name"], "kind": group_kind(g),
                               "logo": g.get("logo"), "tag": g.get("tag"),
                               "room": room.name if room else "",
                               "remote": (u.room is not user.room)})
        mod_log(room.name if room else "-", user.base, "GROUP-ANNOUNCE", text)
        return await notify(user, "Announcement sent.", "msg.announce.sent")

    if t == "groupRename":

        g = (group_by_name(str(msg.get("group") or "")) if user.rank >= RANK_OWNER
             else None) or group_of(user.base)
        if not g:
            return await notify(user, "Group not found.", "msg.groupnotfound")
        is_founder = (g.get("owner") or "").lower() == user.base.lower()
        if not (is_founder or user.rank >= RANK_OWNER):
            return await notify(user, "Only the founder can rename.", "msg.founderonly.rename")
        new = clean_group_name(str(msg.get("name", "")))
        if len(new) < 2:
            return await notify(user, "The name contains too few usable characters.")
        old = g["name"]
        if new == old:
            return await notify(user, "The name is unchanged.")
        if new.lower() in [k.lower() for k in GROUPS if k != old]:
            return await notify(user, f"\"{new}\" already exists.")
        GROUPS.pop(old, None)
        g["name"] = new
        GROUPS[new] = g

        old_room = g.get("room")
        if old_room and old_room in ROOMS:
            new_room = clan_room_name(new)
            if new_room not in ROOMS:
                r = ROOMS.pop(old_room)
                r.name = new_room
                ROOMS[new_room] = r
                g["room"] = new_room
                for u in list(r.users.values()):
                    await send(u, {"t": "sysmsg",
                                   "text": f"The room is now called \"{new_room}\"."})
                save_rooms()
                await push_rooms()
        save_groups()
        mod_log(room.name if room else "-", user.base, "GROUP-RENAME",
                f"'{old}' → '{new}'")
        for u in all_users():
            if group_of(u.base) is g:
                await broadcast_group_change(u)
        await broadcast_group_update(g)
        return await notify(user, f"Renamed to \"{new}\".")

    if t == "groupJoin":
        name = str(msg.get("name", ""))
        g = GROUPS.get(name) or next((x for x in GROUPS.values()
                                      if x["name"].lower() == name.lower()), None)
        if not g:
            return await notify(user, "Group not found.", "msg.groupnotfound")
        if group_of(user.base):
            return await notify(user, "You are already in a group. "
                                      "Leave it first.")
        cap = group_slots(g)
        if len(g.get("members", [])) >= cap:
            return await notify(user, f"This group is full ({cap} slots).")
        kind = group_kind(g)
        if group_policy(g) == "invite":
            return await notify(user, f"{kind} \"{g['name']}\" accepts members "
                                      f"by invitation only.")
        if group_policy(g) == "request":
            reqs = g.setdefault("requests", [])
            if user.base.lower() in [r.lower() for r in reqs]:
                return await notify(user, "Your request is already pending.")
            reqs.append(user.base)
            save_groups()

            for u in all_users():
                if group_of(u.base) is g and may_manage(g, u.base):
                    await notify(u, f"📨 {user.base} would like to join {kind} "
                                    f"\"{g['name']}\".")
            return await notify(user, f"Request sent to {kind} \"{g['name']}\".")
        g.setdefault("members", []).append(user.base)
        g.setdefault("ranks", {})[user.base.lower()] = "Recruit"
        g.setdefault("joined", {})[user.base.lower()] = now_ms()
        g.setdefault("points", {}).setdefault(user.base.lower(), 0)
        ensure_clan_room(g, None)
        save_groups()
        await broadcast_group_change(user)
        await broadcast_group_update(g)
        return await notify(user, f"You joined {kind} \"{g['name']}\".")

    if t == "groupLeave":
        g = group_of(user.base)
        if not g:
            return await notify(user, "You are not in a group.", "msg.nogroup2")
        g["members"] = [m for m in g.get("members", [])
                        if m.lower() != user.base.lower()]
        if not g["members"]:
            GROUPS.pop(g["name"], None)
        save_groups()
        await broadcast_group_change(user)
        return await notify(user, f"You left \"{g['name']}\".")

    if t == "groupBlurb":

        g = group_of(user.base)
        if not g or (g.get("owner") or "").lower() != user.base.lower():
            return await notify(user, "Only the clan leadership can set the text.")
        limit = 600 if perk_active(g, "bigblurb") else 280
        g["blurb"] = str(msg.get("text", "")).strip()[:limit]
        save_groups()
        await broadcast_group_update(g)
        return await notify(user, "Welcome text saved.")

    if t == "avatarOffer" and room:

        target = room.users.get(str(msg.get("to")))
        if not target or target.id == user.id:
            return await notify(user, "This person is not in the room.")
        av = msg.get("url") or user.avatar
        if not valid_media_url(av):
            return await notify(user, "You have no avatar to offer.")
        oid = uuid.uuid4().hex[:10]
        OFFERS[oid] = {"kind": "avatar", "from": user.id, "fromName": user.base,
                       "to": target.id, "url": av, "ts": now_ms()}
        await send(target, {"t": "avatarOffer", "offerId": oid,
                            "from": user.base, "fromId": user.id, "url": av})
        await notify(target, f"🎭 {user.base} offers you an avatar.")
        return await notify(user, f"Avatar an {target.base} angeboten.")

    if t in ("avatarAccept", "avatarDecline"):
        off = OFFERS.pop(str(msg.get("offerId")), None)
        if not off or off.get("to") != user.id or off.get("kind") != "avatar":
            return await notify(user, "This offer no longer exists.")
        giver = users_by_id(off["from"])
        if t == "avatarDecline":
            if giver:
                await notify(giver, f"{user.base} declined the avatar.")
            return await notify(user, "Offer declined.", "msg.offer.declined")
        if not valid_media_url(off["url"]):
            return
        user.avatar = off["url"]
        if user.account:
            ACCOUNTS[user.account["username"].lower()]["avatar"] = user.avatar
            user.account["avatar"] = user.avatar
            save_accounts()
        if room:
            await broadcast(room, {"t": "avatar", "id": user.id, "data": user.avatar})
        if giver:
            await notify(giver, f"{user.base} is now using your avatar. 🎭")
        return await notify(user, "Avatar taken. 🎭", "msg.avatar.taken")

    if t == "groupInvite":

        g = group_of(user.base)
        if not g:
            return await notify(user, "You are not in a guild or clan.", "msg.nogroup")
        if not has_perm(g, user.base, "invite"):
            return await notify(user, "You lack the right to invite people.", "msg.noright.invite")
        target = users_by_id(str(msg.get("to")))
        if not target:
            base = str(msg.get("toName") or "").strip()
            target = find_user(base) if base else None
        if not target:
            return await notify(user, "This person is no longer online.", "msg.useroffline")
        if target.id == user.id:
            return await notify(user, "You don't need to invite yourself.")
        if is_member(g, target.base):
            return await notify(user, "This person is already a member.")
        if group_of(target.base):
            return await notify(user, "This person is already a member elsewhere.")
        if len(g.get("members", [])) >= group_slots(g):
            return await notify(user, f"Full ({group_slots(g)} slots).")
        oid = uuid.uuid4().hex[:10]
        OFFERS[oid] = {"kind": "invite", "from": user.id, "fromName": user.base,
                       "to": target.id, "group": g["name"], "ts": now_ms()}
        await send(target, {"t": "groupInvite", "offerId": oid,
                            "from": user.base, "group": g["name"],
                            "kind": group_kind(g)})
        await notify(target, f"🛡 {user.base} invites you to "
                             f"{group_kind(g)} \"{g['name']}\".")
        return await notify(user, f"Invitation sent to {target.base}.")

    if t in ("inviteAccept", "inviteDecline"):
        off = OFFERS.pop(str(msg.get("offerId")), None)
        if not off or off.get("to") != user.id or off.get("kind") != "invite":
            return await notify(user, "This invitation no longer exists.")
        inviter = users_by_id(off["from"])
        g = GROUPS.get(off["group"])
        if t == "inviteDecline":
            if inviter:
                await notify(inviter, f"{user.base} declined the invitation.")
            return await notify(user, "Invitation declined.")
        if not g:
            return await notify(user, "This group no longer exists.")
        if group_of(user.base):
            return await notify(user, "You are already a member.")
        g.setdefault("members", []).append(user.base)
        g.setdefault("ranks", {})[user.base.lower()] = "Recruit"
        g.setdefault("joined", {})[user.base.lower()] = now_ms()
        g.setdefault("points", {}).setdefault(user.base.lower(), 0)
        reqs = g.setdefault("requests", [])
        g["requests"] = [r for r in reqs if r.lower() != user.base.lower()]
        ensure_clan_room(g, None)
        save_groups()
        await broadcast_group_change(user)
        await broadcast_group_update(g)
        if inviter:
            await notify(inviter, f"{user.base} joined. 🎉")
        return await notify(user, f"Welcome to {group_kind(g)} \"{g['name']}\"!")

    if t == "groupQuery":

        name = str(msg.get("name", "")).strip()
        g = GROUPS.get(name) or next((x for x in GROUPS.values()
                                      if x["name"].lower() == name.lower()), None)
        return await send(user, {"t": "groupCard",
                                 "card": group_card(g, user,
                                                    str(msg.get("member", "")))})

    if t == "groupSettings":

        g = group_of(user.base)
        if not g or ((g.get("owner") or "").lower() != user.base.lower()
                     and user.rank < RANK_OWNER):
            return await notify(user, "Only the founder or the owner "
                                      "can change that.")
        if msg.get("kind") in GROUP_KINDS:
            g["kind"] = msg["kind"]
        if msg.get("policy") in GROUP_POLICIES:
            g["policy"] = msg["policy"]
        if "roomPublic" in msg:
            want = bool(msg.get("roomPublic"))
            if want and not perk_active(g, "publichall") \
                    and int(g.get("total", 0)) < 250:
                return await notify(user, "Open hall: from tier \"Established\" "
                                          "or via the 🏛 perk.")
            g["roomPublic"] = want
        save_groups()
        mod_log(room.name if room else "-", user.base, "GROUP-SETTINGS",
                f"'{g['name']}' kind={group_kind(g)} join={group_policy(g)} "
                f"hall_public={bool(g.get('roomPublic'))}")
        for u in all_users():
            if group_of(u.base) is g:
                await broadcast_group_change(u)
        await broadcast_group_update(g)
        return await notify(user, f"{group_kind(g)} · Join: "
                                  f"{'anyone' if group_policy(g) == 'open' else 'on request'}")

    if t == "groupRequests":

        g = group_of(user.base)
        if not g or not has_perm(g, user.base, "approve"):
            return await send(user, {"t": "groupRequests", "list": []})
        return await send(user, {"t": "groupRequests",
                                 "group": g["name"],
                                 "list": list(g.get("requests") or [])})

    if t in ("groupApprove", "groupDeny"):
        g = group_of(user.base)
        if not g or not has_perm(g, user.base, "approve"):
            return await notify(user, "You lack the right to handle requests.", "msg.noright.approve")
        who = str(msg.get("member", "")).strip()
        reqs = g.setdefault("requests", [])
        hit = next((r for r in reqs if r.lower() == who.lower()), None)
        if not hit:
            return await notify(user, "This request no longer exists.")
        reqs.remove(hit)
        if t == "groupDeny":
            save_groups()
            for u in all_users():
                if u.base.lower() == hit.lower():
                    await notify(u, f"Your request to \"{g['name']}\" was declined.")
            return await notify(user, f"{hit} declined.")
        if group_of(hit):
            save_groups()
            return await notify(user, f"{hit} has meanwhile joined elsewhere.")
        g.setdefault("members", []).append(hit)
        g.setdefault("ranks", {})[hit.lower()] = "Recruit"
        g.setdefault("joined", {})[hit.lower()] = now_ms()
        g.setdefault("points", {}).setdefault(hit.lower(), 0)
        ensure_clan_room(g, None)
        save_groups()
        mod_log(room.name if room else "-", user.base, "GROUP-APPROVE",
                f"'{g['name']}': {hit} accepted")
        await broadcast_group_update(g)
        for u in all_users():
            if u.base.lower() == hit.lower():
                await broadcast_group_change(u)
                await notify(u, f"🎉 You are now in {group_kind(g)} \"{g['name']}\".")
        return await notify(user, f"{hit} accepted.")

    if t == "groupKick":
        g = group_of(user.base)
        if not g or not has_perm(g, user.base, "kick"):
            return await notify(user, "You lack the right to remove members.", "msg.noright.kick")
        who = str(msg.get("member", "")).strip()
        if who.lower() == (g.get("owner") or "").lower():
            return await notify(user, "The founder cannot be removed.")
        if not is_member(g, who):
            return await notify(user, "This person is not a member.")
        if clan_level(g, who) >= clan_level(g, user.base) \
                and clan_level(g, user.base) < CLAN_LEVEL["Founder"]:
            return await notify(user, "This person is not below you.")
        g["members"] = [m for m in g.get("members", []) if m.lower() != who.lower()]
        (g.get("ranks") or {}).pop(who.lower(), None)
        save_groups()
        mod_log(room.name if room else "-", user.base, "GROUP-KICK",
                f"\"{g['name']}\": {who} removed")
        await broadcast_group_update(g)
        for u in all_users():
            if u.base.lower() == who.lower():
                await broadcast_group_change(u)
                await notify(u, f"You were removed from \"{g['name']}\".")
                if u.room and (g.get("room") or "").lower() == u.room.name.lower():
                    await join_room(u, "Plaza" if "Plaza" in ROOMS
                                    else next(iter(ROOMS)))
        return await notify(user, f"{who} removed.")

    if t == "scriptCheck":

        if user.rank < RANK_WIZARD:
            return await send(user, {"t": "scriptCheck", "ok": False,
                                     "errors": ["Only wizards and owners may "
                                                "edit scripts."],
                                     "events": [], "lang": "pps"})
        src = str(msg.get("src") or "")
        hs, errs = pps_parse(src)
        return await send(user, {"t": "scriptCheck", "ok": not errs,
                                 "errors": errs[:20],
                                 "events": sorted(hs.keys()),
                                 "lang": "pps" if pps_is_new_style(src) else "legacy"})

    if t == "roomVisible":
        if not room:
            return
        if not (room.owner == user.id or
                (user.rank >= RANK_WIZARD and not wizard_room_blocked(user, room))):
            return await notify(user, "Only the room creator "
                                      "or a wizard can do that.")
        room.hidden = bool(msg.get("hidden"))
        if room.persistent:
            save_rooms()
        await push_rooms()
        mod_log(room.name, user.base, "ROOM-VIS",
                "hidden" if room.hidden else "visible")
        await broadcast(room, {"t": "roomVis", "hidden": room.hidden})
        return await notify(user, "Room is now " +
                                  ("hidden 🕶" if room.hidden else "visible 👁"))

    if t == "roomStructure":

        if user.rank < RANK_WIZARD:
            return await notify(user, "Wizards and owners only.", "msg.wizonly")
        target = room_by_ref(str(msg.get("room") or (room.name if room else "")))
        if not target:
            return await notify(user, "Room not found.", "msg.roomnotfound")
        if wizard_room_blocked(user, target):
            return await notify(user, "The owner has removed your right to edit "
                                      "this room.", "msg.room.wizblocked")
        if "landing" in msg:
            target.landing = bool(msg.get("landing"))
            if target.landing:
                for r in ROOMS.values():
                    if r is not target:
                        r.landing = False
        if "parent" in msg:
            p = str(msg.get("parent") or "").strip()
            target.parent = p if (p in ROOMS and p != target.name) else ""
        save_rooms()
        await push_rooms()
        mod_log(target.name, user.base, "ROOM-STRUCTURE",
                f"landing={getattr(target,'landing',False)} "
                f"parent={getattr(target,'parent','')}")
        return await notify(user, f"Structure of \"{target.name}\" saved.")

    if t == "roomOrder":

        if user.rank < RANK_OWNER:
            return await notify(user, "Only the owner can change the order.")
        refs = msg.get("order") or []
        if not isinstance(refs, list):
            return
        pos = 1
        for ref in refs[:300]:
            r = room_by_ref(str(ref))
            if r:
                r.order = pos
                pos += 1

        for r in sorted(ROOMS.values(), key=lambda z: z.name.lower()):
            if not getattr(r, "order", 0):
                r.order = pos
                pos += 1
        save_rooms()
        mod_log("-", user.base, "ROOM-ORDER", f"{len(refs)} rooms sorted")
        await push_rooms()
        return await notify(user, "Order saved.")

    if t == "roomRename":

        if user.rank < RANK_WIZARD:
            return await notify(user, "Only wizards and owners may rename "
                                      "rooms.", "msg.wizonly")
        target = ROOMS.get(str(msg.get("room") or (room.name if room else "")))
        if not target:
            return await notify(user, "Room not found.", "msg.roomnotfound")
        if wizard_room_blocked(user, target):
            return await notify(user, "The owner has removed your right to edit "
                                      "this room.", "msg.room.wizblocked")
        old_name = target.name

        if (old_name in BUILTIN_ROOMS or old_name == "Plaza") \
                and user.rank < RANK_OWNER:
            return await notify(user, "This system room cannot be "
                                      "renamed.", "msg.room.rename.system")
        new_name = clean_base_name(str(msg.get("newName", "")), 32).replace("*", "")
        if not new_name:
            return await notify(user, "Invalid room name.", "msg.room.rename.invalid")
        if new_name == old_name:
            return
        if new_name in ROOMS:
            return await notify(user, f"\"{new_name}\" is already taken.",
                                "msg.room.rename.taken", name=new_name)

        ROOMS.pop(old_name, None)
        target.name = new_name
        ROOMS[new_name] = target

        for r in ROOMS.values():
            for d in r.doors.values():
                if d.get("target") == old_name:
                    d["target"] = new_name

        for r in ROOMS.values():
            if getattr(r, "parent", "") == old_name:
                r.parent = new_name

        g = group_by_room(old_name)
        if g:
            g["room"] = new_name
            save_groups()

        if LAST_PAGE.get("room") == old_name:
            LAST_PAGE["room"] = new_name
        if target.persistent:
            save_rooms()
        await push_rooms()
        mod_log(new_name, user.base, "ROOM-RENAME", f"from \"{old_name}\"")
        await broadcast(target, {"t": "roomRenamed", "oldName": old_name,
                                 "newName": new_name})
        return await notify(user, f"Room \"{old_name}\" was renamed to \"{new_name}\" "
                                  f"successfully.", "msg.room.rename.done",
                            old=old_name, new=new_name)

    if t == "roomWizardList":

        if user.rank < RANK_OWNER:
            return await notify(user, "Only the owner may view this.", "msg.owneronly")
        target = ROOMS.get(str(msg.get("room") or (room.name if room else "")))
        if not target:
            return await notify(user, "Room not found.", "msg.roomnotfound")
        blocked = getattr(target, "blocked_wizards", None) or set()
        wizards = sorted({n for n, r in CONFIG["grants"].items() if int(r) == RANK_WIZARD})
        return await send(user, {"t": "roomWizardList", "room": target.name,
                                 "wizards": [{"name": n, "blocked": n in blocked}
                                            for n in wizards]})

    if t == "roomWizardAccess":

        if user.rank < RANK_OWNER:
            return await notify(user, "Only the owner may change this.", "msg.owneronly")
        target = ROOMS.get(str(msg.get("room") or (room.name if room else "")))
        if not target:
            return await notify(user, "Room not found.", "msg.roomnotfound")
        wiz_base = str(msg.get("wizard", "")).strip().lower()
        if not wiz_base:
            return
        allowed = bool(msg.get("allowed", True))
        if not isinstance(getattr(target, "blocked_wizards", None), set):
            target.blocked_wizards = set()
        if allowed:
            target.blocked_wizards.discard(wiz_base)
        else:
            target.blocked_wizards.add(wiz_base)
        if target.persistent:
            save_rooms()
        mod_log(target.name, user.base, "ROOM-WIZACCESS",
                f"{wiz_base}: {'allowed' if allowed else 'blocked'}")
        tgt_user = find_user(wiz_base)
        if tgt_user:
            await send(tgt_user, {"t": "roomWizAccessChanged", "room": target.name,
                                  "blocked": not allowed})
        return await notify(user, f"\"{wiz_base}\" may now \"{target.name}\" "
                                  f"{'edit' if allowed else 'NOT edit any more'}.",
                            "msg.room.wizaccess.set")

    if t == "totpSetup":
        if not TOTP_AVAILABLE:
            return await notify(user, "Two-factor is not available on this "
                                      "server.")
        if not user.account:
            return await notify(user, "You need a member account for that.")
        acc = user.account
        if acc.get("totp_enabled"):
            return await notify(user, "Two-factor is already active.")

        secret = twofactor.new_secret()
        acc["totp_pending"] = secret
        save_accounts()
        uri = twofactor.otpauth_uri(secret, acc["username"],
                                    CONFIG.get("servername", "Pixplace"))
        return await send(user, {"t": "totpSetup", "secret": secret,
                                 "uri": uri, "svg": qrgen.qr_svg(uri, scale=5)})

    if t == "totpConfirm":
        if not (TOTP_AVAILABLE and user.account):
            return
        acc = user.account
        pend = acc.get("totp_pending")
        if not pend:
            return await notify(user, "Please start the setup first.")
        ok, ctr = twofactor.verify(pend, str(msg.get("code", "")))
        if not ok:
            return await send(user, {"t": "totpResult", "ok": False,
                "msg": "The code is incorrect. Is the time on your device right?"})
        codes = twofactor.new_recovery_codes()
        acc["totp_secret"] = pend
        acc["totp_enabled"] = True
        acc["totp_last"] = ctr
        acc["totp_recovery"] = [twofactor.hash_recovery(c) for c in codes]
        acc.pop("totp_pending", None)
        save_accounts()
        mod_log("-", acc["username"], "2FA-ON", "Two-factor enabled")

        return await send(user, {"t": "totpResult", "ok": True,
                                 "recovery": codes,
                                 "msg": "Two-factor is now active."})

    if t == "totpDisable":
        if not (TOTP_AVAILABLE and user.account):
            return
        acc = user.account
        if not acc.get("totp_enabled"):
            return await notify(user, "Two-factor is not active.")

        if not totp_check(acc, str(msg.get("code", ""))):
            return await send(user, {"t": "totpResult", "ok": False,
                "msg": "To disable it, please enter a valid code."})
        acc["totp_enabled"] = False
        acc.pop("totp_secret", None)
        acc.pop("totp_recovery", None)
        acc.pop("totp_last", None)
        save_accounts()
        mod_log("-", acc["username"], "2FA-OFF", "Two-factor disabled")
        return await send(user, {"t": "totpResult", "ok": True,
                                 "off": True, "msg": "Two-factor is off."})

    if t == "bagGet":
        acc = user.account
        return await send(user, {"t": "bagData",
                                 "bag": (acc.get("bag") if acc else None),
                                 "member": bool(acc)})

    if t == "bagSet":
        acc = user.account
        if not acc:
            return
        b = msg.get("bag")
        if not isinstance(b, dict):
            return
        clean = {}
        for k in ("props", "avatars", "cats"):
            v = b.get(k)
            if isinstance(v, list):
                clean[k] = v[:400]
        raw = json.dumps(clean, ensure_ascii=False)
        if len(raw) > 400_000:
            return await notify(user, "The bag is too large to back up.")
        acc["bag"] = clean
        acc["bag_ts"] = now_ms()
        save_accounts()
        return await send(user, {"t": "bagSaved", "ts": acc["bag_ts"]})

    if t == "totpState":
        acc = user.account
        return await send(user, {"t": "totpState",
            "available": bool(TOTP_AVAILABLE),
            "member": bool(acc),
            "enabled": bool(acc and acc.get("totp_enabled")),
            "recoveryLeft": len(acc.get("totp_recovery") or []) if acc else 0})

    if t == "report":
        tgt = str(msg.get("target", ""))[:40]
        reason = str(msg.get("reason", ""))[:60]
        text = str(msg.get("text", ""))[:1000]
        if not tgt and not text:
            return await notify(user, "Please say what you are reporting.")
        if not RL_REGISTER.allow(getattr(user.ws, "ip", "?")):
            return await notify(user, "Too many reports. Please wait a moment.")
        rid = uuid.uuid4().hex[:12]
        REPORTS[rid] = {
            "id": rid, "ts": now_ms(), "status": "open",
            "by": user.base, "target": tgt, "reason": reason,
            "text": text, "room": room.name if room else "",
            "ip": safe_ip(getattr(user.ws, "ip", "")),
            "note": "", "handled": 0, "handler": "",
        }
        save_reports()
        mod_log(room.name if room else "-", user.base, "REPORT",
                f"against \"{tgt}\" ({reason})")
        await to_wizards({"t": "sysmsg",
            "text": f"⚠ New report from {user.base} against \"{tgt}\" ({reason})"})
        return await notify(user, "Thanks. The report was forwarded "
                                  "and will be reviewed.")

    if t == "clanLeaderboard":

        rows = []
        online_by = {}
        for u in all_users():
            gg = group_of(u.base)
            if gg:
                online_by[gg["name"]] = online_by.get(gg["name"], 0) + 1
        for g in GROUPS.values():
            total = int(g.get("total", 0))
            mins = sum(int(v) for v in (g.get("minutes") or {}).values())
            mem = len(g.get("members", []))
            ren = clan_renown(g)["total"]
            rows.append({"name": g["name"], "kind": group_kind(g),
                         "logo": g.get("logo"), "members": mem,
                         "online": online_by.get(g["name"], 0),
                         "points": total, "minutes": mins,
                         "bank": int(g.get("bank", 0)),
                         "renown": ren, "slots": group_slots(g),
                         "tier": clan_tier(ren)[0][1],
                         "policy": group_policy(g),
                         "roomPublic": bool(g.get("roomPublic")),
                         "room": g.get("room") or "",

                         "activity": round(total / mem, 1) if mem else 0})
        board = {
            "renown":   sorted(rows, key=lambda r: -r["renown"])[:10],
            "bank":     sorted(rows, key=lambda r: -r["bank"])[:10],
            "members":  sorted(rows, key=lambda r: -r["members"])[:10],
            "online":   sorted(rows, key=lambda r: -r["online"])[:10],
            "activity": sorted(rows, key=lambda r: -r["activity"])[:10],
        }
        return await send(user, {"t": "clanLeaderboard", "board": board,
                                 "count": len(rows),
                                 "tiers": [{"points": p, "name": n}
                                           for p, n in CLAN_REWARDS]})

    if t == "clanStats":

        g = group_by_room(room.name) if room else None
        if not g:
            g = group_of(user.base)
        return await send(user, {"t": "clanStats", "stats": clan_stats(g)})

    if t == "groupDelete":

        name = str(msg.get("name", "")).strip()
        g = GROUPS.get(name) or next((x for x in GROUPS.values()
                                      if x["name"].lower() == name.lower()), None)
        if not g:
            g = group_of(user.base)
        if not g:
            return await notify(user, "Clan not found.")
        is_founder = (g.get("owner") or "").lower() == user.base.lower()
        if not (is_founder or user.rank >= RANK_OWNER):
            return await notify(user, "Only the founder or an owner can delete the clan.")
        gname = g["name"]
        mod_log(room.name if room else "-", user.base, "GROUP-DELETE",
                f"\"{gname}\" ({len(g.get('members', []))} members)")
        members = list(g.get("members", []))
        room_name = g.get("room")
        GROUPS.pop(gname, None)

        if room_name and room_name in ROOMS and not ROOMS[room_name].users:
            ROOMS.pop(room_name, None)
            save_rooms()
            await push_rooms()
        save_groups()

        members_l = [m.lower() for m in members]
        for u in all_users():
            if u.base.lower() in members_l:
                await broadcast_group_change(u)
        return await notify(user, f"Clan \"{gname}\" was deleted.")

    if t == "watch":

        user.observer = True
        WATCHERS.add(user)
        await send(user, {"t": "presence", **presence_snapshot()})
        return
    if t == "getComments":
        return await send(user, {"t": "comments", "comments": COMMENTS[-100:]})
    if t == "comment" and getattr(user, "observer", False):
        c = add_comment(msg.get("name", ""), msg.get("text", ""))
        if c:
            await push_comment(c)
        return

    if t == "login":
        base = clean_base_name(msg.get("name", ""))

        if base.lower() in ("", "gast", "guest"):
            base = ""
        if base.lower() in BANS["names"] or user.ws.ip in BANS["ips"]:
            return await send(user, {"t": "killed", "msg": "You are banned."})

        if CONFIG.get("moderation_logging") and not msg.get("consent"):
            return await send(user, {"t": "consent",
                                     "notice": CONFIG["moderation_notice"],
                                     "servername": CONFIG["servername"]})

        token = msg.get("token") or ""

        if token:
            ip = getattr(user.ws, "ip", "?")
            if not RL_MEMBER_LOGIN.allow(ip) and not ip_is_known_good(ip):
                return await send(user, {"t": "killed",
                    "msg": "Too many login attempts. Please wait a moment."})

            key = "member:" + clean_base_name(msg.get("name", "")).lower()
            wait = 0.0 if ip_is_known_good(ip) else FAILS.delay_for(key)
            if wait > 2.0:
                return await send(user, {"t": "killed",
                    "msg": "Too many login attempts. Please wait a moment."})
            if wait:
                await asyncio.sleep(wait)
        account = account_by_token(token)

        pw = str(msg.get("password", "") or "")
        fresh_token = None
        if not account and pw and base:
            ipx = getattr(user.ws, "ip", "?")
            key = "member:" + base.lower()
            if not RL_MEMBER_LOGIN.allow(ipx) and not ip_is_known_good(ipx):
                return await send(user, {"t": "error", "code": "ratelimit",
                    "msg": "Too many login attempts. Please wait a moment."})
            wait = 0.0 if ip_is_known_good(ipx) else FAILS.delay_for(key)
            if wait > 2.0:
                return await send(user, {"t": "error", "code": "ratelimit",
                    "msg": "Too many login attempts. Please wait a moment."})
            if wait:
                await asyncio.sleep(wait)

            cand = account_by_login(str(msg.get("name", "")).strip()) \
                   or account_by_login(base)
            if cand and cand.get("pw_hash") \
                    and await verify_password_async(pw, cand["pw_hash"]):
                account = cand
                fresh_token = uuid.uuid4().hex + uuid.uuid4().hex
                acc_add_token(account, fresh_token)
                FAILS.ok(key)
                mark_ip_good(ipx)
            else:
                FAILS.fail(key)
                return await send(user, {"t": "error", "code": "badlogin",
                    "msg": "Wrong name or password."})
        if token:
            if account:
                FAILS.ok(key)
                mark_ip_good(getattr(user.ws, "ip", ""))
            else:
                FAILS.fail(key)

        if account and totp_on(account):
            otp = str(msg.get("otp", "") or "")
            ipx = getattr(user.ws, "ip", "?")
            if not otp:
                return await send(user, {"t": "otpRequired",
                    "name": account.get("username", ""),
                    "msg": "Please enter the code from your authenticator app."})
            if not RL_OTP.allow(ipx) and not ip_is_known_good(ipx):
                return await send(user, {"t": "error", "code": "ratelimit",
                    "msg": "Too many code attempts. Please wait a moment."})
            okey = "otp:" + account.get("username", "").lower()
            wait = FAILS.delay_for(okey)
            if wait > 2.0:
                return await send(user, {"t": "error", "code": "ratelimit",
                    "msg": "Too many code attempts. Please wait a moment."})
            if wait:
                await asyncio.sleep(wait)
            if not totp_check(account, otp):
                FAILS.fail(okey)
                mod_log("-", account.get("username", "?"), "2FA-FAIL",
                        f"wrong code from {safe_ip(ipx)}")
                return await send(user, {"t": "error", "code": "badotp",
                    "msg": "The code is incorrect."})
            FAILS.ok(okey)

        if account and not fresh_token and account.get("token_expires"):
            if account["token_expires"] < now_ms():
                return await send(user, {"t": "error", "code": "expired",
                    "msg": "Your session has expired. Please sign in with name "
                           "and password."})

        if account:
            _new_exp = now_ms() + INVITE_DEFAULT_DAYS * 86400_000

            if _new_exp - int(account.get("token_expires") or 0) > 3600_000:
                account["token_expires"] = _new_exp
                save_accounts()

        user.joined_ts = now_ms()
        await drop_ghost_sessions(user, base, account)
        if account:
            base = clean_base_name(account["username"])
        else:

            if not base:
                base = guest_name()
            elif not name_free(base):
                return await send(user, {"t": "error", "code": "reserved",
                    "msg": f"The name \"{base}\" is taken. Please sign in with the "
                           f"matching member token or choose "
                           f"another name."})
            elif any(u is not user and u.base.lower() == base.lower()
                     for u in all_users()):
                return await send(user, {"t": "error", "code": "reserved",
                    "msg": f"\"{base}\" is currently in use."})
        user.account = account

        user.rank = effective_rank(base, account)
        user.base = base

        av = msg.get("avatar")
        if account and valid_media_url(account.get("avatar")):
            user.avatar = account["avatar"]
        elif valid_media_url(av):
            user.avatar = av

        pol = (account or {}).get("whisperPolicy") or msg.get("whisperPolicy")
        if pol in ("all", "room", "none"):
            user.whisper_policy = pol
        await send(user, {"t": "hello", "id": user.id, "name": user.name,
                          "base": user.base, "rank": user.rank,
                          "rankName": RANK_NAME[user.rank],
                          "servername": CONFIG["servername"],
                          "member": bool(account),
                          "avatar": user.avatar,
                          "moderated": bool(CONFIG.get("moderation_logging")),

                          **({"pwTemp": True}
                             if (account and account.get("pw_temp")) else {}),

                          **({"token": fresh_token} if fresh_token else {}),

                          **({"docKey": doc_token_new()}
                             if user.rank >= RANK_WIZARD else {})})
        await send(user, {"t": "rooms", "list": room_list()})
        await join_room(user, msg.get("room") or start_room())
        await push_rooms()
        return

    if t == "auth":

        role = msg.get("role")
        pw = msg.get("password") or ""
        ip = safe_ip(getattr(user, "ip", None))

        if not RL_ROLE_AUTH.allow("auth:" + str(ip), peek=True):
            mod_log(room.name if room else "-", user.base, "AUTH-BLOCKED",
                    f"too many attempts (ip={ip})")
            return await notify(user, "Too many failed attempts. "
                                      "Please wait a few minutes.")
        def pw_ok(a: str, b: str) -> bool:
            return hmac.compare_digest(str(a or ""), str(b or ""))
        if role == "owner" and pw_ok(pw, CONFIG["owner_pass"]):
            user.rank = RANK_OWNER
        elif role == "wizard" and CONFIG.get("wizard_pass") \
                and pw_ok(pw, CONFIG["wizard_pass"]):

            user.rank = RANK_WIZARD
        else:
            if role == "wizard" and not CONFIG.get("wizard_pass"):
                return await notify(user,
                    "Wizard rights are granted by the owner by name – "
                    "there is no shared wizard password.")
            RL_ROLE_AUTH.allow("auth:" + str(ip))
            mod_log(room.name if room else "-", user.base, "AUTH-FAIL",
                    f"role \"{role}\" (ip={ip})")
            await asyncio.sleep(1.0)
            return await notify(user, "Wrong password – role not granted.")
        mod_log(room.name if room else "-", user.base, "AUTH",
                f"role \"{role}\" granted (ip={safe_ip(getattr(user, 'ip', None))})")
        await send(user, {"t": "rank", "rank": user.rank,
                          "rankName": RANK_NAME[user.rank], "name": user.name,

                          **({"docKey": doc_token_new()}
                             if user.rank >= RANK_WIZARD else {})})
        if user.room:
            await broadcast(user.room, {"t": "rename", "id": user.id,
                                        "name": user.name, "base": user.base,
                                        "rank": user.rank})
        mod_log(user.room.name if user.room else "-", user.base, "AUTH",
                f"→ {RANK_NAME[user.rank]}")
        return await notify(user, f"You are now {RANK_NAME[user.rank]}.")

    if t == "rooms":
        return await send(user, {"t": "rooms", "list": room_list()})

    if t == "join":
        return await join_room(user, str(msg.get("room", "")), msg.get("password"))

    if t == "createRoom":
        if not can(user, "create_room"):
            return await send(user, {"t": "error", "code": "perm",
                "msg": "Creating rooms is reserved for members. "
                       "Register as a member (login window)."})
        name = clean_base_name(msg.get("room", ""), 32).replace("*", "")
        if not name:
            return await send(user, {"t": "error", "msg": "Invalid room name."})
        if name in ROOMS:
            return await join_room(user, name, msg.get("password"))
        bg = msg.get("bg")

        ROOMS[name] = Room(name, hidden=bool(msg.get("hidden")),
                           password=msg.get("password") or None,
                           bg=bg if valid_media_url(bg) else None, owner=user.id,
                           persistent=False)

        ensure_lock_door(ROOMS[name])
        mod_log(name, user.base, "ROOM-CREATE",
                f"hidden={bool(msg.get('hidden'))} "
                f"password={'yes' if msg.get('password') else 'no'} "
                f"(ip={safe_ip(getattr(user, 'ip', None))})")
        await join_room(user, name, msg.get("password"))
        await push_rooms()
        await notify(user, "Room created – this room is temporary. For a "
                           "permanent room type ::makepermanent (a wizard "
                           "must approve).")
        return

    if t == "say" and room:
        text = str(msg.get("text", ""))[:MAX_CHAT_LEN].strip()
        if not text:
            return
        if is_command(text):
            return await handle_command(user, text)
        if user.gagged:
            return await notify(user, "You are gagged and cannot speak.")
        if not RL_CHAT.allow("u:" + user.id):
            return await notify(user, "Please slow down – too many messages.")
        ctx = await run_event("CHAT", user, room, chatstr=text)
        if not (ctx and ctx.suppress):
            room.add_log(user.name, text)
            mod_log(room.name, user.base, "CHAT", text)
            for u in room.users.values():
                if user.id in u.muted:
                    continue
                await send(u, {"t": "chat", "from": user.name, "id": user.id,
                               "rank": user.rank, "text": text,
                               "x": user.x, "y": user.y})
        if ctx and ctx.goto and ctx.goto in ROOMS:
            await join_room(user, ctx.goto, ROOMS[ctx.goto].password)
        return

    if t == "whisper":

        text = str(msg.get("text", ""))[:MAX_CHAT_LEN].strip()
        if user.gagged:
            return await notify(user, "You are gagged.", "msg.gagged")
        if not text:
            return
        target = users_by_id(str(msg.get("to", "")))
        if not target:
            base = str(msg.get("toName", "")).strip()
            target = find_user(base) if base else None
        if not target:
            return await send(user, {"t": "whisperFail", "reason": "gone",
                                     "msg": "This person is no longer online."})
        if target.id == user.id:
            return await notify(user, "You cannot whisper to yourself.")
        pol = getattr(target, "whisper_policy", "all")
        same_room = (user.room is not None and target.room is user.room)
        if pol == "none" and user.rank < RANK_WIZARD:
            return await send(user, {"t": "whisperFail", "reason": "off",
                                     "to": target.base,
                                     "msg": f"{target.base} does not accept "
                                            f"whispers."})
        if pol == "room" and not same_room and user.rank < RANK_WIZARD:
            return await send(user, {"t": "whisperFail", "reason": "room",
                                     "to": target.base,
                                     "msg": f"{target.base} only allows whispers "
                                            f"in the same room."})
        if user.id in target.muted:
            return await send(user, {"t": "whisperFail", "reason": "muted",
                                     "to": target.base,
                                     "msg": f"{target.base} has "
                                            f"muted you."})
        p = {"t": "whisper", "from": user.name, "id": user.id,
             "to": target.id, "toName": target.base, "rank": user.rank,
             "text": text, "remote": not same_room,
             "room": user.room.name if user.room else ""}
        await send(target, p)
        await send(user, p)
        mod_log(user.room.name if user.room else "-", user.base,
                f"WHISPER→{target.base}", text)
        return

    if t == "groupSay":

        text = str(msg.get("text", ""))[:MAX_CHAT_LEN].strip()
        if not text:
            return
        if user.gagged:
            return await notify(user, "You are gagged.", "msg.gagged")
        if not RL_CHAT.allow("u:" + user.id):
            return await notify(user, "Please slow down.", "msg.slowdown")
        g = group_of(user.base)
        if not g:
            return await notify(user, "You are not in a guild or clan.", "msg.nogroup")
        if not has_perm(g, user.base, "chat"):
            return await notify(user, "You lack the right to write in the group.", "msg.noright.chat")
        kind = group_kind(g)
        sender_room = user.room.name if user.room else ""
        n = 0
        for u in all_users():
            if not is_member(g, u.base):
                continue
            if user.id in u.muted:
                continue
            n += 1
            await send(u, {"t": "groupChat", "from": user.name, "id": user.id,
                           "rank": user.rank, "text": text,
                           "group": g["name"], "kind": kind,

                           "logo": g.get("logo"), "tag": g.get("tag"),
                           "room": sender_room,
                           "remote": (u.room is not user.room)})
        mod_log(sender_room or "-", user.base, f"GROUPCHAT:{g['name']}", text)
        return

    if t == "idle":

        on = bool(msg.get("on"))
        txt = str(msg.get("text", "")).strip()[:120]
        if on == user.idle and txt == user.idle_text:
            return
        user.idle = on
        user.idle_text = txt if on else ""

        if on and not user.idle_since:
            user.idle_since = now_ms()
        if not on:
            user.idle_since = 0
        if room:
            await broadcast(room, {"t": "idle", "id": user.id,
                                   "on": user.idle, "text": user.idle_text,
                                   "since": user.idle_since})
            if not user.hidden:
                msg_txt = (f"{user.base} is away"
                           + (f": {user.idle_text}" if user.idle_text else ".")
                           ) if on else f"{user.base} is back."
                await broadcast(room, {"t": "chat", "id": "room",
                                       "from": "System", "rank": 0,
                                       "sys": True, "event": "idle",
                                       "text": msg_txt}, skip=user)
        return

    if t == "announce":

        if user.rank < RANK_WIZARD:
            return await notify(user, "Wizards and owners only.", "msg.wizonly")
        text = str(msg.get("text", "")).strip()[:300]
        if not text:
            return await notify(user, "Usage: ::announce <text>")
        scope = "all" if msg.get("scope") == "all" else "room"
        pack = {"t": "announce", "text": text, "from": user.base,
                "rank": user.rank, "scope": scope, "ts": now_ms()}
        if scope == "all":
            for u in all_users():
                await send(u, pack)
        elif room:
            for u in list(room.users.values()):
                await send(u, pack)
        mod_log(room.name if room else "-", user.base,
                "ANNOUNCE-" + scope.upper(), text)
        return await notify(user, "Announcement sent (" 
                                  + ("all rooms" if scope == "all"
                                     else "this room") + ").")

    if t == "whisperPolicy":
        pol = str(msg.get("policy", "all"))
        if pol not in ("all", "room", "none"):
            return
        user.whisper_policy = pol
        if user.account:
            ACCOUNTS[user.account["username"].lower()]["whisperPolicy"] = pol
            user.account["whisperPolicy"] = pol
            save_accounts()
        if room:
            await broadcast(room, {"t": "whisperPolicy", "id": user.id,
                                   "policy": pol})
        names = {"all": "from everywhere", "room": "only in the same room",
                 "none": "not at all"}
        return await notify(user, f"Whispers to you: {names[pol]}.")

    if t == "move" and room:
        if user.pinned:
            return await send(user, {"t": "move", "id": user.id,
                                     "x": user.x, "y": user.y})
        try:
            user.x = max(0, min(2000, int(msg.get("x", user.x))))
            user.y = max(0, min(2000, int(msg.get("y", user.y))))
        except Exception:
            return
        return await broadcast(room, {"t": "move", "id": user.id,
                                      "x": user.x, "y": user.y}, skip=user)

    if t == "moveUser":

        if not can(user, "moderate"):
            return await notify(user, "You lack the moderation right for that.")
        target = users_by_id(msg.get("id"))
        if not target or not target.room:
            return
        if target.rank > user.rank:
            return await notify(user, "You cannot move higher-ranked users.")
        try:
            target.x = max(0, min(2000, int(msg.get("x", target.x))))
            target.y = max(0, min(2000, int(msg.get("y", target.y))))
        except Exception:
            return
        return await broadcast(target.room, {"t": "move", "id": target.id,
                                             "x": target.x, "y": target.y})

    if t == "avatarClear":

        user.avatar = None
        user.props = []
        if user.account:
            ACCOUNTS[user.account["username"].lower()]["avatar"] = None
            user.account["avatar"] = None
            save_accounts()
        if room:
            await broadcast(room, {"t": "avatar", "id": user.id, "data": None})
            await broadcast(room, {"t": "props", "id": user.id, "props": []})
        return await notify(user, "All avatars removed.", "msg.avatars.cleared")

    if t == "avatar":
        av = msg.get("data")
        if valid_media_url(av) or av is None:
            user.avatar = av

            if user.account:
                if valid_media_url(av):
                    ACCOUNTS[user.account["username"].lower()]["avatar"] = av
                    user.account["avatar"] = av
                else:

                    ACCOUNTS[user.account["username"].lower()]["avatar"] = None
                    user.account["avatar"] = None
                save_accounts()
            if room:
                await broadcast(room, {"t": "avatar", "id": user.id, "data": av})
        return

    if t == "prop" and room:
        if user.propgagged:
            return await notify(user, "Your props were taken away (propgag).")
        act = msg.get("action")
        _cap = MAX_PROPS
        if act == "wear" and valid_media_url(msg.get("url")) and len(user.props) < _cap:
            used = {p.get("slot") for p in user.props}
            free = next((i for i in range(9) if i not in used), len(user.props) % 9)
            try:
                slot = int(msg.get("slot", free))
            except Exception:
                slot = free
            user.props.append({"id": uuid.uuid4().hex[:6],
                               "name": clean_base_name(msg.get("name", "Prop"), 20),
                               "url": msg["url"],
                               "slot": max(0, min(8, slot))})
        elif act == "move":

            pid = msg.get("id")
            for p in user.props:
                if p["id"] == pid:
                    try:
                        p["slot"] = max(0, min(8, int(msg.get("slot", p.get("slot", 0)))))
                    except Exception:
                        return
                    break
            else:
                return
        elif act == "box":

            try:
                v = int(msg.get("size", AVATAR_BOX_MIN))
            except Exception:
                return
            user.box = max(AVATAR_BOX_MIN, min(AVATAR_BOX_MAX, v))
            if room:
                await broadcast(room, {"t": "box", "id": user.id, "box": user.box})
            return await notify(user, f"Avatar area: {user.box}×{user.box}")
        elif act == "layout":

            lay = msg.get("layout")
            if lay in ("grid", "single"):
                user.layout = lay
                if room:
                    await broadcast(room, {"t": "layout", "id": user.id, "layout": lay})
            return
        elif act == "remove":
            pid = msg.get("id")
            user.props = [p for p in user.props if p["id"] != pid] if pid else []
        else:
            return
        return await broadcast(room, {"t": "props", "id": user.id, "props": user.props})

    if t == "placeProp" and room:
        if not (room.loose_allowed or user.rank >= RANK_WIZARD):
            return await notify(user, "Loose props are not allowed in this room.")
        if not valid_media_url(msg.get("url")):
            return
        if len(room.loose_props) >= 120:
            return await notify(user, "There are already too many props in the room.")
        pid = uuid.uuid4().hex[:8]
        prop = {"id": pid, "url": msg["url"],
                "x": max(0, min(2000, int(msg.get("x", 100)))),
                "y": max(0, min(2000, int(msg.get("y", 100)))),
                "scale": max(0.2, min(4.0, float(msg.get("scale", 1.0)))),
                "name": clean_base_name(msg.get("name", "Prop"), 20),
                "owner": user.id, "ownerName": user.base}
        room.loose_props[pid] = prop
        if room.persistent:
            save_rooms()
        return await broadcast(room, {"t": "looseAdd", "prop": prop})

    if t == "copyProp" and room:
        src = room.loose_props.get(msg.get("id"))
        if not src:
            return
        if not (room.loose_allowed or user.rank >= RANK_WIZARD):
            return await notify(user, "Loose props are not allowed here.")
        if len(room.loose_props) >= 120:
            return await notify(user, "Too many props in the room.")
        pid = uuid.uuid4().hex[:8]
        prop = dict(src); prop["id"] = pid
        prop["x"] = max(0, min(2000, src["x"] + 30))
        prop["y"] = max(0, min(2000, src["y"] + 24))
        prop["owner"] = user.id; prop["ownerName"] = user.base
        room.loose_props[pid] = prop
        if room.persistent:
            save_rooms()
        return await broadcast(room, {"t": "looseAdd", "prop": prop})

    if t == "moveProp" and room:
        p = room.loose_props.get(msg.get("id"))
        if not p:
            return
        if p["owner"] != user.id and not can(user, "moderate"):
            return
        p["x"] = max(0, min(2000, int(msg.get("x", p["x"]))))
        p["y"] = max(0, min(2000, int(msg.get("y", p["y"]))))

        if msg.get("final") and room.persistent:
            save_rooms()
        return await broadcast(room, {"t": "looseMove", "id": p["id"],
                                      "x": p["x"], "y": p["y"]})

    if t == "deleteProp" and room:
        p = room.loose_props.get(msg.get("id"))
        if not p:
            return
        if p["owner"] != user.id and not can(user, "moderate"):
            return await notify(user, "Only the owner or a wizard may delete that.")
        room.loose_props.pop(p["id"], None)
        if room.persistent:
            save_rooms()
        return await broadcast(room, {"t": "looseRemove", "id": p["id"]})

    if t == "looseAllowed" and room:
        if not (can(user, "edit_room") or user.rank >= RANK_WIZARD):
            return await notify(user, "Only wizards can change that.")
        room.loose_allowed = bool(msg.get("on"))
        if room.persistent:
            save_rooms()
        await broadcast(room, {"t": "looseAllowed", "on": room.loose_allowed})
        return await notify(user, f"Loose props are now "
                                  f"{'allowed' if room.loose_allowed else 'blocked'}.")

    if t == "doorMove" and room:

        if not can_edit_doors(user, room):
            return
        door = room.doors.get(msg.get("id"))
        if not door:
            return
        pts = msg.get("points")
        if not isinstance(pts, list) or not (3 <= len(pts) <= 12):
            return
        clean = []
        for p in pts:
            if not (isinstance(p, list) and len(p) == 2):
                return
            try:
                clean.append([max(0, min(2000, int(p[0]))), max(0, min(2000, int(p[1])))])
            except (TypeError, ValueError):
                return
        door["points"] = clean
        return await broadcast(room, {"t": "doorMove", "id": door["id"],
                                      "points": clean}, skip=user)

    if t == "doorSave" and room:
        if not can_edit_doors(user, room):
            return await notify(user, "Only wizards and owners may edit doors.", "msg.doors.wizonly")
        door = sanitize_door(msg.get("door") or {}, (msg.get("door") or {}).get("id"))
        if not door:
            return await notify(user, "Invalid door (at least 3 corners needed).")
        if door["id"] not in room.doors and len(room.doors) >= 40:
            return await notify(user, "Too many doors in the room.")
        room.doors[door["id"]] = door
        if room.persistent:
            save_rooms()
        return await broadcast(room, {"t": "doorSet", "door": door})

    if t == "doorDelete" and room:
        if not can_edit_doors(user, room):
            return await notify(user, "Only wizards and owners may delete doors.")
        did = msg.get("id")
        if did in room.doors:
            room.doors.pop(did, None)
            if room.persistent:
                save_rooms()
            await broadcast(room, {"t": "doorRemove", "id": did})
        return

    if t == "door" and room:

        door = room.doors.get(msg.get("id"))
        if not door:
            return

        if (door.get("action") or "") == "lock":
            if not may_lock_room(user, room):
                return await notify(user, "Only the room creator "
                                          "or a wizard can lock.")
            room.operatorsonly = not room.operatorsonly
            if room.persistent:
                save_rooms()
            state = "blocked" if room.operatorsonly else "open"
            mod_log(room.name, user.base, "ROOM-LOCK", state)
            await broadcast(room, {"t": "roomLock", "on": room.operatorsonly,
                                   "by": user.base})

            await sysline(room, "🔒 Room locked" if room.operatorsonly
                                else "🔓 Room open")
            await push_rooms()
            return

        if (door.get("action") or "") == "clanstats":
            g = group_by_room(room.name) or group_of(user.base)
            return await send(user, {"t": "clanBoard", "stats": clan_stats(g)})

        _t = room_by_ref(door.get("targetId") or "") or \
             room_by_ref(door.get("target") or "")
        goto = _t.name if _t else door.get("target")
        if door.get("script"):
            ctx = SC(user, room)
            try:
                run_script(parse_handlers("ON CLICK { " + door["script"] + " }")
                           .get("CLICK", []), ctx, room.vars)
            except Exception:
                ctx = None
            if ctx:
                for line in ctx.say[:5]:
                    await broadcast(room, {"t": "chat", "from": "✦ " + room.name,
                                           "id": "room", "rank": 0, "text": line,
                                           "system": True})
                if ctx.setpos and not user.pinned:
                    user.x, user.y = ctx.setpos
                    await broadcast(room, {"t": "move", "id": user.id,
                                           "x": user.x, "y": user.y})
                if ctx.goto:
                    goto = ctx.goto
        if goto and goto in ROOMS:
            await join_room(user, goto, ROOMS[goto].password
                            if user.rank >= RANK_WIZARD else "")
        return

    if t == "draw" and room:
        if not (room.draw_allowed or user.rank >= RANK_WIZARD):
            return await notify(user, "Drawing is not allowed in this room.")
        pts = msg.get("points")
        if not isinstance(pts, list) or not (2 <= len(pts) <= 400):
            return
        clean = []
        for p in pts:
            try:
                clean.append([max(0, min(2000, int(p[0]))),
                              max(0, min(2000, int(p[1])))])
            except Exception:
                pass
        if len(clean) < 2:
            return
        col = str(msg.get("color", "#ffffff"))[:9]
        wdt = max(1, min(40, int(msg.get("width", 3))))
        stroke = {"id": uuid.uuid4().hex[:8], "by": user.base,
                  "color": col, "width": wdt, "points": clean}
        room.strokes.append(stroke)
        if len(room.strokes) > 4000:
            del room.strokes[:len(room.strokes) - 4000]
        if room.persistent:
            room._draw_n = getattr(room, "_draw_n", 0) + 1
            if room._draw_n % 20 == 0:
                save_rooms()
        return await broadcast(room, {"t": "draw", "stroke": stroke}, skip=user)

    if t == "drawClear" and room:

        if msg.get("all"):
            if not (can(user, "edit_room") or user.rank >= RANK_WIZARD):
                return await notify(user, "Only wizards may clear the whole board.")
            room.strokes = []
            await broadcast(room, {"t": "drawClear", "all": True})
        else:
            room.strokes = [s for s in room.strokes if s.get("by") != user.base]
            await broadcast(room, {"t": "drawClear", "by": user.base})
        if room.persistent:
            save_rooms()
        return

    if t == "drawAllowed" and room:
        if not (can(user, "edit_room") or user.rank >= RANK_WIZARD):
            return await notify(user, "Only wizards can toggle drawing.")
        room.draw_allowed = bool(msg.get("on"))
        if room.persistent:
            save_rooms()
        await broadcast(room, {"t": "drawAllowed", "on": room.draw_allowed})
        return await notify(user, f"Drawing is now "
                                  f"{'allowed' if room.draw_allowed else 'blocked'}.")

    if t == "offerProp" and room:
        return
        if user.propgagged:
            return await notify(user, "Your props were taken away.")
        target = users_by_id(msg.get("to"))
        if not target or target.room is not room:
            return await notify(user, "The recipient is not in the room.")
        if not valid_media_url(msg.get("url")):
            return
        oid = uuid.uuid4().hex[:10]
        OFFERS[oid] = {"from": user.id, "fromName": user.base, "to": target.id,
                       "url": msg["url"],
                       "name": clean_base_name(msg.get("name", "Prop"), 20),
                       "scale": max(0.2, min(4.0, float(msg.get("scale", 1.0)))),
                       "ts": now_ms()}
        await send(target, {"t": "propOffer", "offerId": oid,
                            "from": user.base, "name": OFFERS[oid]["name"],
                            "url": OFFERS[oid]["url"]})
        return await notify(user, f"Prop \"{OFFERS[oid]['name']}\" offered to {target.base}.")

    if t in ("acceptOffer", "declineOffer"):
        return
        off = OFFERS.pop(msg.get("offerId"), None)
        if not off or off["to"] != user.id:
            return
        offerer = users_by_id(off["from"])
        if t == "declineOffer":
            if offerer:
                await notify(offerer, f"{user.base} declined your prop offer.")
            return

        if len(user.props) < MAX_PROPS and valid_media_url(off["url"]):
            user.props.append({"id": uuid.uuid4().hex[:6], "name": off["name"],
                               "url": off["url"], "dx": 0, "dy": -44,
                               "scale": off["scale"]})
            if user.room:
                await broadcast(user.room, {"t": "props", "id": user.id,
                                            "props": user.props})
        if offerer:
            await notify(offerer, f"{user.base} accepted your prop. 🎁")
        return await notify(user, f"Prop \"{off['name']}\" received.")

    if t == "setbg" and room:

        if is_fixed_room(room):
            if not (can(user, "edit_room") or
                    (user.rank >= RANK_WIZARD and not wizard_room_blocked(user, room))):
                return await notify(user, "In fixed rooms only wizards may "
                                          "change the background.")
        elif not (can(user, "edit_room") or room.owner in (None, user.id)):
            return await notify(user, "You lack the right to change the background.")
        url = msg.get("data")
        fit = msg.get("fit")
        if fit in ("fill", "contain", "stretch", "cover"):
            room.bg_fit = fit
        if valid_media_url(url) or url is None:
            mod_log(room.name, user.base, "ROOM-BG",
                    f"new background ({'removed' if url is None else url})")
            room.bg = url
            try:
                w = int(msg.get("w", 0)); h = int(msg.get("h", 0))
                if w >= 320 and h >= 240:
                    room.room_w = max(320, min(2000, w))
                    room.room_h = max(240, min(1400, h))
            except Exception:
                pass
            save_rooms()
            await broadcast(room, {"t": "bg", "data": url, "fit": room.bg_fit,
                                   "roomW": room.room_w, "roomH": room.room_h})
        return

    if t == "setbgfit" and room:

        if is_fixed_room(room):
            if not (can(user, "edit_room") or
                    (user.rank >= RANK_WIZARD and not wizard_room_blocked(user, room))):
                return await notify(user, "In fixed rooms only wizards may "
                                          "change the background.")
        elif not (can(user, "edit_room") or room.owner in (None, user.id)):
            return await notify(user, "You lack the right to change the background.")
        fit = msg.get("fit")
        if fit in ("fill", "contain", "stretch", "cover"):
            room.bg_fit = fit
            save_rooms()
            await broadcast(room, {"t": "bg", "data": room.bg, "fit": fit})
        return

    if t == "log" and room:
        return await send(user, {"t": "log", "room": room.name, "entries": room.log})

    if t == "script" and room:

        if user.rank >= RANK_WIZARD and not wizard_room_blocked(user, room):
            room.set_script(str(msg.get("code", ""))[:20000])
            save_rooms()
            errs = getattr(room, "script_errors", []) or []
            n = sum(len(v) if isinstance(v, list) else 1
                    for v in room.handlers.values())
            if errs:
                return await notify(user, "Script saved, BUT: " +
                                          " | ".join(errs[:3]))
            return await notify(user, f"Script saved – {n} block(s), "
                                      f"language: {getattr(room,'script_lang','legacy')}.")
        return await notify(user, "Only wizards and owners may change room scripts.", "msg.script.wizonly")

    if t == "yt" and room:
        a = msg.get("action"); y = room.yt

        async def push_viewers():
            lst = [{"id": i, "name": v["name"], "mode": v.get("mode", "video")}
                   for i, v in room.yt_viewers.items() if i in room.users]
            await broadcast(room, {"t": "ytViewers", "list": lst,
                                   "videoId": y.get("videoId"),
                                   "shared": bool(y.get("shared"))})

        if a == "set":

            vid = str(msg.get("videoId", ""))[:20]
            if not re.fullmatch(r"[\w\-]{6,15}", vid):
                return
            mode = "music" if msg.get("mode") == "music" else "video"
            if msg.get("share"):

                room.yt = {"videoId": vid, "playing": True, "time": 0.0,
                           "shared": True, "mode": mode,
                           "by": user.base, "updated": now_ms()}
                room.yt_viewers = {u.id: {"name": u.base, "mode": mode}
                                   for u in room.users.values()}
                st = room.yt_now(); st.update({"t": "yt", "by": user.name,
                                               "mode": mode, "shared": True,
                                               "started": True})
                await broadcast(room, st)
                await push_viewers()
                await sysline(room, f"🎬 {user.base} is sharing "
                                    + ("music" if mode == "music" else "a video")
                                    + " in the room.")
                mod_log(room.name, user.base, "YT-SHARE", f"{vid} ({mode})")
                return

            room.yt_viewers[user.id] = {"name": user.base, "mode": mode}
            await send(user, {"t": "yt", "videoId": vid, "playing": True,
                              "time": 0.0, "solo": True, "mode": mode,
                              "by": user.name})
            await push_viewers()
            return

        if a == "join" and y.get("videoId"):

            mode = "music" if msg.get("mode") == "music" else "video"
            room.yt_viewers[user.id] = {"name": user.base, "mode": mode}
            st = room.yt_now()
            st.update({"t": "yt", "join": True, "mode": mode,
                       "by": user.name, "shared": True})
            await send(user, st)
            await push_viewers()
            return

        if a == "leave":

            room.yt_viewers.pop(user.id, None)
            await send(user, {"t": "yt", "videoId": None, "playing": False,
                              "time": 0.0, "reset": True})
            await push_viewers()
            return

        if a == "viewers":
            await push_viewers()
            return

        if a in ("play", "pause", "seek") and y.get("videoId"):

            if y.get("shared") and (y.get("by") or "").lower() != user.base.lower() \
                    and user.rank < RANK_WIZARD:
                return await notify(user, "Only the person who shared the video may control it.", "msg.media.ownercontrol")
            y["time"] = float(msg.get("time", y["time"]) or 0)
            if a != "seek":
                y["playing"] = (a == "play")
            y["updated"] = now_ms()
            st = room.yt_now(); st.update({"t": "yt", "by": user.name,
                                           "shared": bool(y.get("shared"))})

            for uid in list(room.yt_viewers.keys()):
                u2 = room.users.get(uid)
                if u2:
                    await send(u2, st)
            return

        if a == "stop":
            if y.get("shared") and (y.get("by") or "").lower() != user.base.lower() \
                    and user.rank < RANK_WIZARD:
                return await notify(user, "Only the person who shared the video may stop it.", "msg.media.ownerstop")
            room.yt = {"videoId": None, "playing": False, "time": 0.0,
                       "shared": False, "updated": now_ms()}
            room.yt_viewers.clear()
            st = room.yt_now(); st.update({"t": "yt", "by": user.name,
                                           "reset": True})
            await broadcast(room, st)
            await push_viewers()
            return
        return

    if t == "ping":
        return await send(user, {"t": "pong", "ts": now_ms()})

def _is_trusted_proxy(ip: str) -> bool:
    if not ip:
        return False
    for net in (CONFIG.get("trusted_proxies")
                or DEFAULTS["trusted_proxies"]):
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False

def real_ip(headers, fallback_ip):
    if not _is_trusted_proxy(fallback_ip):
        return fallback_ip
    xff = headers.get("x-forwarded-for", "")
    if xff:

        cand = xff.split(",")[-1].strip()
        try:
            ipaddress.ip_address(cand)
            return cand
        except ValueError:
            return fallback_ip
    return fallback_ip

async def on_connection(reader, writer):
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else "?"
    try:
        start, headers, _ = await read_headers(reader)
    except Exception:
        try: writer.close()
        except Exception: pass
        return
    ip = real_ip(headers, peer_ip)

    if not (ip_is_known_good(ip) or RL_CONNECT.allow(ip)):
        try:
            if "websocket" not in headers.get("upgrade", "").lower():
                await http_respond(writer, "429 Too Many Requests",
                                   "Too many connections. Please wait a moment.")
            else:
                writer.close()
        except Exception:
            pass
        return

    if "websocket" in headers.get("upgrade", "").lower() \
            and headers.get("sec-websocket-key"):

        if CONFIG.get("test_mode") and not has_test_pass(headers):
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            try:
                await writer.drain()
            finally:
                writer.close()
            return
        ws = MiniWS(reader, writer, headers["sec-websocket-key"])
        ws.fwd_ip = ip
        await writer.drain()
        user = User(ws)
        user.ip = ws.ip
        print(f"[+] WS {ws.ip} → {user.id}")
        mod_log("-", "-", "CONNECT", f"id={user.id} ip={safe_ip(ws.ip)}")
        try:
            async for raw in ws_iter(ws):
                try:
                    m = json.loads(raw)
                except Exception:
                    continue
                if isinstance(m, dict):
                    await handle(user, m)
        except (ConnectionClosed, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            print(f"[-] gone {user.name} ({user.id})")
            mod_log(user.room.name if user.room else "-", user.base, "DISCONNECT",
                    f"id={user.id} ip={safe_ip(getattr(user, 'ip', None))} "
                    f"member={bool(user.account)} rang={RANK_NAME[user.rank]}")
            WATCHERS.discard(user)
            await leave_room(user, quitting=True)
            await push_rooms()
            await ws.close()
        return

    await handle_http(reader, writer, start, headers, client_ip=ip)

async def ws_iter(ws):
    while True:
        try:
            yield await ws.recv()
        except ConnectionClosed:
            return

OAUTH_STATES: dict[str, dict] = {}
_JWKS_CACHE: dict[str, dict] = {}

OAUTH_PROVIDERS = {
    "google": {
        "name": "Google",
        "auth": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "jwks": "https://www.googleapis.com/oauth2/v3/certs",
        "issuers": ("https://accounts.google.com", "accounts.google.com"),
        "scope": "openid email profile",
    },
    "apple": {
        "name": "Apple",
        "auth": "https://appleid.apple.com/auth/authorize",
        "token": "https://appleid.apple.com/auth/token",
        "jwks": "https://appleid.apple.com/auth/keys",
        "issuers": ("https://appleid.apple.com",),
        "scope": "openid email name",
    },

    "discord": {
        "name": "Discord",
        "auth": "https://discord.com/oauth2/authorize",
        "token": "https://discord.com/api/oauth2/token",
        "userinfo": "https://discord.com/api/users/@me",
        "scope": "identify email",
        "fields": {"sub": "id", "email": "email",
                   "name": ("global_name", "username")},
    },
    "github": {
        "name": "GitHub",
        "auth": "https://github.com/login/oauth/authorize",
        "token": "https://github.com/login/oauth/access_token",
        "userinfo": "https://api.github.com/user",
        "scope": "read:user user:email",
        "fields": {"sub": "id", "email": "email",
                   "name": ("name", "login")},
    },
}

LANG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lang")
if not os.path.isdir(LANG_DIR):
    LANG_DIR = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "lang")

def lang_read(code: str) -> dict:
    p = os.path.join(LANG_DIR, code + ".lang")
    out = {}
    try:
        with open(p, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#") or " = " not in ln:
                    continue
                k, v = ln.split(" = ", 1)
                out[k.strip()] = v.strip()
    except Exception:
        pass
    return out

def lang_list() -> list:
    out = []
    try:
        for fn in sorted(os.listdir(LANG_DIR)):
            if not fn.endswith(".lang"):
                continue
            code = fn[:-5]
            d = lang_read(code)
            out.append({"code": code,
                        "name": d.get("lang.name", code),
                        "flag": d.get("lang.flag", "🌐")})
    except Exception:
        pass
    return out

def oauth_cfg(provider: str) -> dict:
    return (CONFIG.get("oauth") or {}).get(provider) or {}

def oauth_enabled(provider: str) -> bool:
    c = oauth_cfg(provider)
    base = (CONFIG.get("oauth") or {}).get("public_url") or ""
    if not base or not c.get("client_id"):
        return False
    if provider == "google":
        return bool(c.get("client_secret"))
    if provider == "apple":
        return bool(c.get("team_id") and c.get("key_id")
                    and c.get("private_key"))

    if provider in OAUTH_PROVIDERS:
        return bool(c.get("client_secret"))
    return False

def oauth_redirect_uri() -> str:
    base = ((CONFIG.get("oauth") or {}).get("public_url") or "").rstrip("/")
    return base + "/auth/callback"

def _b64url_dec(v: str) -> bytes:
    v = str(v)
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))

def _int_from_b64(v: str) -> int:
    return int.from_bytes(_b64url_dec(v), "big")

async def _http_json(url: str, data: bytes | None = None,
                     headers: dict | None = None) -> dict:
    def _do():
        req = urllib.request.Request(url, data=data,
                                     headers=headers or {})
        with urllib.request.urlopen(req, timeout=12) as r:
            return json.loads(r.read().decode("utf-8"))
    return await asyncio.get_running_loop().run_in_executor(None, _do)

async def oauth_jwks(url: str) -> list:
    c = _JWKS_CACHE.get(url)
    if c and now_ms() - c["ts"] < 3600_000:
        return c["keys"]
    data = await _http_json(url)
    keys = data.get("keys") or []
    _JWKS_CACHE[url] = {"ts": now_ms(), "keys": keys}
    return keys

def _rsa_pkcs1_verify(n: int, e: int, msg: bytes, sig: bytes,
                      hashname: str) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n)
    em = m.to_bytes(k, "big")

    prefix = {
        "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
        "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
        "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    }[hashname]
    digest = hashlib.new(hashname, msg).digest()
    expect = b"\x00\x01" + b"\xff" * (k - len(prefix) - len(digest) - 3) \
        + b"\x00" + prefix + digest
    return hmac.compare_digest(em, expect)

async def oauth_userinfo(provider: str, access_token: str) -> dict | None:
    meta = OAUTH_PROVIDERS.get(provider) or {}
    url = meta.get("userinfo")
    if not url or not access_token:
        return None
    try:
        prof = await _http_json(url, None, {
            "Authorization": "Bearer " + access_token,
            "Accept": "application/json",
            "User-Agent": "Pixplace",
        })
    except Exception as e:
        print("OAuth profile error:", e)
        return None
    if not isinstance(prof, dict):
        return None
    f = meta.get("fields") or {}

    def pick(spec):
        if isinstance(spec, tuple):
            for k in spec:
                if prof.get(k):
                    return prof[k]
            return ""
        return prof.get(spec) or ""

    sub = pick(f.get("sub", "id"))
    if not sub:
        return None
    email = pick(f.get("email", "email"))

    if provider == "github" and not email:
        try:
            mails = await _http_json("https://api.github.com/user/emails", None, {
                "Authorization": "Bearer " + access_token,
                "Accept": "application/json",
                "User-Agent": "Pixplace",
            })
            if isinstance(mails, list):
                email = next((m.get("email") for m in mails
                              if isinstance(m, dict) and m.get("primary")
                              and m.get("verified")), "")
        except Exception:
            email = ""
    return {"sub": str(sub), "email": str(email or ""),
            "name": str(pick(f.get("name", "name")) or "")}

async def oauth_verify_id_token(provider: str, id_token: str) -> dict | None:
    try:
        h_b64, p_b64, s_b64 = id_token.split(".")
        header = json.loads(_b64url_dec(h_b64))
        payload = json.loads(_b64url_dec(p_b64))
        sig = _b64url_dec(s_b64)
    except Exception:
        return None
    meta = OAUTH_PROVIDERS.get(provider) or {}
    alg = header.get("alg")
    if alg not in ("RS256", "RS384", "RS512"):
        return None
    keys = await oauth_jwks(meta.get("jwks", ""))
    jwk = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if not jwk or jwk.get("kty") != "RSA":
        return None
    n, e = _int_from_b64(jwk["n"]), _int_from_b64(jwk["e"])
    signed = (h_b64 + "." + p_b64).encode()
    hashname = {"RS256": "sha256", "RS384": "sha384",
                "RS512": "sha512"}[alg]
    if not _rsa_pkcs1_verify(n, e, signed, sig, hashname):
        return None
    if payload.get("iss") not in meta.get("issuers", ()):
        return None
    aud = payload.get("aud")
    want = oauth_cfg(provider).get("client_id")
    if (aud if isinstance(aud, str) else "") != want and want not in (aud or []):
        return None
    if int(payload.get("exp", 0)) < int(time.time()) - 60:
        return None
    return payload

def _apple_client_secret() -> str:
    c = oauth_cfg("apple")
    header = {"alg": "ES256", "kid": c.get("key_id")}
    now = int(time.time())
    payload = {"iss": c.get("team_id"), "iat": now, "exp": now + 3600,
               "aud": "https://appleid.apple.com", "sub": c.get("client_id")}
    b64 = lambda o: base64.urlsafe_b64encode(
        json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
    signing_input = (b64(header) + "." + b64(payload)).encode()

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils as asu
        key = serialization.load_pem_private_key(
            c["private_key"].encode(), password=None)
        der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, sv = asu.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + sv.to_bytes(32, "big")
    except Exception as ex:
        raise RuntimeError("Apple sign-in needs the package \"cryptography\" "
                           "(pip install cryptography): " + str(ex))
    return signing_input.decode() + "." + \
        base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def oauth_account_for(provider: str, sub: str, email: str,
                      display: str) -> dict:
    key = f"{provider}:{sub}"
    for acc in ACCOUNTS.values():
        if acc.get("oauth") == key:
            return acc

    base = clean_base_name(display or (email or "").split("@")[0] or "")
    if not base or not name_free(base):
        base = guest_name()
        while not name_free(base):
            base = guest_name()
    _tok = uuid.uuid4().hex + uuid.uuid4().hex
    acc = {"username": base,
           "token_hash": token_hash(_tok),
           "rank": RANK_MEMBER, "created": now_ms(),
           "oauth": key, "email": email or "", "points": 0}
    ACCOUNTS[base.lower()] = acc
    save_accounts()

    acc["_plain_token"] = _tok
    return acc

def oauth_result_page(acc, err: str | None) -> str:
    if err:
        payload = json.dumps({"ok": False, "error": err})
        body = f"<h1>Sign-in failed</h1><p>{err}</p>"
    else:
        payload = json.dumps({"ok": True, "name": acc["username"],
                              "token": acc.get("_plain_token", "")})
        body = (f"<h1>Welcome, {acc['username']}!</h1>"
                "<p>You can close this window \u2013 the chat takes over "
                "automatically.</p>")
    return ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
            "<title>Pixplace</title><style>" + PPS_DOC_CSS + "</style>"
            "</head><body><main>" + body + "</main><script>"
            "try{if(window.opener){window.opener.postMessage("
            "{pp_oauth:" + payload + "},'*');setTimeout(()=>window.close(),900);}"
            "else{localStorage.setItem('pp_oauth_result'," +
            json.dumps(payload) + ");location.href='/app';}}catch(e){}"
            "</script></body></html>")

LEGAL_DEFAULTS = {
    "operator_name": "[Operator full name]",
    "operator_address": "[Street, number, postcode, city]",
    "operator_country": "[Country]",
    "operator_mail": "[contact@your-domain.example]",
    "operator_agent": "",
    "hosting": "[Name and address of the hosting provider]",
    "minage": "16",
    "retention_days": "30",
}

def page_lang(target: str) -> str:
    if "?" in target:
        q = dict(urllib.parse.parse_qsl(target.split("?", 1)[1]))
        code = (q.get("lang") or "").lower()[:2]
        if code == "en":
            return code
    return "en"

def legal(key: str) -> str:
    return str((CONFIG.get("legal") or {}).get(key)
               or LEGAL_DEFAULTS.get(key, ""))

def legal_page(kind: str, lang: str = "en") -> str:
    name = legal("operator_name")
    addr = legal("operator_address")
    land = legal("operator_country")
    mail = legal("operator_mail")
    agent = legal("operator_agent")
    host = legal("hosting")
    minage = legal("minage")
    mode = CONFIG.get("moderation_mode") or (
        "full" if CONFIG.get("moderation_logging") else "off")
    try:
        keep = int(CONFIG.get("log_retention_days") or 0)
    except Exception:
        keep = 0
    days = str(keep) if keep > 0 else legal("retention_days")
    srv = CONFIG.get("servername", "Pixplace")

    todo = ("<div style=\"background:#3a2a12;border:1px solid #7a5a20;"
            "border-radius:10px;padding:12px 14px;margin:0 0 18px\">"
            "<b>Note to the operator:</b> Fields marked with [ ] are still "
            "placeholders. Fill them in before going public "
            "(<code>palace_config.json</code> \u2192 <code>legal</code>). "
            "See <code>LEGAL.md</code>."
            "</div>") if "[" in (name + addr + mail + host) else ""

    if mode == "off":
        log_row = ("<tr><td>Chat messages</td><td>delivered to the people "
                   "present only \u2013 <b>not stored</b></td>"
                   "<td>Performance of the service</td>"
                   "<td>not stored</td></tr>")
        log_block = """
    <h2>3. Moderation and logging</h2>
    <p><b>Conversation content is not stored.</b> Messages are delivered only
       to the people present in the room and then discarded.</p>
    <ul>
      <li>There are <b>no logs</b> of conversations. Reading them back is
          technically impossible &ndash; even for the operator.</li>
      <li>Moderation is <b>automated only, at the moment of sending</b>, using
          filters (blocked words, message floods).</li>
      <li>Automated methods including artificial intelligence may be used;
          <b>currently they are not</b>.</li>
      <li>Consequence: reports about past incidents cannot be verified from
          logs. Please report incidents while they are happening.</li>
    </ul>"""
    elif mode == "events":
        log_row = ("<tr><td>Chat messages</td><td>delivered to the people "
                   "present only \u2013 <b>content is not "
                   "stored</b></td><td>Performance of the service</td>"
                   "<td>not stored</td></tr>"
                   "<tr><td>Events (sign-in/out, room changes, bans)"
                   "</td><td>Operational security, abuse prevention</td>"
                   "<td>Legitimate interest</td>"
                   f"<td>{days} days</td></tr>")
        log_block = f"""
    <h2>3. Moderation and logging</h2>
    <p><b>Conversation content is not stored.</b> Only technical events are
       recorded: sign-ins and sign-outs, room changes, renames and moderation
       actions.</p>
    <ul>
      <li>This event data is <b>deleted automatically after {days}
          days</b>.</li>
      <li>What someone wrote is <b>not readable</b> &ndash; neither by
          moderators nor by the operator.</li>
      <li>Content moderation is <b>automated at the moment of
          sending</b> using filters.</li>
      <li>Automated methods including artificial intelligence may be used;
          <b>currently they are not</b>.</li>
      <li>Conversations are <b>not monitored</b>.</li>
    </ul>"""
    else:
        log_row = ("<tr><td>Chat messages in rooms</td>"
                   "<td>Delivery to those present, moderation after a "
                   "report</td><td>Performance of the service and legitimate "
                   "interest</td>"
                   f"<td>{days} days</td></tr>")
        log_block = f"""
    <h2>3. Moderation and logging</h2>
    <p>Rooms are logged. The notice &ldquo;moderated &amp; logged&rdquo; is
       permanently visible in the chat window. Logs are <b>deleted
       automatically after {days} days</b>.</p>
    <ul>
      <li>Moderation is <b>mostly automated</b> using filters (e.g. blocked
          words, message floods).</li>
      <li>Automated methods including artificial intelligence may be used;
          <b>currently they are not</b>. Any change will be announced here
          in advance.</li>
      <li>There is <b>no permanent monitoring</b> of conversations. Nobody
          reads along continuously.</li>
      <li>Logs are viewed <b>only when there is a reason</b>: after a report,
          in case of concrete suspicion of violations, or to fix
          malfunctions.</li>
      <li>No automated decision with legal effect within the meaning of
          Art. 22 GDPR takes place.</li>
    </ul>"""

    if kind == "imprint":
        body = f"""
    <h1>Imprint</h1>
    {todo}
    <h2>Provider of this service</h2>
    <p>{name}<br>{addr}<br>{land}</p>
    <p>E-mail: <a href="mailto:{mail}">{mail}</a></p>
    {'<h2>Authorized agent for service of process</h2><p>' + agent + '</p>' if agent else ''}
    <h2>Responsible for the content</h2>
    <p>{name}, address as above.</p>
    <h2>Nature of the service</h2>
    <p>{srv} is a privately operated, non-commercial hobby project. No fees
       are charged, no advertising is served and no data is sold.</p>
    <h2>User content</h2>
    <p>The texts, images and rooms visible in the chat come from the users.
       The provider does not adopt this content as its own and gives no
       guarantee of its accuracy or lawfulness. Users are responsible for
       their own content under general law; there is no obligation to monitor
       third-party content generally.</p>
    <h2>Reports</h2>
    <p>Please report unlawful content to
       <a href="mailto:{mail}">{mail}</a>. After a concrete notice, the
       content in question will be reviewed and removed if necessary.
       In the chat you can reach moderation directly with
       <code>::page&nbsp;&lt;text&gt;</code>.</p>
    <h2>Availability</h2>
    <p>There is no entitlement to availability or to the preservation of
       content or accounts. Operation may be restricted or discontinued at
       any time.</p>
"""
    elif kind == "privacy":
        body = f"""
    <h1>Privacy Policy</h1>
    {todo}
    <p class="lead">In short: only the data needed to run the chat is
       processed. There is no advertising, no tracking, no sharing for
       advertising purposes and no sale of data.</p>

    <h2>1. Controller</h2>
    <p>{name}<br>{addr}<br>{land}<br>
       E-mail: <a href="mailto:{mail}">{mail}</a></p>

    <h2>2. What data is processed</h2>
    <table>
      <tr><th>Data</th><th>Purpose</th><th>Legal basis</th><th>Retention</th></tr>
      <tr><td>IP address (when connecting)</td>
          <td>Establishing the connection, abuse prevention, bans</td>
          <td>Legitimate interest</td><td>up to {days} days</td></tr>
      <tr><td>Chosen name, rank, room</td>
          <td>Display in the chat</td>
          <td>Performance of the service</td><td>Duration of the session</td></tr>
      {log_row}
      <tr><td>Member account (name, access key, points)</td>
          <td>Recognition, name reservation</td>
          <td>Performance of the service</td><td>until deletion</td></tr>
      <tr><td>Uploaded images (avatars, backgrounds)</td>
          <td>Display in the chat</td>
          <td>Performance of the service</td><td>until deletion</td></tr>
      <tr><td>Sign-in via Google/Apple (if used)</td>
          <td>Linking to an account</td>
          <td>Performance of the service</td><td>until deletion</td></tr>
    </table>
    <p>There are <b>no</b> analytics services, advertising networks, tracking
       pixels or profiling. The browser stores only technically necessary
       information (e.g. chosen language, avatar bag, access key) &ndash; it
       does not leave the device without being asked.</p>
{log_block}

    <h2>4. Recipients</h2>
    <p>Technical hosting is provided by: {host}. The host processes data as a
       processor. Data is passed on to other third parties only if there is
       a legal obligation.</p>

    <h2>5. Your rights</h2>
    <p>Where applicable (e.g. under the GDPR) you have the right of access
       (Art. 15), rectification (Art. 16), erasure (Art. 17), restriction
       (Art. 18), data portability (Art. 20) and objection (Art. 21). You
       also have the right to lodge a complaint with a data protection
       supervisory authority.</p>
    <p><b>Access and deletion:</b> A request to
       <a href="mailto:{mail}">{mail}</a> is enough. Requests are answered
       <b>within 30 days</b>. Please state the name used in the chat so that
       the data can be matched.</p>
    <p>A member account can be deleted at any time. Name, access key and
       associated points are then removed.</p>

    <h2>6. Minimum age</h2>
    <p>Use is intended for people aged {minage} and over. Younger people may
       use the service only with the consent of their legal guardians.</p>

    <h2>7. Security</h2>
    <p>Connections should always be encrypted (HTTPS/WSS). Access keys are not
       displayed in plain text except at the explicit request of the
       authorized person themselves.</p>

    <h2>8. Changes</h2>
    <p>This policy is updated when the processing changes. The version
       published here applies.</p>
"""
    else:
        body = f"""
    <h1>Terms of Use</h1>
    {todo}
    <p class="lead">{srv} is a private hobby project. Participation is
       voluntary and at your own risk.</p>

    <h2>1. Participation</h2>
    <p>Use is free and intended for people aged {minage} and over. There is
       no entitlement to access, availability or preservation of content and
       accounts.</p>

    <h2>2. What is not allowed</h2>
    <ul>
      <li>Unlawful content of any kind, in particular calls to violence,
          incitement to hatred, depictions of sexualized violence and
          content that endangers minors.</li>
      <li>Harassment, threats, insults, exposing other people.</li>
      <li>Publishing personal data of third parties without their
          consent.</li>
      <li>Copyright infringement in images, videos and music.</li>
      <li>Advertising, spam, message floods, automated mass access.</li>
      <li>Attempts to bypass protection mechanisms, bans or permissions.</li>
    </ul>

    <h2>3. User content</h2>
    <p>The person posting content is responsible for it. By posting, they
       confirm that they hold the necessary rights. The provider does not
       adopt this content as its own.</p>

    <h2>4. Moderation</h2>
    <p>Moderation is mostly automated using filters. Content may be removed
       without notice and access may be restricted or blocked if these terms
       are violated. A reason will be given on request where possible.</p>
    <p>Please report issues in the chat via <code>::page</code> or to
       <a href="mailto:{mail}">{mail}</a>.</p>

    <h2>5. Liability</h2>
    <p>The provider is liable under the statutory provisions for intent and
       gross negligence and for injury to life, body and health. Otherwise
       liability &ndash; in particular for data loss, downtime and third-party
       content &ndash; is excluded to the extent permitted by law. Liability
       that cannot be excluded by law remains unaffected.</p>

    <h2>6. Changes and termination</h2>
    <p>These terms may be changed; the version published at the time applies.
       Operation may be discontinued at any time. Accounts may be deleted
       without stating reasons if they are unused for a long time or violate
       these terms.</p>

    <h2>7. Governing law</h2>
    <p>The law of the operator's country applies, unless mandatory provisions
       of the user's country of residence take precedence.</p>
"""

    nav = ('<nav><b>Pixplace</b>'
           '<a href="/">Home</a> \u00b7 '
           '<a href="/imprint">Imprint</a> \u00b7 '
           '<a href="/privacy">Privacy</a> \u00b7 '
           '<a href="/terms">Terms</a> \u00b7 '
           '<a href="/app">Chat</a></nav>')
    titles = {"imprint": "Imprint", "privacy": "Privacy",
              "terms": "Terms of use"}
    return ("<!DOCTYPE html><html lang=\"en\">"
            "<head><meta charset=\"UTF-8\">"
            "<meta name=\"viewport\" "
            "content=\"width=device-width,initial-scale=1\">"
            f"<title>Pixplace \u2013 {titles.get(kind, 'Legal')}</title>"
            f"<style>{PPS_DOC_CSS}</style></head><body>"
            + nav + "<main>" + body + "</main></body></html>")

def _pps_doc_body(admin: bool) -> str:
    cmds = [
        ("SAY \"text\"", "The room speaks – everyone in the room sees it.",
         'SAY "Welcome, {user}!"'),
        ("TOAST \"text\"", "Short notice that only the triggering person sees.",
         'TOAST "Please keep it down."'),
        ("WHISPER \"text\"", "The room whispers to the triggering person only.",
         'WHISPER "The key is on the left."'),
        ("GOTO room", "Sends the person to another room.",
         "GOTO Plaza"),
        ("SET name value", "Set a room variable (stays stored in the room).",
         "SET door open"),
        ("ADD name number", "Increase a number variable (negative works too).",
         "ADD visits 1"),
        ("IF a comparison b … END", "Condition. Comparisons: == != &gt; &lt; &gt;= &lt;= CONTAINS.",
         'IF {rank} &gt;= wizard\n  SAY "Hello wizard"\nEND'),
        ("ELSE", "Else branch inside an IF block.", "ELSE"),
        ("MOVE x y", "Places the person at a position in the room.", "MOVE 450 300"),
        ("LOCK / UNLOCK", "Lock the room for non-wizards or release it.", "LOCK"),
        ("POINTS n", "Gives the person's guild points (max. 50 per trigger).",
         "POINTS 5"),
        ("ANNOUNCE \"text\"", "Message to all members of the guild/clan.",
         'ANNOUNCE "Meeting at 8 pm"'),
        ("STOP", "Aborts the block (suppresses follow-up actions).", "STOP"),
    ]
    ph = [("{user}", "Name without rank star"), ("{name}", "Display name with star"),
          ("{room}", "Room name"), ("{roomid}", "Room ID"),
          ("{rank}", "user | member | wizard | owner"),
          ("{group}", "The person's guild/clan"),
          ("{grouprank}", "Rank name within the guild"),
          ("{users}", "Number of people in the room"),
          ("{text}", "The spoken text (for ON SAY)"),
          ("{var.NAME}", "Value of a room variable")]
    rows = "".join(
        f"<tr><td><code>{c}</code></td><td>{d}</td>"
        f"<td><pre>{e}</pre></td></tr>" for c, d, e in cmds)
    prow = "".join(f"<tr><td><code>{a}</code></td><td>{b}</td></tr>" for a, b in ph)
    extra = ""
    if admin:
        extra = """
    <h2>Setting up sign-in with Google / Apple</h2>
    <p>Without an entry the feature is off – the buttons do not appear at all.
       To enable it, edit <code>palace_config.json</code>:</p>
<pre>"oauth": {
  "public_url": "https://chat.example.com",
  "google": { "client_id": "…apps.googleusercontent.com",
              "client_secret": "…" },
  "apple":  { "client_id": "com.example.chat", "team_id": "ABCDE12345",
              "key_id": "XYZ9876543", "private_key": "-----BEGIN PRIVATE KEY-----…" }
}</pre>
    <ul>
      <li>Register the <b>redirect URL</b> with both providers:
          <code>&lt;public_url&gt;/auth/callback</code></li>
      <li><b>HTTPS is required.</b> Google and Apple do not accept
          <code>http://</code> addresses (except localhost for Google).</li>
      <li>Google: create the credentials in the Google Cloud Console under
          &ldquo;APIs &amp; Services → Credentials&rdquo; as an <i>OAuth client ID</i>
          (web application).</li>
      <li>Apple: in the Apple Developer portal create a <i>Services ID</i> and a
          <i>Sign in with Apple</i> key (.p8). Apple additionally needs the
          Python package <code>cryptography</code>
          (<code>pip install cryptography</code>); Google works without it.</li>
      <li>The signature (RS256 against the provider's keys), issuer, audience
          and expiry are verified. Tokens with
          <code>alg: none</code> are rejected.</li>
      <li>Linking uses the provider's stable identifier <code>sub</code>, not
          the e-mail address – so an address change has no effect.</li>
    </ul>

    <h2>For owners: operation &amp; limits</h2>
    <ul>
      <li>Scripts run <b>server-side</b>. A client cannot bypass them.</li>
      <li>Max. <b>500 steps</b> per trigger, max. <b>400 lines</b> per room –
          infinite loops are therefore impossible.</li>
      <li><b>Several ON blocks</b> per event are allowed (e.g. one per keyword).</li>
      <li>Output is limited: 5× SAY, 3× TOAST, 3× WHISPER, 2× ANNOUNCE.</li>
      <li><code>POINTS</code> is capped at 50 per trigger.</li>
      <li>Permissions: only <b>wizards</b> and <b>owners</b> may save scripts.
          This is checked in <code>t=&quot;script&quot;</code> and
          <code>t=&quot;doorSave&quot;</code>.</li>
      <li>Old rooms using the earlier bracket syntax keep working unchanged;
          the language is detected automatically.</li>
      <li>Every save is written to the moderation log.</li>
    </ul>
    <h2>Checking without risk</h2>
    <p>The client sends <code>{"t":"scriptCheck","src":"…"}</code> and receives
       <code>{"ok":true|false,"errors":[…],"events":[…]}</code> back. The
       script editor in the chat uses exactly this for live checking.</p>
"""
    return f"""
    <h1>PPScript – {"Admin wiki" if admin else "Manual"}</h1>
    <p class="lead">The scripting language for <b>rooms</b> and <b>doors</b>.
       One line = one command. Blocks start with <code>ON …</code> and
       end with <code>END</code>. Everything after <code>#</code> is a comment.
       Only <b>wizards</b> and <b>owners</b> can save scripts.</p>

    <h2>Basic structure</h2>
<pre>ON ENTER
  SAY "Welcome, {{user}}!"
END</pre>

    <h2>Events</h2>
    <table>
      <tr><th>Event</th><th>When</th></tr>
      <tr><td><code>ON ENTER</code></td><td>someone enters the room</td></tr>
      <tr><td><code>ON LEAVE</code></td><td>someone leaves the room</td></tr>
      <tr><td><code>ON SAY</code></td><td>someone writes something</td></tr>
      <tr><td><code>ON SAY "word"</code></td>
          <td>only if the text contains <i>word</i></td></tr>
      <tr><td><code>ON DOOR</code></td><td>a door is used</td></tr>
      <tr><td><code>ON TIMER</code></td><td>time-controlled (reserved)</td></tr>
    </table>

    <h2>Commands</h2>
    <table><tr><th>Command</th><th>Effect</th><th>Example</th></tr>{rows}</table>

    <h2>Placeholders</h2>
    <table><tr><th>Placeholder</th><th>Meaning</th></tr>{prow}</table>

    <h2>Example 1 – Greeting with a counter</h2>
<pre>ON ENTER
  ADD visits 1
  SAY "Welcome, {{user}}! You are visitor no. {{var.visits}}."
END</pre>

    <h2>Example 2 – Password door</h2>
<pre># Whoever says "sesame” enters the gallery
ON SAY "sesame"
  SAY "The door opens …"
  GOTO Gallery
END</pre>

    <h2>Example 3 – Wizards only</h2>
<pre>ON ENTER
  IF {{rank}} &gt;= wizard
    TOAST "Tools unlocked."
  ELSE
    SAY "Nice to have you here, {{user}}."
  END
END</pre>

    <h2>Example 4 – Guild hall with a reward</h2>
<pre>ON ENTER
  IF {{group}} != ""
    SAY "{{group}} greets {{grouprank}} {{user}}!"
    POINTS 2
  ELSE
    SAY "This hall belongs to a guild."
  END
END</pre>

    <h2>Example 5 – Door switch</h2>
<pre>ON DOOR
  IF {{var.door}} == open
    GOTO Cinema
  ELSE
    TOAST "Locked. Say "sesame”."
  END
END

ON SAY "sesame"
  SET door open
  SAY "Click."
END</pre>
{extra}
"""

PPS_DOC_CSS = """
:root{--bg:#08070c;--panel:rgba(23,19,32,.72);--panel-2:#1f1a2b;
  --line:rgba(150,110,225,.18);--line-2:rgba(150,110,225,.32);
  --ink:#f1ecfb;--dim:#a89dc0;--faint:#746a8c;
  --accent:#a855f7;--accent-2:#c77dff;--accent-3:#7c3aed}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.7 'Inter',system-ui,Segoe UI,sans-serif;letter-spacing:-.005em;
  -webkit-font-smoothing:antialiased;position:relative}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(58% 46% at 12% -6%,rgba(124,58,237,.18),transparent 62%),
    radial-gradient(50% 42% at 94% 4%,rgba(168,85,247,.13),transparent 60%),var(--bg)}
main{max-width:900px;margin:0 auto;padding:32px 22px 72px}
h1{font-size:29px;margin:0 0 12px;font-weight:780;letter-spacing:-.03em;
  background:linear-gradient(180deg,#fff 25%,#cdb4f0 80%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
h2{font-size:19px;margin:30px 0 10px;color:var(--accent-2);font-weight:680;
  letter-spacing:-.02em}
h3{font-size:16px;margin:22px 0 8px;font-weight:650}
p.lead{color:var(--dim);font-size:16px}
code{background:var(--panel-2);border:1px solid var(--line);border-radius:6px;
  padding:2px 6px;font-size:13px;color:#f0c9a0;
  font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace}
pre{background:rgba(16,13,24,.8);border:1px solid var(--line);border-radius:11px;
  padding:14px 16px;overflow:auto;font-size:13px;color:#e5dbff;
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;line-height:1.6}
pre code{background:none;border:0;padding:0;color:inherit}
table{width:100%;border-collapse:collapse;margin:8px 0 6px;
  background:var(--panel);border:1px solid var(--line);border-radius:11px;
  overflow:hidden}
th,td{border-bottom:1px solid var(--line);padding:9px 11px;
  text-align:left;vertical-align:top;font-size:13.5px}
tr:last-child td{border-bottom:0}
th{color:var(--dim);font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;
  background:rgba(168,85,247,.07)}
td pre{margin:0;border:0;background:none;padding:0}
a{color:var(--accent-2);text-decoration:none;transition:color .18s ease}
a:hover{color:#e2c4ff}
ul,ol{padding-left:22px}
li{margin:5px 0}
hr{border:0;border-top:1px solid var(--line);margin:26px 0}
blockquote{margin:14px 0;padding:12px 16px;border-left:3px solid var(--accent);
  background:rgba(168,85,247,.08);border-radius:0 10px 10px 0;color:var(--dim)}
nav{background:linear-gradient(180deg,rgba(12,10,18,.9),rgba(12,10,18,.66));
  backdrop-filter:blur(18px) saturate(150%);
  -webkit-backdrop-filter:blur(18px) saturate(150%);
  border-bottom:1px solid var(--line);padding:14px 22px;position:sticky;top:0;z-index:20}
nav b{margin-right:16px;font-weight:750;letter-spacing:-.02em}
nav a{margin-right:14px;font-size:14px}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
"""

def pps_doc_page(admin: bool, lang: str = "en") -> str:
    title = "PPScript – Admin wiki" if admin else "PPScript – Manual"
    note = ""
    return ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{title}</title><style>{PPS_DOC_CSS}</style></head><body>"
            "<nav><b>Pixplace</b>"
            f"<a href=\"/manual?lang={lang}\">Manual</a> · "
            f"<a href=\"/wiki?lang={lang}\">Admin wiki</a> · "
            "<a href=\"/app\">Chat</a>"
            "</nav><main>"
            + note + _pps_doc_body(admin) +
            "</main></body></html>")

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pixplace – Admin</title>
<style>
:root{--bg:#08070c;--panel:rgba(23,19,32,.74);--panel-solid:#17131f;
  --line:rgba(150,110,225,.18);--line-2:rgba(150,110,225,.32);
  --ink:#f1ecfb;--dim:#a89dc0;--faint:#746a8c;
  --accent:#a855f7;--accent-2:#c77dff;--accent-3:#7c3aed;
  --accent-soft:rgba(168,85,247,.14);
  --ok:#33b36b;--warn:#e0a63a;--danger:#e05a4a;--wiz:#c77dff;--own:#e0a63a}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(58% 46% at 10% -6%,rgba(124,58,237,.18),transparent 62%),
    radial-gradient(50% 42% at 95% 4%,rgba(168,85,247,.13),transparent 60%),var(--bg)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,'Segoe UI',sans-serif;background:var(--bg);color:var(--ink);font-size:14px}
a{color:var(--accent)}
.wrap{max-width:920px;margin:0 auto;padding:24px 18px}
h1{font-size:22px;margin-bottom:4px}h1 .b{color:var(--accent)}
.sub{color:var(--dim);margin-bottom:20px;font-size:13px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:18px;margin-bottom:16px}
.card h2{font-size:15px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
label{display:block;font-size:12px;color:var(--dim);margin:10px 0 4px}
input,textarea,select{width:100%;background:var(--bg);border:1px solid var(--line);
  color:var(--ink);border-radius:8px;padding:8px 10px;font:inherit}
textarea{resize:vertical;min-height:80px}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1;min-width:120px}
button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:9px 16px;
  font:inherit;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.1)}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
button.danger{background:var(--danger)}
button.sm{padding:5px 10px;font-size:12px}
.toggle{display:flex;align-items:center;gap:10px;margin-top:8px}
.toggle input{width:auto}
table{width:100%;border-collapse:collapse;margin-top:6px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--dim);font-weight:600}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700}
.pill.user{background:#2b2e3d;color:var(--dim)}
.pill.member{background:rgba(168,85,247,.16);color:#8fb4ff}
.pill.wizard{background:rgba(38,194,166,.15);color:var(--wiz)}
.pill.owner{background:rgba(224,166,58,.15);color:var(--own)}
#perms td{text-align:center}#perms td:first-child{text-align:left;font-weight:500}
#perms input{width:auto;cursor:pointer;transform:scale(1.2)}
#perms .lock{color:var(--dim)}
.on{color:var(--ok);font-size:11px}
.muted{color:var(--dim);font-size:12px}
#login{max-width:360px;margin:12vh auto}
#log{background:#0c0d12;border:1px solid var(--line);border-radius:8px;padding:10px;
  font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;
  max-height:340px;overflow:auto;color:#cfd3e6}
.msg{font-size:12px;margin-top:8px;min-height:16px}
.msg.ok{color:var(--ok)}.msg.err{color:var(--danger)}
.hide{display:none}
.flex{display:flex;gap:8px;align-items:flex-end}
.flex>*{flex:0 0 auto}
</style></head>
<body>
<div class="wrap">
  <div id="login" class="card">
    <h1><svg class="pxp" width="20" height="20" viewBox="0 0 6 7" fill="#c77dff" aria-hidden="true" shape-rendering="crispEdges"><rect x="0" y="0" width="1" height="1"/><rect x="1" y="0" width="1" height="1"/><rect x="2" y="0" width="1" height="1"/><rect x="3" y="0" width="1" height="1"/><rect x="4" y="0" width="1" height="1"/><rect x="0" y="1" width="1" height="1"/><rect x="1" y="1" width="1" height="1"/><rect x="4" y="1" width="1" height="1"/><rect x="5" y="1" width="1" height="1"/><rect x="0" y="2" width="1" height="1"/><rect x="1" y="2" width="1" height="1"/><rect x="4" y="2" width="1" height="1"/><rect x="5" y="2" width="1" height="1"/><rect x="0" y="3" width="1" height="1"/><rect x="1" y="3" width="1" height="1"/><rect x="2" y="3" width="1" height="1"/><rect x="3" y="3" width="1" height="1"/><rect x="4" y="3" width="1" height="1"/><rect x="0" y="4" width="1" height="1"/><rect x="1" y="4" width="1" height="1"/><rect x="0" y="5" width="1" height="1"/><rect x="1" y="5" width="1" height="1"/><rect x="0" y="6" width="1" height="1"/><rect x="1" y="6" width="1" height="1"/></svg> Pixplace <span class="b">Admin</span></h1>
    <div class="sub">Backend administration – please sign in with the owner password.</div>
    <label>Owner password</label>
    <input type="password" id="pw" autocomplete="current-password">
    <div style="margin-top:12px"><button id="loginBtn">Sign in</button></div>
    <div class="msg" id="loginMsg"></div>
  </div>

  <div id="app" class="hide"></div>
  </div>
</div>
<script>

const $=s=>document.querySelector(s);
let TOKEN=sessionStorage.getItem("pp_admin_tok")||"";
function msgL(t,ok){const e=$("#loginMsg");e.textContent=t;
  e.className="msg "+(ok?"ok":"err");}
async function boot(){
  const r=await fetch("__BASE__/ui",{headers:{"Authorization":"Bearer "+TOKEN}});
  if(!r.ok){TOKEN="";sessionStorage.removeItem("pp_admin_tok");return false;}
  const d=await r.json();
  $("#app").innerHTML=d.html;
  $("#login").classList.add("hide");
  $("#app").classList.remove("hide");
  const sc=document.createElement("script");
  
  
  sc.textContent="(function(TOKEN,$){"+d.js+"\n})(window.__T,document.querySelector.bind(document));";
  window.__T=TOKEN;
  document.body.appendChild(sc);
  
  
  const lo=$("#logout");
  if(lo)lo.addEventListener("click",()=>{
    TOKEN="";sessionStorage.removeItem("pp_admin_tok");
    location.replace("__BASE__");},true);
  return true;
}
$("#loginBtn").onclick=async()=>{
  const pw=$("#pw").value;
  const r=await fetch("__BASE__/login",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({password:pw})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok||!d.token){msgL(d.error||"Wrong password",false);return;}
  TOKEN=d.token;sessionStorage.setItem("pp_admin_tok",TOKEN);
  $("#pw").value="";
  if(!await boot())msgL("Could not load the interface.",false);
};
$("#pw").addEventListener("keydown",e=>{if(e.key==="Enter")$("#loginBtn").click();});
if(TOKEN)boot();
</script>
</body></html>
"""

ADMIN_CSS = r"""
:root{--bg:#08070c;--panel:rgba(23,19,32,.74);--panel-solid:#17131f;
  --line:rgba(150,110,225,.18);--line-2:rgba(150,110,225,.32);
  --ink:#f1ecfb;--dim:#a89dc0;--faint:#746a8c;
  --accent:#a855f7;--accent-2:#c77dff;--accent-3:#7c3aed;
  --accent-soft:rgba(168,85,247,.14);
  --ok:#33b36b;--warn:#e0a63a;--danger:#e05a4a;--wiz:#c77dff;--own:#e0a63a}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(58% 46% at 10% -6%,rgba(124,58,237,.18),transparent 62%),
    radial-gradient(50% 42% at 95% 4%,rgba(168,85,247,.13),transparent 60%),var(--bg)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,'Segoe UI',sans-serif;background:var(--bg);color:var(--ink);font-size:14px}
a{color:var(--accent)}
.wrap{max-width:920px;margin:0 auto;padding:24px 18px}
h1{font-size:22px;margin-bottom:4px}h1 .b{color:var(--accent)}
.sub{color:var(--dim);margin-bottom:20px;font-size:13px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:18px;margin-bottom:16px}
.card h2{font-size:15px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
label{display:block;font-size:12px;color:var(--dim);margin:10px 0 4px}
input,textarea,select{width:100%;background:var(--bg);border:1px solid var(--line);
  color:var(--ink);border-radius:8px;padding:8px 10px;font:inherit}
textarea{resize:vertical;min-height:80px}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1;min-width:120px}
button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:9px 16px;
  font:inherit;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.1)}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
button.danger{background:var(--danger)}
button.sm{padding:5px 10px;font-size:12px}
.toggle{display:flex;align-items:center;gap:10px;margin-top:8px}
.toggle input{width:auto}
table{width:100%;border-collapse:collapse;margin-top:6px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--dim);font-weight:600}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700}
.pill.user{background:#2b2e3d;color:var(--dim)}
.pill.member{background:rgba(168,85,247,.16);color:#8fb4ff}
.pill.wizard{background:rgba(38,194,166,.15);color:var(--wiz)}
.pill.owner{background:rgba(224,166,58,.15);color:var(--own)}
#perms td{text-align:center}#perms td:first-child{text-align:left;font-weight:500}
#perms input{width:auto;cursor:pointer;transform:scale(1.2)}
#perms .lock{color:var(--dim)}
.on{color:var(--ok);font-size:11px}
.muted{color:var(--dim);font-size:12px}
#login{max-width:360px;margin:12vh auto}
#log{background:#0c0d12;border:1px solid var(--line);border-radius:8px;padding:10px;
  font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;
  max-height:340px;overflow:auto;color:#cfd3e6}
.msg{font-size:12px;margin-top:8px;min-height:16px}
.msg.ok{color:var(--ok)}.msg.err{color:var(--danger)}
.hide{display:none}
.flex{display:flex;gap:8px;align-items:flex-end}
.flex>*{flex:0 0 auto}
"""

WP_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="de-DE"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>Log In &lsaquo; Blog</title>
<style>
html{background:#f0f0f1}
body{background:#f0f0f1;color:#3c434a;margin:0;padding:0;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",
  sans-serif;font-size:13px;line-height:1.4}
#login{width:320px;padding:8% 0 0;margin:auto}
.login h1{text-align:center}
.login h1 a{background-image:url("data:image/svg+xml;charset=utf8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 122.5 122.5'%3E%3Cpath fill='%233c434a' d='M8.7 61.3c0 20.8 12.1 38.7 29.6 47.3L13.2 39.9c-2.9 6.6-4.5 13.8-4.5 21.4zm88 -2.7c0-6.5-2.3-11-4.3-14.5-2.7-4.3-5.2-8-5.2-12.3 0-4.8 3.7-9.3 8.9-9.3h.7a52.4 52.4 0 0 0-79.4 9.9h3.4c5.5 0 14-.7 14-.7 2.9-.2 3.2 4 .3 4.3 0 0-2.9.3-6 .5l19.1 56.9 11.5-34.4-8.2-22.5c-2.8-.2-5.5-.5-5.5-.5-2.8-.2-2.5-4.5.3-4.3 0 0 8.7.7 13.8.7 5.5 0 14-.7 14-.7 2.9-.2 3.2 4 .3 4.3 0 0-2.9.3-6 .5l19 56.5 5.2-17.5c2.3-7.3 4.1-12.5 4.1-17zM62.2 65.9l-15.8 45.8a52.6 52.6 0 0 0 32.3-.8l-.4-.7-16.1-44.3zm45.3-29.9c.2 1.7.4 3.5.4 5.5 0 5.4-1 11.5-4.1 19.1l-16.3 47.3a52.4 52.4 0 0 0 20-70.9zM61.3 0a61.3 61.3 0 1 0 .1 122.7A61.3 61.3 0 0 0 61.3 0zm0 119.7a58.5 58.5 0 1 1 .1-117 58.5 58.5 0 0 1-.1 117z'/%3E%3C/svg%3E");
  background-size:84px;background-position:center top;background-repeat:no-repeat;
  color:#3c434a;height:84px;font-size:20px;font-weight:400;line-height:1.3;
  margin:0 auto 25px;padding:0;text-decoration:none;width:84px;
  text-indent:-9999px;outline:0;overflow:hidden;display:block}
.login form{background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04);
  margin-left:0;padding:26px 24px 34px;font-weight:400;overflow:hidden}
.login label{color:#3c434a;font-size:14px;display:block;line-height:1.5;margin-bottom:3px}
.login form .input,.login input[type=text],.login input[type=password]{
  font-size:24px;line-height:1.33;width:100%;border:1px solid #8c8f94;
  background:#fff;box-sizing:border-box;padding:3px 5px;margin:0 6px 16px 0;
  min-height:40px;max-height:none;color:#2c3338;border-radius:0;outline:0}
.login input:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1}
.login .button-primary{background:#2271b1;border-color:#2271b1;color:#fff;
  text-decoration:none;text-shadow:none;font-size:13px;line-height:2.15384615;
  min-height:32px;padding:0 12px;border-width:1px;border-style:solid;
  border-radius:3px;cursor:pointer;float:right;box-sizing:border-box}
.login .button-primary:hover{background:#135e96;border-color:#135e96}
.forgetmenot{font-weight:400;float:left;margin-bottom:0;line-height:1.4}
.forgetmenot label{font-size:12px;line-height:1.4;display:inline}
.submit{clear:both;padding:0}
#nav,#backtoblog{font-size:13px;padding:0 24px;margin:24px 0 0}
#backtoblog{margin:8px 0 0}
#nav a,#backtoblog a{color:#50575e;text-decoration:none}
#nav a:hover,#backtoblog a:hover{color:#135e96}
#login_error{background:#fff;border-left:4px solid #d63638;
  box-shadow:0 1px 1px rgba(0,0,0,.04);margin:0 0 20px;padding:12px;
  word-wrap:break-word;display:none;font-size:13px}
.wp-hidden{display:none}
@media screen and (max-height:550px){#login{padding:20px 0}}
</style></head>
<body class="login no-js login-action-login wp-core-ui locale-de-de">
<div id="login">
  <h1><a href="#">Powered by WordPress</a></h1>
  <div id="login_error"></div>
  <form name="loginform" id="loginform" method="post" onsubmit="return false">
    <p>
      <label for="user_login">Username or Email Address</label>
      <input type="text" name="log" id="user_login" class="input"
             value="" size="20" autocapitalize="off" autocomplete="username">
    </p>
    <div class="user-pass-wrap">
      <label for="user_pass">Password</label>
      <input type="password" name="pwd" id="user_pass" class="input"
             value="" size="20" autocomplete="current-password">
    </div>
    <p class="forgetmenot">
      <input name="rememberme" type="checkbox" id="rememberme" value="forever">
      <label for="rememberme">Angemeldet bleiben</label></p>
    <p class="submit">
      <input type="submit" name="wp-submit" id="wp-submit"
             class="button button-primary button-large" value="Log In">
    </p>
  </form>
  <p id="nav"><a href="#">Lost your password?</a></p>
  <p id="backtoblog"><a href="/">&larr; Go to Blog</a></p>
</div>
<div id="app" class="wp-hidden"></div>
<script>
const $=s=>document.querySelector(s);
let TOKEN=sessionStorage.getItem("pp_admin_tok")||"";
function showErr(t){const e=$("#login_error");
  e.innerHTML=/^Error/i.test(t)?("<strong>"+t.replace(/^Error:?\s*/i,"Error: ")+"</strong>")
    :("<strong>Error:</strong> "+t);e.style.display="block";}
async function boot(){
  const r=await fetch("__BASE__/ui",{headers:{"Authorization":"Bearer "+TOKEN}});
  if(!r.ok){TOKEN="";sessionStorage.removeItem("pp_admin_tok");return false;}
  const d=await r.json();
  document.head.insertAdjacentHTML("beforeend","<style>"+d.css+"</style>");
  document.body.className="";
  const L=$("#login");if(L)L.remove();
  const app=$("#app");app.className="";app.innerHTML=d.html;
  const sc=document.createElement("script");
  sc.textContent="(function(TOKEN,$){"+d.js+"\n})(window.__T,document.querySelector.bind(document));";
  window.__T=TOKEN;document.body.appendChild(sc);
  const lo=$("#logout");
  if(lo)lo.addEventListener("click",()=>{
    TOKEN="";sessionStorage.removeItem("pp_admin_tok");
    location.replace("__BASE__");},true);
  return true;
}
async function submit(){
  const r=await fetch("__BASE__/login",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({log:$("#user_login").value,pwd:$("#user_pass").value})});
  const d=await r.json().catch(()=>({}));
  if(!r.ok||!d.token){
    showErr(d.error||"The password is not correct.");
    $("#user_pass").value="";return;}
  TOKEN=d.token;sessionStorage.setItem("pp_admin_tok",TOKEN);
  if(!await boot())showErr("Sign-in failed.");
}
$("#wp-submit").addEventListener("click",submit);
$("#loginform").addEventListener("submit",e=>{e.preventDefault();submit();});
if(TOKEN)boot();
</script>
</body></html>"""

ADMIN_APP_HTML = r"""    <h1>✦ Pixplace <span class="b">Admin</span>
      <button class="ghost sm" id="logout" style="float:right">Abmelden</button></h1>
    <div class="sub" id="hello"></div>

    <div class="card">
      <h2>🔑 Roles &amp; privileges</h2>
      <div class="muted">Permanent assignment: when someone joins with exactly this
        name, they automatically receive the role. Changes take effect immediately,
        including for users who are currently signed in.</div>
      <table id="grants"><thead><tr><th>Name</th><th>Role</th><th>Status</th><th></th></tr></thead>
        <tbody></tbody></table>
      <div class="flex" style="margin-top:12px">
        <div style="flex:1"><label>Name</label><input id="gName" placeholder="z. B. nova"></div>
        <div><label>Role</label>
          <select id="gRole"><option value="member">member</option>
            <option value="wizard">wizard</option>
            <option value="owner">owner</option></select></div>
        <div><button id="gAdd">Zuweisen</button></div>
      </div>
      <div class="msg" id="gMsg"></div>
    </div>

    <div class="card">
      <h2>🧩 Rights per role</h2>
      <div class="muted">Define from which role an ability is allowed.
        Owner always has all rights. Changes take effect immediately.</div>
      <table id="perms"><thead><tr><th>Capability</th>
        <th style="text-align:center">Guest</th><th style="text-align:center">Member</th>
        <th style="text-align:center">Wizard</th><th style="text-align:center">Owner</th>
      </tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <h2>🪪 Member accounts</h2>
      <div class="muted">Registered names are reserved and linked to a
        <b>permanent token</b> (never expires). Users register
        themselves in the login window; here you can create or remove accounts.</div>
      <table id="accts"><thead><tr><th>Name</th><th>Role</th><th>Status</th><th></th></tr></thead>
        <tbody></tbody></table>
      <div class="flex" style="margin-top:12px">
        <div style="flex:1"><label>New account (name)</label>
          <input id="aName" placeholder="z. B. luna"></div>
        <div><button id="aAdd">Anlegen</button></div>
      </div>
      <div class="msg" id="aMsg"></div>
      <div id="tokenBox" class="hide" style="margin-top:10px;padding:10px;
        background:#0c0d12;border:1px solid var(--line);border-radius:8px">
        <div class="muted">Token for <b id="tokName"></b> – shown only once,
          hand it over to the person securely:</div>
        <code id="tokVal" style="display:block;word-break:break-all;color:#8fe;margin-top:6px"></code>
      </div>
    </div>

    <div class="card">
      <h2>🏠 Manage rooms</h2>
      <div class="muted">New rooms are <b>temporary</b> (they disappear when empty
        or on restart). Anyone who wants a permanent room asks with
        <code>`makepermanent</code>; you can approve it here. Open requests
        are highlighted.</div>
      <table id="rooms"><thead><tr><th>Room</th><th>Status</th><th>User</th>
        <th></th></tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <h2>👥 Connected users</h2>
      <div class="muted">Currently connected users – gag, disconnect or ban.</div>
      <table id="users"><thead><tr><th>Name</th><th>Role</th><th>Room</th>
        <th>IP</th><th></th></tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <h2>🚧 Betriebszustand</h2>
      <div class="toggle"><input type="checkbox" id="testMode">
        <span><b>Test mode</b> – outsiders only see a
          construction page. No legal texts, no chat, no
          registration.</span></div>
      <div class="toggle"><input type="checkbox" id="privMode">
        <span><b>Closed circle</b> – purely private operation: the
          start page shows only a login form. No public
          pages, no self-registration. You hand out access below
          under "Member accounts" manually.</span></div>
      <div class="toggle"><input type="checkbox" id="pubReg">
        <span><b>Public registration</b> – off: nobody can
          sign up (wizards/owners still can).</span></div>
      <div class="toggle"><input type="checkbox" id="demoMode">
        <span><b>Demo mode</b> – for trying things out: nothing is
          logged, no IP addresses, no chat history.</span></div>
      <div class="toggle"><input type="checkbox" id="admHide">
        <span><b>Hide administration</b> – /admin then shows
          nothing (404). Reachable only via the path below.</span></div>
      <div class="row">
        <div><label>Eigener Pfad</label>
          <input id="admPath" placeholder="admin"></div>
        <div><label>Anmelde-Optik</label>
          <select id="admMask">
            <option value="default">Default (Pixplace)</option>
            <option value="wp">Blog login</option>
          </select></div>
      </div>
      <p class="hint">Remember the path well – without it you cannot get back
        into the administration.</p>
      <label style="margin-top:12px">Test mode access (keep secret)</label>
      <div class="row">
        <div><input id="testLink" readonly></div>
        <div><button id="newKey" class="ghost">Generate new access</button></div>
      </div>
      <p class="hint">Open this link once in the browser – afterwards
        this browser is unlocked permanently (30 days).
        <a href="/preview/logout">Revoke access here</a>.</p>
      <div style="margin-top:12px"><button id="saveState">Save</button></div>
      <div class="msg" id="stateMsg"></div>
    </div>

    <div class="card">
      <h2>✉ Einladungen</h2>
      <div class="muted">Access is handed out via invitation links. The
        invited person sets name and password themselves.</div>
      <div class="row" style="margin-top:10px">
        <div><label>Note (internal only)</label>
          <input id="invNote" placeholder="e.g. Anna from the club"></div>
        <div><label>Valid (days)</label>
          <input id="invDays" type="number" min="1" max="365" value="14"></div>
        <div><label>Rank</label>
          <select id="invRank">
            <option value="1">Member</option>
            <option value="0">Guest</option>
            <option value="2">Wizard</option>
          </select></div>
      </div>
      <div style="margin-top:10px"><button id="invCreate">Create invitation</button></div>
      <div class="msg" id="invMsg"></div>
      <div id="invNew" style="display:none;margin-top:10px">
        <label>Link – hand it over now</label>
        <input id="invLink" readonly>
        <p class="hint">The link works once. After that it is used up.</p>
      </div>
      <table style="margin-top:14px"><thead><tr>
        <th>Note</th><th>Status</th><th>Valid until</th><th>Redeemed by</th><th></th>
      </tr></thead><tbody id="invRows"></tbody></table>
    </div>

    <div class="card">
      <h2>⚖ Privacy &amp; authorities</h2>
      <div class="muted">Access under Art. 15 GDPR, erasure under Art. 17.
        Every action is recorded traceably.</div>
      <div class="row" style="margin-top:10px">
        <div><label>Person (name or e-mail)</label>
          <input id="gdWho" placeholder="z. B. Anna"></div>
        <div><label>Anlass / Aktenzeichen</label>
          <input id="gdReason" placeholder="z. B. Auskunftsersuchen 12/2026"></div>
      </div>
      <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
        <button id="gdExport">Auskunft erzeugen (JSON)</button>
        <button id="gdLog" class="ghost">Show actions</button>
      </div>
      <div class="msg" id="gdMsg"></div>
      <pre id="gdLogBox" style="display:none;margin-top:10px;max-height:220px;
        overflow:auto;background:rgba(10,8,15,.6);border:1px solid var(--line);
        border-radius:10px;padding:10px;font-size:12px"></pre>
      <label style="margin-top:14px">Complete deletion</label>
      <div class="row">
        <div><input id="gdDelName" placeholder="Name exakt wiederholen"></div>
        <div><label class="toggle" style="margin:0">
          <input type="checkbox" id="gdKeepMedia"><span>Keep images</span>
        </label></div>
        <div><button id="gdErase" class="ghost" style="color:#ff7a7a">
          Delete irreversibly</button></div>
      </div>
      <p class="hint">Removes account, messages, uploads, group membership
        and log entries. The action itself remains in the legal log.</p>
    </div>

    <div class="card">
      <h2>🚩 Meldungen <span id="repCount" class="muted"></span></h2>
      <div class="muted">Content reported by users (DSA notice route).</div>
      <table style="margin-top:10px"><thead><tr>
        <th>Time</th><th>From</th><th>Against</th><th>Reason</th>
        <th>Status</th><th></th></tr></thead>
        <tbody id="repRows"></tbody></table>
    </div>

    <div class="card">
      <h2>🖼 Uploaded images</h2>
      <div class="muted">Avatars, room backgrounds and guild logos – with
        author and time. Every upload is also in the log
        (<code>UPLOAD</code>).</div>
      <div class="row" style="margin-top:10px">
        <div><label>Filter</label>
          <select id="medKind">
            <option value="">alle Arten</option>
            <option value="avatar">Avatars</option>
            <option value="background">Backgrounds</option>
            <option value="guild">Guild logos</option>
            <option value="image">sonstige</option>
          </select></div>
        <div><label>Only from</label><input id="medWho" placeholder="Name"></div>
        <div><label>&nbsp;</label><button id="medReload" class="ghost">Neu laden</button></div>
      </div>
      <div id="medInfo" class="muted" style="margin-top:8px">—</div>
      <div id="medGrid" style="display:grid;margin-top:10px;gap:10px;
        grid-template-columns:repeat(auto-fill,minmax(150px,1fr))"></div>
    </div>

    <div class="card">
      <h2>✉ E-mail sending</h2>
      <div class="muted" id="mailState">—</div>
      <div class="row" style="margin-top:10px">
        <div><label>Server (SMTP)</label><input id="smHost" placeholder="mail.example.org"></div>
        <div><label>Port</label><input id="smPort" type="number" value="587"></div>
        <div><label>Security</label>
          <select id="smSec">
            <option value="starttls">STARTTLS (587)</option>
            <option value="ssl">SSL/TLS (465)</option>
            <option value="none">none (internal only)</option>
          </select></div>
      </div>
      <div class="row">
        <div><label>Benutzer</label><input id="smUser" autocomplete="off"></div>
        <div><label>Password</label>
          <input id="smPass" type="password" placeholder="leave unchanged"
                 autocomplete="new-password"></div>
        <div><label>Absender</label>
          <input id="smFrom" placeholder="Pixplace &lt;noreply@example.org&gt;"></div>
      </div>
      <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
        <button id="saveMail">Save</button>
        <input id="mailTo" placeholder="Testmail an …" style="max-width:220px">
        <button id="sendTest" class="ghost">Send test mail</button>
      </div>
      <div class="msg" id="mailMsg"></div>
      <label style="margin-top:14px">Set one-time password</label>
      <div class="row">
        <div><input id="spWho" placeholder="Username or e-mail"></div>
        <div><input id="spPw" placeholder="empty = generate randomly"></div>
        <div><label class="toggle" style="margin:0"><input type="checkbox" id="spMail">
          <span>also by e-mail</span></label></div>
      </div>
      <div style="margin-top:8px"><button id="setPass" class="ghost">Set password</button></div>
      <p class="hint">The person can sign in with it immediately and is
        asked to change it. Existing sessions are ended.</p>
      <div class="msg" id="spMsg"></div>

      <label style="margin-top:14px">Reset password</label>
      <div class="row">
        <div><input id="resetWho" placeholder="Username or e-mail"></div>
        <div><button id="sendReset" class="ghost">Send link by e-mail</button></div>
      </div>
      <p class="hint">The person receives a link that is valid for one hour and
        works only once. The old password stays valid until then.</p>
      <div class="msg" id="resetMsg"></div>
    </div>

    <div class="card">
      <h2>🛡 Moderation</h2>
      <div class="toggle"><input type="checkbox" id="logging">
        <span>Chat logging active (public &amp; private messages
          are stored with date, time, room, username)</span></div>
      <label>Notice users must accept when entering</label>
      <textarea id="notice"></textarea>
      <div style="margin-top:12px"><button id="saveMod">Save</button></div>
      <div class="msg" id="modMsg"></div>
    </div>

    <div class="card">
      <h2>⚙ Server &amp; passwords</h2>
      <label>Server name</label><input id="servername">
      <div class="row">
        <div><label>New owner password (empty = unchanged)</label>
          <input type="password" id="ownerPass"></div>
        <div><label>New wizard password (empty = unchanged)</label>
          <input type="password" id="wizardPass"></div>
      </div>
      <div style="margin-top:12px"><button id="saveSrv">Save</button></div>
      <div class="msg" id="srvMsg"></div>
    </div>

    <div class="card">
      <h2>📜 Moderation logs</h2>
      <div class="flex">
        <div style="flex:1"><label>Day</label>
          <select id="logDate"></select></div>
        <div><button class="ghost" id="loadLog">Show</button></div>
      </div>
      <div id="log" style="margin-top:10px">—</div>
    </div>

    <div class="card">
      <h2>🔎 Search by person &amp; period</h2>
      <p class="hint">For access requests under Art. 15 GDPR: filter,
         view and download as a table (CSV). The request must be
         answered within 30 days.</p>
      <div class="flex">
        <div style="flex:1"><label>Person (partial name is enough)</label>
          <input type="text" id="qUser" placeholder="e.g. Anna"></div>
        <div><label>From (YYYY-MM-DD)</label>
          <input type="date" id="qFrom"></div>
        <div><label>To</label>
          <input type="date" id="qTo"></div>
      </div>
      <div class="flex">
        <div style="flex:1"><label>Room (optional)</label>
          <input type="text" id="qRoom" placeholder="e.g. Plaza"></div>
        <div style="flex:1"><label>Type (optional)</label>
          <input type="text" id="qKind" placeholder="CHAT, WHISPER, SIGNON …"></div>
        <div><label>&nbsp;</label>
          <button class="ghost" id="qGo">Search</button></div>
        <div><label>&nbsp;</label>
          <button class="ghost" id="qCsv">Download CSV</button></div>
      </div>
      <div class="msg" id="qMsg"></div>
      <div id="qResult" style="margin-top:10px;overflow:auto;max-height:60vh">—</div>
    </div>"""

ADMIN_APP_JS = r"""/* TOKEN and $ come from the sign-in (see /admin) */

async function api(path,opts={}){
  opts.headers=Object.assign({"Content-Type":"application/json"},opts.headers||{},
    TOKEN?{"Authorization":"Bearer "+TOKEN}:{});
  const r=await fetch(path,opts);
  if(r.status===401){logout();throw new Error("not signed in");}
  const ct=r.headers.get("content-type")||"";
  return ct.includes("json")?r.json():r.text();
}
function msg(el,text,ok){const e=$(el);e.textContent=text;e.className="msg "+(ok?"ok":"err");}
/* ---- Log search by person and period ---- */
function qParams(){
  const p=new URLSearchParams();
  const u=$("#qUser").value.trim(); if(u)p.set("user",u);
  const f=$("#qFrom").value.trim(); if(f)p.set("from",f);
  const t=$("#qTo").value.trim();   if(t)p.set("to",t);
  const r=$("#qRoom").value.trim(); if(r)p.set("room",r);
  const k=$("#qKind").value.trim(); if(k)p.set("kind",k);
  return p.toString();
}
async function qSearch(){
  const box=$("#qResult");
  box.textContent="loading …";
  try{
    const d=await api("__BASE__/api/logs?"+qParams());
    if(!d.rows.length){box.textContent="No entries found.";
      msg("#qMsg","0 matches",true);return;}
    let h='<table style="width:100%;border-collapse:collapse;font-size:12.5px">'+
      '<tr><th>Date</th><th>Time</th><th>Room</th><th>Person</th>'+
      '<th>Type</th><th>Text</th></tr>';
    for(const r of d.rows){
      h+='<tr>'+[r.date,r.time,r.room,r.user,r.kind,r.text]
        .map(c=>'<td style="border-bottom:1px solid #2e3142;padding:4px 6px;'+
          'vertical-align:top">'+String(c||"")
          .replace(/&/g,"&amp;").replace(/</g,"&lt;")+'</td>').join("")+'</tr>';
    }
    box.innerHTML=h+'</table>';
    msg("#qMsg",d.count+" matches from "+d.files+" file(s)"+
      (d.truncated?" – truncated, narrow the period":""),true);
  }catch(e){msg("#qMsg","Error: "+e.message,false);box.textContent="—";}
}
function qDownload(){
  
  const url="/admin/api/logs.csv?"+qParams();
  fetch(url,{headers:{"Authorization":"Bearer "+TOKEN}})
    .then(r=>{if(!r.ok)throw new Error("HTTP "+r.status);return r.blob();})
    .then(b=>{
      const a=document.createElement("a");
      a.href=URL.createObjectURL(b);
      a.download="pixplace-log.csv";
      document.body.appendChild(a);a.click();a.remove();
      msg("#qMsg","Table downloaded.",true);})
    .catch(e=>msg("#qMsg","Error: "+e.message,false));
}
function show(app){const L=$("#login");if(L)L.classList.toggle("hide",app);$("#app").classList.toggle("hide",!app);}

async function doLogin(){
  try{const r=await fetch("__BASE__/login",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({password:($("#pw")||{}).value||""})});
    const d=await r.json();
    if(d.token){TOKEN=d.token;sessionStorage.pp_admin=TOKEN;show(true);load();}
    else msg("#loginMsg",d.error||"Error",false);
  }catch(e){msg("#loginMsg","Verbindungsfehler",false);}
}
function logout(){TOKEN="";sessionStorage.removeItem("pp_admin");show(false);}

async function load(){
  const s=await api("__BASE__/api/state");
  $("#hello").textContent="Server \""+s.servername+"\" · "+s.grants.length
    +" Rollen hinterlegt · "+s.onlineCount+" online";
  $("#testMode").checked=!!s.testMode;
  $("#privMode").checked=!!s.privateMode;
  renderInvites(s.invites,s.inviteDefaultDays||14);
  renderReports(s.reports,s.reportsOpen);
  loadMedia();
  const sm=s.smtp||{};
  $("#smHost").value=sm.host||"";$("#smPort").value=sm.port||587;
  $("#smSec").value=sm.security||"starttls";$("#smUser").value=sm.user||"";
  $("#smFrom").value=sm.from||"";
  $("#mailState").textContent=s.mailReady
    ? "Sending is configured."
    : "No mail server configured – \"Forgot password\" will not work.";
  $("#admHide").checked=!!s.adminHidden;
  $("#admPath").value=s.adminPath||"admin";
  $("#admMask").value=s.adminMask||"default";
  $("#pubReg").checked=!!s.publicRegistration;
  $("#demoMode").checked=!!s.demoMode;
  $("#testLink").value=location.origin+"/preview/"+(s.testKey||"");
  // grants
  const tb=$("#grants tbody");tb.innerHTML="";
  for(const g of s.grants){
    const tr=document.createElement("tr");
    tr.innerHTML=`<td>${g.name}</td>
      <td><span class="pill ${g.role}">${g.role}</span></td>
      <td>${g.online?'<span class="on">● online</span>':'<span class="muted">offline</span>'}</td>
      <td style="text-align:right">
        <button class="ghost sm" data-edit="${g.name}">edit</button>
        <button class="danger sm" data-rev="${g.name}">remove</button></td>`;
    tb.appendChild(tr);
  }
  tb.querySelectorAll("[data-rev]").forEach(b=>b.onclick=async()=>{
    await api("__BASE__/api/revoke",{method:"POST",body:JSON.stringify({name:b.dataset.rev})});load();});
  tb.querySelectorAll("[data-edit]").forEach(b=>b.onclick=()=>{
    $("#gName").value=b.dataset.edit;$("#gName").focus();});
  
  const pm=$("#perms tbody");pm.innerHTML="";
  for(const pd of s.permDefs){
    const row=s.permMatrix[pd.cap];
    const tr=document.createElement("tr");
    let cells=`<td>${pd.label}</td>`;
    for(const r of ["0","1","2","3"]){
      if(r==="3")cells+=`<td><span class="lock" title="Owner always">✓</span></td>`;
      else cells+=`<td><input type="checkbox" data-cap="${pd.cap}" data-rank="${r}"
        ${row[r]?"checked":""}></td>`;
    }
    tr.innerHTML=cells;pm.appendChild(tr);
  }
  pm.querySelectorAll("input[type=checkbox]").forEach(cb=>cb.onchange=async()=>{
    await api("__BASE__/api/perms",{method:"POST",body:JSON.stringify(
      {cap:cb.dataset.cap,rank:cb.dataset.rank,allowed:cb.checked})});});
  // Member-Konten
  const at=$("#accts tbody");at.innerHTML="";
  for(const a of (s.accounts||[])){
    const tr=document.createElement("tr");
    tr.innerHTML=`<td>${a.username}</td>
      <td><span class="pill ${a.role}">${a.role}</span></td>
      <td>${a.online?'<span class="on">● online</span>':'<span class="muted">offline</span>'}</td>
      <td style="text-align:right">
        <button class="danger sm" data-del="${a.username}">delete</button></td>`;
    at.appendChild(tr);
  }
  at.querySelectorAll("[data-del]").forEach(b=>b.onclick=async()=>{
    if(!confirm("Really delete account \""+b.dataset.del+"\"? The token becomes invalid."))return;
    await api("__BASE__/api/account/delete",{method:"POST",
      body:JSON.stringify({username:b.dataset.del})});load();});
  
  const rt=$("#rooms tbody");rt.innerHTML="";
  for(const r of (s.rooms||[])){
    const tr=document.createElement("tr");
    let st=r.builtin?'<span class="pill wizard">Default</span>'
      :r.persistent?'<span class="pill owner">permanent</span>'
      :'<span class="pill user">temporary</span>';
    if(r.permRequested)st+=' <span class="pill member">Request</span>';
    if(r.hidden)st+=' 🕶'; if(r.locked)st+=' 🔒';
    let btns="";
    if(!r.builtin){
      if(r.permRequested)btns+=`<button class="sm" data-room="${r.name}" data-a="approve">genehmigen</button> `;
      if(r.persistent)btns+=`<button class="ghost sm" data-room="${r.name}" data-a="temporary">temporary</button> `;
      else btns+=`<button class="ghost sm" data-room="${r.name}" data-a="permanent">permanent</button> `;
      btns+=`<button class="danger sm" data-room="${r.name}" data-a="delete">delete</button>`;
    }
    tr.innerHTML=`<td>${r.name}</td><td>${st}</td><td>${r.users}</td>
      <td style="text-align:right">${btns}</td>`;
    if(r.permRequested)tr.style.background="rgba(168,85,247,.08)";
    rt.appendChild(tr);
  }
  rt.querySelectorAll("[data-room]").forEach(b=>b.onclick=async()=>{
    if(b.dataset.a==="delete"&&!confirm("Delete room \""+b.dataset.room+"\"?"))return;
    await api("__BASE__/api/room",{method:"POST",
      body:JSON.stringify({name:b.dataset.room,action:b.dataset.a})});load();});
  
  const ut=$("#users tbody");ut.innerHTML="";
  for(const u of (s.onlineUsers||[])){
    const tr=document.createElement("tr");
    tr.innerHTML=`<td>${u.name}${u.gagged?' 🔇':''}${u.pinned?' 📌':''}</td>
      <td><span class="pill ${u.role}">${u.role}</span></td>
      <td>${u.room}</td><td class="muted">${u.ip}</td>
      <td style="text-align:right">
        ${u.gagged?`<button class="ghost sm" data-uid="${u.id}" data-a="ungag">entknebeln</button>`
                  :`<button class="ghost sm" data-uid="${u.id}" data-a="gag">gag</button>`}
        ${u.pinned?`<button class="ghost sm" data-uid="${u.id}" data-a="unpin">entsperren</button>`
                  :`<button class="ghost sm" data-uid="${u.id}" data-a="pin">pin</button>`}
        <button class="sm" data-uid="${u.id}" data-a="kick">trennen</button>
        <button class="danger sm" data-uid="${u.id}" data-a="ban">bannen</button></td>`;
    ut.appendChild(tr);
  }
  ut.querySelectorAll("[data-uid]").forEach(b=>b.onclick=async()=>{
    if((b.dataset.a==="ban"||b.dataset.a==="kick")&&
       !confirm("Really "+(b.dataset.a==="ban"?"ban":"disconnect")+" this user?"))return;
    await api("__BASE__/api/user",{method:"POST",
      body:JSON.stringify({id:b.dataset.uid,action:b.dataset.a})});load();});
  // moderation & server
  $("#logging").checked=s.logging;
  $("#notice").value=s.notice;
  $("#servername").value=s.servername;
  // logs
  const sel=$("#logDate");sel.innerHTML="";
  for(const d of s.logDates){const o=document.createElement("option");o.value=o.textContent=d;sel.appendChild(o);}
  if(!s.logDates.length){const o=document.createElement("option");o.textContent="(none)";sel.appendChild(o);}
}

/* Sign-in is handled by the start page – only here if present. */
if($("#loginBtn"))$("#loginBtn").onclick=doLogin;
if($("#pw"))$("#pw").addEventListener("keydown",e=>{if(e.key==="Enter")doLogin();});
$("#logout").onclick=logout;
$("#gAdd").onclick=async()=>{
  const name=$("#gName").value.trim();if(!name)return msg("#gMsg","Name missing",false);
  await api("__BASE__/api/grant",{method:"POST",
    body:JSON.stringify({name,role:$("#gRole").value})});
  $("#gName").value="";msg("#gMsg","Gespeichert.",true);load();};
function invFmt(ts){if(!ts)return "–";const d=new Date(ts);
  return d.toLocaleDateString()+" "+d.toLocaleTimeString().slice(0,5);}
function renderInvites(list,days){
  const tb=$("#invRows");if(!tb)return;tb.innerHTML="";
  if(!list||!list.length){
    tb.innerHTML='<tr><td colspan="5" class="muted">No invitations yet.</td></tr>';
    return;}
  for(const i of list){
    const tr=document.createElement("tr");
    const col={"open":"var(--ok)","redeemed":"var(--dim)",
               "expired":"var(--warn)","blocked":"var(--danger)"}[i.state]||"";
    tr.innerHTML=
      '<td><input data-note="'+i.code+'" value="'+(i.note||"").replace(/"/g,"&quot;")+
        '" style="width:100%"></td>'+
      '<td style="color:'+col+'">'+i.state+'</td>'+
      '<td>'+invFmt(i.expires)+'</td>'+
      '<td>'+(i.usedBy||"–")+'</td>'+
      '<td style="white-space:nowrap"></td>';
    const cell=tr.lastElementChild;
    const mk=(txt,act,cls)=>{const b=document.createElement("button");
      b.textContent=txt;b.className=cls||"ghost sm";
      b.onclick=()=>invAct(act,i.code);cell.appendChild(b);return b;};
    if(i.state==="open"){
      const l=document.createElement("button");l.className="ghost sm";
      l.textContent="Link";l.onclick=()=>{
        $("#invLink").value=location.origin+"/join/"+i.code;
        $("#invNew").style.display="";
        $("#invLink").select();};
      cell.appendChild(l);
      mk("Block","disable");
    }else{
      mk("Reaktivieren","enable");
    }
    if(i.state==="redeemed")mk("Release again","reset");
    mk("+"+days+"T","extend");
    mk("Delete","delete","ghost sm").style.color="#ff7a7a";
    tb.appendChild(tr);
  }
  tb.querySelectorAll("[data-note]").forEach(inp=>{
    inp.onchange=()=>invAct("note",inp.dataset.note,{note:inp.value});});
}
async function invAct(action,code,extra){
  const days=parseInt($("#invDays").value||"14",10);
  await api("__BASE__/api/invite",{method:"POST",
    body:JSON.stringify(Object.assign({action:action,code:code,days:days},extra||{}))});
  msg("#invMsg","Gespeichert.",true);load();
}
$("#invCreate").onclick=async()=>{
  const d=await api("__BASE__/api/invite",{method:"POST",
    body:JSON.stringify({action:"create",note:$("#invNote").value,
      days:parseInt($("#invDays").value||"14",10),
      rank:parseInt($("#invRank").value,10)})});
  if(d&&d.invite){
    $("#invLink").value=location.origin+"/join/"+d.invite.code;
    $("#invNew").style.display="";$("#invLink").select();
    $("#invNote").value="";msg("#invMsg","Invitation created.",true);load();}
};
let MEDIA=[];
function medWhen(ts){if(!ts)return "–";const d=new Date(ts);
  return d.toLocaleDateString()+" "+d.toLocaleTimeString().slice(0,5);}
function medRender(){
  const g=$("#medGrid");if(!g)return;
  const kind=$("#medKind").value, who=$("#medWho").value.trim().toLowerCase();
  const list=MEDIA.filter(m=>(!kind||m.kind===kind)&&
    (!who||String(m.by||"").toLowerCase().includes(who)));
  $("#medInfo").textContent=list.length+" of "+MEDIA.length+" images";
  g.innerHTML="";
  if(!list.length){g.innerHTML='<div class="muted">No images.</div>';return;}
  for(const m of list){
    const fn=String(m.url||"").split("/").pop();
    const card=document.createElement("div");
    card.style.cssText="border:1px solid var(--line);border-radius:10px;"+
      "overflow:hidden;background:var(--panel-2)";
    card.innerHTML=
      '<a href="'+m.url+'" target="_blank" rel="noopener">'+
      '<img src="'+m.url+'" alt="" loading="lazy" style="width:100%;height:110px;'+
      'object-fit:contain;background:#0c0a12;display:block"></a>'+
      '<div style="padding:7px 8px;font-size:12px;line-height:1.5">'+
      '<div><b>'+(m.by||"?")+'</b>'+(m.verified?"":' <span class="muted">(unverified)</span>')+'</div>'+
      '<div class="muted">'+medWhen(m.ts)+' · '+(m.kind||"image")+'</div>'+
      '<div class="muted">'+Math.round((m.size||0)/1024)+' KB · '+(m.ip||"-")+'</div>'+
      '</div>';
    const del=document.createElement("button");
    del.className="ghost sm";del.textContent="Delete";
    del.style.cssText="margin:0 8px 8px;color:#ff7a7a";
    del.onclick=async()=>{
      if(!confirm("Really delete image \""+fn+"\" by "+(m.by||"?")+"?"))return;
      await api("__BASE__/api/media/delete",{method:"POST",
        body:JSON.stringify({file:fn})});
      loadMedia();
    };
    card.appendChild(del);
    g.appendChild(card);
  }
}
async function loadMedia(){
  const d=await api("__BASE__/api/media");
  MEDIA=(d&&d.media)||[];medRender();
}
function repWhen(ts){if(!ts)return "–";const d=new Date(ts);
  return d.toLocaleDateString()+" "+d.toLocaleTimeString().slice(0,5);}
function renderReports(list,openCount){
  const tb=$("#repRows");if(!tb)return;
  $("#repCount").textContent=openCount?("· "+openCount+" open"):"";
  tb.innerHTML="";
  if(!list||!list.length){
    tb.innerHTML='<tr><td colspan="6" class="muted">No reports.</td></tr>';
    return;}
  const lbl={open:"open",review:"under review",done:"done",rejected:"rejected"};
  for(const r of list){
    const tr=document.createElement("tr");
    tr.innerHTML='<td>'+repWhen(r.ts)+'</td><td>'+(r.by||"?")+'</td>'
      +'<td>'+(r.target||"–")+'</td><td>'+(r.reason||"–")+'</td>'
      +'<td>'+(lbl[r.status]||r.status)+'</td><td style="white-space:nowrap"></td>';
    const cell=tr.lastElementChild;
    const mk=(txt,act)=>{const b=document.createElement("button");
      b.className="ghost sm";b.textContent=txt;
      b.onclick=async()=>{await api("__BASE__/api/report",{method:"POST",
        body:JSON.stringify({id:r.id,action:act})});load();};
      cell.appendChild(b);};
    if(r.text){const v=document.createElement("button");
      v.className="ghost sm";v.textContent="Text";
      v.onclick=()=>alert(r.text);cell.appendChild(v);}
    if(r.status!=="done")mk("erledigt","done");
    if(r.status==="open")mk("under review","review");
    if(r.status!=="rejected")mk("ablehnen","rejected");
    mk("delete","delete");
    tb.appendChild(tr);
  }
}
$("#gdExport")?.addEventListener("click",async()=>{
  const who=$("#gdWho").value.trim();
  if(!who)return msg("#gdMsg","Please enter a name.",false);
  const r=await fetch("__BASE__/api/gdpr/export",{method:"POST",
    headers:{"Content-Type":"application/json","Authorization":"Bearer "+TOKEN},
    body:JSON.stringify({name:who,reason:$("#gdReason").value})});
  if(!r.ok)return msg("#gdMsg","Not found or failed.",false);
  const blob=await r.blob();
  const a=document.createElement("a");
  a.href=URL.createObjectURL(blob);
  a.download="auskunft-"+who.replace(/[^\w-]/g,"_")+".json";
  document.body.appendChild(a);a.click();a.remove();
  msg("#gdMsg","Report generated and downloaded.",true);
});
$("#gdLog")?.addEventListener("click",async()=>{
  const d=await api("__BASE__/api/gdpr/log");
  const box=$("#gdLogBox");
  box.style.display="";
  box.textContent=(d&&d.lines&&d.lines.length)?d.lines.join("\n")
    :"No actions yet.";
});
$("#gdErase")?.addEventListener("click",async()=>{
  const who=$("#gdWho").value.trim();
  const cf=$("#gdDelName").value.trim();
  if(!who)return msg("#gdMsg","Please enter the person above.",false);
  if(cf!==who)return msg("#gdMsg",
    "To confirm, repeat the name below exactly.",false);
  if(!confirm("Permanently delete all data of \""+who+"\"?"))return;
  const d=await api("__BASE__/api/gdpr/erase",{method:"POST",
    body:JSON.stringify({name:who,confirm:cf,reason:$("#gdReason").value,
      keepMedia:$("#gdKeepMedia").checked})});
  if(d&&d.ok){
    $("#gdDelName").value="";
    msg("#gdMsg","Deleted: "+JSON.stringify(d.result),true);load();
  }else msg("#gdMsg",(d&&d.error)||"Fehlgeschlagen.",false);
});
$("#medKind")?.addEventListener("change",medRender);
$("#medWho")?.addEventListener("input",medRender);
$("#medReload")?.addEventListener("click",loadMedia);
$("#saveMail").onclick=async()=>{
  await api("__BASE__/api/settings",{method:"POST",
    body:JSON.stringify({smtp:{host:$("#smHost").value.trim(),
      port:parseInt($("#smPort").value||"587",10),
      security:$("#smSec").value,user:$("#smUser").value.trim(),
      password:$("#smPass").value,from:$("#smFrom").value.trim()}})});
  $("#smPass").value="";msg("#mailMsg","Gespeichert.",true);load();};
$("#sendTest").onclick=async()=>{
  const d=await api("__BASE__/api/mailtest",{method:"POST",
    body:JSON.stringify({to:$("#mailTo").value.trim()})});
  msg("#mailMsg",d&&d.ok?"Testmail verschickt.":(d&&d.error)||"Versand fehlgeschlagen.",!!(d&&d.ok));};
$("#setPass").onclick=async()=>{
  const d=await api("__BASE__/api/setpass",{method:"POST",
    body:JSON.stringify({name:$("#spWho").value.trim(),
      password:$("#spPw").value,sendMail:$("#spMail").checked})});
  if(d&&d.ok){
    $("#spPw").value="";
    msg("#spMsg","Password for "+d.user+": "+d.password+
        (d.mailed?" (also sent by e-mail)":" – hand it over now"),true);
  }else msg("#spMsg",(d&&d.error)||"Fehlgeschlagen.",false);
};
$("#sendReset").onclick=async()=>{
  const d=await api("__BASE__/api/sendreset",{method:"POST",
    body:JSON.stringify({name:$("#resetWho").value.trim()})});
  msg("#resetMsg",d&&d.ok?("Link verschickt an "+d.to):(d&&d.error)||"Fehlgeschlagen.",!!(d&&d.ok));};
$("#saveState").onclick=async()=>{
  await api("__BASE__/api/settings",{method:"POST",
    body:JSON.stringify({testMode:$("#testMode").checked,
                         privateMode:$("#privMode").checked,
                         publicRegistration:$("#pubReg").checked,
                         demoMode:$("#demoMode").checked,
                         adminHidden:$("#admHide").checked,
                         adminPath:$("#admPath").value.trim(),
                         adminMask:$("#admMask").value})});
  msg("#stateMsg","Operating state saved.",true);load();};
$("#newKey").onclick=async()=>{
  if(!confirm("Generate new access? The old link will no longer work."))return;
  await api("__BASE__/api/settings",{method:"POST",
    body:JSON.stringify({newTestKey:true})});
  msg("#stateMsg","New access generated.",true);load();};
$("#saveMod").onclick=async()=>{
  await api("__BASE__/api/settings",{method:"POST",
    body:JSON.stringify({logging:$("#logging").checked,notice:$("#notice").value})});
  msg("#modMsg","Moderation settings saved.",true);};
$("#saveSrv").onclick=async()=>{
  const body={servername:$("#servername").value};
  if($("#ownerPass").value)body.ownerPass=$("#ownerPass").value;
  if($("#wizardPass").value)body.wizardPass=$("#wizardPass").value;
  await api("__BASE__/api/settings",{method:"POST",body:JSON.stringify(body)});
  $("#ownerPass").value="";$("#wizardPass").value="";
  msg("#srvMsg","Server settings saved.",true);load();};
$("#aAdd").onclick=async()=>{
  const name=$("#aName").value.trim();if(!name)return msg("#aMsg","Name missing",false);
  try{const s=await api("__BASE__/api/account",{method:"POST",
    body:JSON.stringify({username:name})});
    $("#aName").value="";msg("#aMsg","Account created.",true);
    if(s.newToken){$("#tokenBox").classList.remove("hide");
      $("#tokName").textContent=s.newName;$("#tokVal").textContent=s.newToken;}
    load();}catch(e){msg("#aMsg","Error (name may be taken).",false);}};
$("#qGo").onclick=qSearch;
$("#qCsv").onclick=qDownload;
$("#loadLog").onclick=async()=>{
  const d=$("#logDate").value;if(!d||d==="(none)")return;
  try{const t=await api("__BASE__/api/log?date="+encodeURIComponent(d));
    $("#log").textContent=t||"(empty)";}catch(e){$("#log").textContent="Error";}};

if(TOKEN){show(true);load().catch(()=>logout());}else show(false);"""

ADMIN_IDLE_MS = 30 * 60 * 1000

def admin_token_new(ip: str = "") -> str:
    tok = secrets.token_urlsafe(32)
    ADMIN_TOKENS[tok] = {"exp": now_ms() + ADMIN_TTL_MS,
                         "seen": now_ms(), "ip": ip or ""}
    for k, v in list(ADMIN_TOKENS.items()):
        if isinstance(v, dict) and v["exp"] < now_ms():
            ADMIN_TOKENS.pop(k, None)
    return tok

def admin_token_ok(headers: dict, ip: str = "") -> bool:
    auth = headers.get("authorization", "")
    got = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not got:
        return False
    found = None
    for tok, v in ADMIN_TOKENS.items():
        if hmac.compare_digest(tok, got):
            found = (tok, v)
            break
    if not found:
        return False
    tok, v = found
    if not isinstance(v, dict):
        ADMIN_TOKENS.pop(tok, None)
        return False
    n = now_ms()
    if v["exp"] < n or (n - v["seen"]) > ADMIN_IDLE_MS:
        ADMIN_TOKENS.pop(tok, None)
        return False
    if CONFIG.get("admin_bind_ip", True) and v.get("ip") and ip and v["ip"] != ip:
        return False
    v["seen"] = n
    return True

def perm_matrix() -> dict:
    out = {}
    for cap, _label in PERM_DEFS:
        table = perms().get(cap) or DEFAULT_PERMS.get(cap, {})
        out[cap] = {str(r): bool(table.get(str(r), table.get(r, False)))
                    for r in (RANK_GUEST, RANK_MEMBER, RANK_WIZARD, RANK_OWNER)}
    return out

def admin_state() -> dict:
    logs = sorted([f[:-4] for f in os.listdir(MOD_DIR) if f.endswith(".txt")],
                  reverse=True)
    online = {u.base.lower(): u.rank for u in all_users()}
    grants = [{"name": n, "role": RANK_NAME.get(int(r), "user"),
               "online": n in online}
              for n, r in sorted(CONFIG["grants"].items())]
    accounts = [{"username": a["username"], "role": RANK_NAME.get(a.get("rank", 1), "member"),
                 "created": a.get("created", 0),
                 "online": a["username"].lower() in online}
                for a in sorted(ACCOUNTS.values(),
                                key=lambda x: x.get("created", 0), reverse=True)]
    rooms = [{"name": r.name, "users": len(r.users), "hidden": r.hidden,
              "locked": bool(r.password), "operatorsonly": r.operatorsonly,
              "persistent": r.persistent, "permRequested": r.perm_requested,
              "builtin": r.name in BUILTIN_ROOMS}
             for r in sorted(ROOMS.values(), key=lambda x: x.name.lower())]
    onlineUsers = [{"id": u.id, "name": u.name, "base": u.base,
                    "role": RANK_NAME.get(u.rank, "user"), "rank": u.rank,
                    "room": u.room.name if u.room else "-", "ip": safe_ip(u.ws.ip),
                    "gagged": u.gagged, "pinned": u.pinned}
                   for u in sorted(all_users(), key=lambda x: x.base.lower())]
    return {
        "servername": CONFIG["servername"],
        "notice": CONFIG["moderation_notice"],
        "logging": bool(CONFIG["moderation_logging"]),
        "ownerPassSet": bool(CONFIG["owner_pass"]),
        "wizardPassSet": bool(CONFIG["wizard_pass"]),
        "grants": grants,
        "accounts": accounts,
        "rooms": rooms,
        "onlineUsers": onlineUsers,
        "permDefs": [{"cap": c, "label": l} for c, l in PERM_DEFS],
        "permMatrix": perm_matrix(),
        "rankNames": RANK_NAME,
        "logDates": logs,
        "onlineCount": len(online),
        "testMode": bool(CONFIG.get("test_mode")),
        "privateMode": bool(CONFIG.get("private_mode")),
        "adminHidden": bool(CONFIG.get("admin_hidden")),
        "mailReady": mail_ready(),
        "reports": sorted(REPORTS.values(), key=lambda x: -x.get("ts", 0))[:200],
        "reportsOpen": sum(1 for r in REPORTS.values()
                           if r.get("status") == "open"),
        "smtp": {k: v for k, v in (CONFIG.get("smtp") or {}).items()
                 if k != "password"},
        "adminPath": admin_base(),
        "adminMask": CONFIG.get("admin_mask", "default"),
        "publicRegistration": bool(CONFIG.get("public_registration")),
        "demoMode": bool(CONFIG.get("demo_mode")),
        "testKey": str(CONFIG.get("test_key") or ""),
        "inviteDefaultDays": INVITE_DEFAULT_DAYS,
        "invites": sorted(
            [{"code": i["code"], "note": i.get("note", ""),
              "rank": i.get("rank", RANK_MEMBER),
              "state": invite_state(i),
              "created": i.get("created", 0),
              "expires": i.get("expires", 0),
              "usedBy": i.get("used_by", "")}
             for i in INVITES.values()],
            key=lambda x: -x["created"])[:200],
    }

async def _apply_grant_live(name: str, rank: int):
    tgt = find_user(name)
    if not tgt:
        return
    tgt.rank = rank
    await send(tgt, {"t": "rank", "rank": rank,
                     "rankName": RANK_NAME[rank], "name": tgt.name})
    if tgt.room:
        await broadcast(tgt.room, {"t": "rename", "id": tgt.id,
                                   "name": tgt.name, "base": tgt.base, "rank": rank})

async def handle_admin(writer, method, target, headers, body, client_ip="?"):
    path = target.split("?")[0]

    _b = "/" + admin_base()
    if _b != "/admin" and (path == _b or path.startswith(_b + "/")):
        path = "/admin" + path[len(_b):]
    query = {}
    if "?" in target:
        for kv in target.split("?", 1)[1].split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                query[k] = v

    def jbody():
        try:
            return json.loads(body or b"{}")
        except Exception:
            return {}

    async def json_resp(status, obj):

        return await http_respond(writer, status, json.dumps(obj),
                                  "application/json",
                                  extra={"Cache-Control": "no-store, no-cache, "
                                                          "must-revalidate",
                                         "Pragma": "no-cache"})

    if method == "GET" and path == "/admin":
        if CONFIG.get("admin_mask") == "wp":
            page = WP_LOGIN_HTML.replace("__BASE__", "/" + admin_base())
            return await http_respond(writer, "200 OK", page,
                                      "text/html; charset=utf-8")
        page = ADMIN_HTML.replace("__BASE__", "/" + admin_base())
        return await http_respond(writer, "200 OK", page,
                                  "text/html; charset=utf-8")

    if method == "POST" and path == "/admin/login":

        trusted = ip_is_known_good(client_ip)
        if not RL_ADMIN_LOGIN.allow(client_ip) or \
                (not trusted and not RL_ADMIN_TOTAL.allow("*")):
            return await json_resp("429 Too Many Requests",
                {"error": "Too many failed attempts. Please wait a few minutes."})

        wait = 0.0 if trusted else FAILS.delay_for("admin")
        if wait > 2.0:
            return await json_resp("429 Too Many Requests",
                {"error": "Too many failed attempts. Please wait a few minutes.",
                 "retryAfter": int(wait)})
        if wait:
            await asyncio.sleep(wait)
        d = jbody()
        pw = d.get("password") or d.get("pwd") or ""
        if pw and hmac.compare_digest(str(pw), str(CONFIG["owner_pass"])):
            FAILS.ok("admin")
            mark_ip_good(client_ip)
            return await json_resp("200 OK", {"token": admin_token_new(client_ip)})
        FAILS.fail("admin")
        if FAILS.count("admin") in (5, 20, 50):
            mod_log("-", "-", "ADMIN-BRUTEFORCE",
                    f"{FAILS.count('admin')} failed attempts, latest from "
                    f"{safe_ip(client_ip)}")

        if CONFIG.get("admin_mask") == "wp":
            return await json_resp("401 Unauthorized", {"error":
                "Error: The password for this username is not correct."})
        return await json_resp("401 Unauthorized", {"error": "Wrong password"})

    if not admin_token_ok(headers, client_ip):
        return await json_resp("401 Unauthorized", {"error": "Not signed in"})

    if method == "POST" and path.startswith("/admin/api/"):
        try:
            _d = jbody()
        except Exception:
            _d = {}

        _safe = {k: ("***" if k.lower().endswith(("pass", "password", "token",
                                                  "secret", "key")) else v)
                 for k, v in (_d.items() if isinstance(_d, dict) else [])}
        _txt = json.dumps(_safe, ensure_ascii=False)[:400]
        mod_log("-", "admin", "ADMIN-" + path.rsplit("/", 1)[-1].upper(),
                f"{_txt} (from {safe_ip(client_ip)})")

    if method == "GET" and path == "/admin/ui":
        return await json_resp("200 OK", {"html": ADMIN_APP_HTML,
                                          "js": ADMIN_APP_JS.replace(
                                              "__BASE__", "/" + admin_base()),
                                          "css": ADMIN_CSS})

    if method == "POST" and path == "/admin/api/invite":
        d = jbody()
        act = str(d.get("action", ""))
        if act == "create":
            days = max(1, min(365, int(d.get("days") or INVITE_DEFAULT_DAYS)))
            rank = int(d.get("rank", RANK_MEMBER))
            rank = rank if rank in (RANK_USER, RANK_MEMBER, RANK_WIZARD) else RANK_MEMBER
            inv = new_invite(d.get("note", ""), days, rank)
            return await json_resp("200 OK", {"ok": True, "invite": inv})
        inv = INVITES.get(str(d.get("code", "")))
        if not inv:
            return await json_resp("404 Not Found", {"error": "Not found."})
        if act == "delete":
            INVITES.pop(inv["code"], None)
        elif act == "disable":
            inv["disabled"] = True
        elif act == "enable":

            inv["disabled"] = False
            days = max(1, min(365, int(d.get("days") or INVITE_DEFAULT_DAYS)))
            inv["expires"] = now_ms() + days * 86400_000
        elif act == "extend":
            days = max(1, min(365, int(d.get("days") or INVITE_DEFAULT_DAYS)))
            base_ts = max(now_ms(), int(inv.get("expires") or 0))
            inv["expires"] = base_ts + days * 86400_000
        elif act == "reset":

            inv["used_by"] = ""
            inv["used_at"] = 0
            inv["disabled"] = False
            days = max(1, min(365, int(d.get("days") or INVITE_DEFAULT_DAYS)))
            inv["expires"] = now_ms() + days * 86400_000
        elif act == "note":
            inv["note"] = str(d.get("note", ""))[:120]
        else:
            return await json_resp("400 Bad Request", {"error": "Unbekannt."})
        save_invites()
        return await json_resp("200 OK", {"ok": True})

    if method == "POST" and path == "/admin/api/sendreset":
        d = jbody()
        acc = account_by_login(str(d.get("name", "")))
        if not acc:
            return await json_resp("404 Not Found", {"error": "Account not found."})
        if not acc.get("email"):
            return await json_resp("400 Bad Request",
                {"error": "No e-mail address is stored for this account."})
        if not mail_ready():
            return await json_resp("400 Bad Request",
                {"error": "No mail server configured (see e-mail settings)."})
        tok = reset_token_new(acc["username"])
        ok = await send_mail(
            acc["email"],
            f"{CONFIG.get('servername','Pixplace')}: Reset your password",
            f"Hello {acc['username']},\n\n"
            f"a new password was requested for your account:\n\n"
            f"{public_url()}/reset/{tok}\n\n"
            f"The link is valid for one hour and can be used only once.\n")
        return await json_resp("200 OK" if ok else "500 Internal Server Error",
            {"ok": ok, "to": mask_mail(acc["email"]),
             "error": None if ok else "Sending failed – check the settings."})

    if method == "POST" and path == "/admin/api/setpass":
        d = jbody()
        acc = account_by_login(str(d.get("name", "")))
        if not acc:
            return await json_resp("404 Not Found", {"error": "Account not found."})
        pw = str(d.get("password", "")).strip()
        generated = False
        if not pw:
            pw = gen_passphrase(14)
            generated = True
        elif len(pw) < 8:
            return await json_resp("400 Bad Request",
                {"error": "Mindestens 8 Zeichen."})
        acc["pw_hash"] = await hash_password_async(pw)

        acc["pw_temp"] = True

        acc_clear_tokens(acc)
        save_accounts()
        mod_log("-", acc["username"], "PW-SET-BY-ADMIN",
                f"One-time password set (from {safe_ip(client_ip)})")

        mailed = False
        if d.get("sendMail") and acc.get("email") and mail_ready():
            mailed = await send_mail(
                acc["email"],
                f"{CONFIG.get('servername','Pixplace')}: new password",
                f"Hello {acc['username']},\n\n"
                f"a new password was set for your account:\n\n"
                f"    {pw}\n\n"
                f"Please change it after signing in.\n")
        return await json_resp("200 OK",
            {"ok": True, "password": pw, "generated": generated,
             "mailed": mailed, "user": acc["username"]})

    if method == "POST" and path == "/admin/api/mailtest":
        d = jbody()
        to = str(d.get("to", "")).strip()
        if not valid_mail(to):
            return await json_resp("400 Bad Request", {"error": "Invalid address."})
        ok = await send_mail(to, f"{CONFIG.get('servername','Pixplace')}: Test mail",
                             "If you are reading this, mail sending works.\n")
        return await json_resp("200 OK", {"ok": ok})

    if method == "GET" and path == "/admin/api/media":
        items = sorted(MEDIA_INDEX.values(), key=lambda x: -x.get("ts", 0))[:400]

        out = []
        for it in items:
            fn = str(it.get("url", "")).rsplit("/", 1)[-1]
            if fn and os.path.isfile(os.path.join(MEDIA_DIR, fn)):
                out.append(it)
        return await json_resp("200 OK", {"media": out,
                                          "total": len(MEDIA_INDEX)})

    if method == "POST" and path == "/admin/api/media/delete":
        d = jbody()
        fn = os.path.basename(str(d.get("file", "")))
        if not fn or fn not in MEDIA_INDEX:
            return await json_resp("404 Not Found", {"error": "Not found."})
        try:
            os.remove(os.path.join(MEDIA_DIR, fn))
        except Exception:
            pass
        by = MEDIA_INDEX[fn].get("by", "?")
        MEDIA_INDEX.pop(fn, None)
        save_media_index()
        mod_log("-", "admin", "MEDIA-DELETE", f"{fn} (by {by})")
        return await json_resp("200 OK", {"ok": True})

    if method == "POST" and path == "/admin/api/gdpr/export":
        d = jbody()
        who = str(d.get("name", "")).strip()
        if not who:
            return await json_resp("400 Bad Request", {"error": "Name missing."})
        data = export_subject(who)
        gdpr_log("ACCESS", who, "admin",
                 f"{len(data['messages'])} messages, "
                 f"{len(data['media'])} media items, reason: "
                 f"{str(d.get('reason',''))[:120]}")
        return await http_respond(
            writer, "200 OK",
            json.dumps(data, ensure_ascii=False, indent=2),
            "application/json",
            extra={"Cache-Control": "no-store",
                   "Content-Disposition":
                       'attachment; filename="auskunft-%s.json"'
                       % re.sub(r"[^A-Za-z0-9_-]", "_", who)[:40]})

    if method == "POST" and path == "/admin/api/gdpr/erase":
        d = jbody()
        who = str(d.get("name", "")).strip()
        if not who:
            return await json_resp("400 Bad Request", {"error": "Name missing."})
        if str(d.get("confirm", "")) != who:
            return await json_resp("400 Bad Request",
                {"error": "To confirm, repeat the name exactly."})
        res = erase_subject(who, bool(d.get("keepMedia")))
        gdpr_log("ERASURE", who, "admin",
                 f"{res} reason: {str(d.get('reason',''))[:120]}")
        for u in list(all_users()):
            if u.base.lower() == who.lower():
                try:
                    await u.ws.close()
                except Exception:
                    pass
        return await json_resp("200 OK", {"ok": True, "result": res})

    if method == "GET" and path == "/admin/api/gdpr/log":
        try:
            with open(GDPR_LOG, encoding="utf-8") as f:
                lines = f.readlines()[-500:]
        except Exception:
            lines = []
        return await json_resp("200 OK", {"lines": [l.rstrip() for l in lines]})

    if method == "POST" and path == "/admin/api/report":
        d = jbody()
        rid = str(d.get("id", ""))
        r = REPORTS.get(rid)
        if not r:
            return await json_resp("404 Not Found", {"error": "Not found."})
        act = str(d.get("action", ""))
        if act == "note":
            r["note"] = str(d.get("note", ""))[:500]
        elif act in ("open", "review", "done", "rejected"):
            r["status"] = act
            r["handled"] = now_ms()
            r["handler"] = "admin"
        elif act == "delete":
            REPORTS.pop(rid, None)
        save_reports()
        gdpr_log("REPORT", r.get("target", "?"), "admin", f"{act} #{rid[:8]}")
        return await json_resp("200 OK", {"ok": True})

    if method == "GET" and path == "/admin/api/state":
        return await json_resp("200 OK", admin_state())

    if method == "GET" and path == "/admin/api/logs":
        uq = lambda k: urllib.parse.unquote_plus(query.get(k, "") or "").strip()
        who = uq("user").lower()
        frm = uq("from")
        to = uq("to")
        room_f = uq("room").lower()
        kind_f = uq("kind").upper()
        try:
            limit = max(1, min(20000, int(uq("limit") or 5000)))
        except Exception:
            limit = 5000
        rows, files = [], []
        try:
            for fn in sorted(os.listdir(MOD_DIR)):
                if not fn.endswith(".txt"):
                    continue
                day = fn[:-4]
                if frm and day < frm:
                    continue
                if to and day > to:
                    continue
                files.append(fn)
        except Exception:
            pass
        for fn in files:
            try:
                with open(os.path.join(MOD_DIR, fn), encoding="utf-8",
                          errors="replace") as f:
                    for ln in f:
                        rec = mod_parse(ln, fn[:-4])
                        if not rec:
                            continue
                        if who and who not in rec["user"].lower():
                            continue
                        if room_f and room_f not in rec["room"].lower():
                            continue
                        if kind_f and kind_f not in rec["kind"].upper():
                            continue
                        rows.append(rec)
                        if len(rows) >= limit:
                            break
            except Exception:
                continue
            if len(rows) >= limit:
                break
        return await json_resp("200 OK", {"rows": rows, "count": len(rows),
                                         "files": len(files),
                                         "truncated": len(rows) >= limit})

    if method == "GET" and path == "/admin/api/logs.csv":

        uq = lambda k: urllib.parse.unquote_plus(query.get(k, "") or "").strip()
        who = uq("user").lower()
        frm, to = uq("from"), uq("to")
        out = ["Date;Time;Room;Person;Type;Text"]
        try:
            for fn in sorted(os.listdir(MOD_DIR)):
                if not fn.endswith(".txt"):
                    continue
                day = fn[:-4]
                if (frm and day < frm) or (to and day > to):
                    continue
                with open(os.path.join(MOD_DIR, fn), encoding="utf-8",
                          errors="replace") as f:
                    for ln in f:
                        rec = mod_parse(ln, day)
                        if not rec:
                            continue
                        if who and who not in rec["user"].lower():
                            continue
                        cells = [rec["date"], rec["time"], rec["room"],
                                 rec["user"], rec["kind"], rec["text"]]
                        out.append(";".join(
                            '"' + str(c).replace('"', '""') + '"'
                            for c in cells))
        except Exception:
            pass
        csv = "\ufeff" + "\r\n".join(out)
        fname = "pixplace-log"
        if who:
            fname += "-" + re.sub(r"[^\w\-]", "", who)[:20]
        return await http_respond(
            writer, "200 OK", csv, "text/csv; charset=utf-8",
            extra={"Content-Disposition":
                   f'attachment; filename="{fname}.csv"'})

    if method == "POST" and path == "/admin/api/settings":
        d = jbody()
        if isinstance(d.get("servername"), str) and d["servername"].strip():
            CONFIG["servername"] = d["servername"].strip()[:40]
        if isinstance(d.get("notice"), str) and d["notice"].strip():
            CONFIG["moderation_notice"] = d["notice"].strip()[:2000]
        if "logging" in d:
            CONFIG["moderation_logging"] = bool(d["logging"])
        if d.get("ownerPass"):
            CONFIG["owner_pass"] = str(d["ownerPass"])
        if d.get("wizardPass"):
            CONFIG["wizard_pass"] = str(d["wizardPass"])
        if "testMode" in d:
            CONFIG["test_mode"] = bool(d["testMode"])
        if "privateMode" in d:
            CONFIG["private_mode"] = bool(d["privateMode"])
        if isinstance(d.get("smtp"), dict):
            cur = dict(CONFIG.get("smtp") or {})
            for k in ("host", "user", "from", "security"):
                if k in d["smtp"]:
                    cur[k] = str(d["smtp"][k])
            if "port" in d["smtp"]:
                cur["port"] = int(d["smtp"]["port"] or 587)

            if d["smtp"].get("password"):
                cur["password"] = str(d["smtp"]["password"])
            CONFIG["smtp"] = cur
        if "adminHidden" in d:
            CONFIG["admin_hidden"] = bool(d["adminHidden"])
        if d.get("adminPath"):
            CONFIG["admin_path"] = str(d["adminPath"])
        if d.get("adminMask") in ("default", "wp"):
            CONFIG["admin_mask"] = d["adminMask"]
        if "publicRegistration" in d:
            CONFIG["public_registration"] = bool(d["publicRegistration"])
        if "demoMode" in d:
            CONFIG["demo_mode"] = bool(d["demoMode"])
        if d.get("newTestKey"):

            CONFIG["test_key"] = gen_passphrase(18)
        save_config()
        return await json_resp("200 OK", admin_state())

    if method == "POST" and path == "/admin/api/grant":
        d = jbody()
        name = str(d.get("name", "")).strip().lstrip("*").lower()
        role = str(d.get("role", "user")).lower()
        rank = {"user": RANK_USER, "member": RANK_MEMBER,
                "wizard": RANK_WIZARD, "owner": RANK_OWNER}.get(role)
        if not name or rank is None:
            return await json_resp("400 Bad Request", {"error": "name/role missing"})
        if rank == RANK_USER:
            CONFIG["grants"].pop(name, None)
        else:
            CONFIG["grants"][name] = rank
        save_config()
        await _apply_grant_live(name, rank)
        return await json_resp("200 OK", admin_state())

    if method == "POST" and path == "/admin/api/revoke":
        name = str(jbody().get("name", "")).strip().lower()
        CONFIG["grants"].pop(name, None)
        save_config()
        await _apply_grant_live(name, RANK_USER)
        return await json_resp("200 OK", admin_state())

    if method == "POST" and path == "/admin/api/perms":
        d = jbody()
        cap = str(d.get("cap", ""))
        rank = str(d.get("rank", ""))
        allowed = bool(d.get("allowed"))
        if cap not in dict(PERM_DEFS) or rank not in ("0", "1", "2", "3"):
            return await json_resp("400 Bad Request", {"error": "cap/rank invalid"})
        table = perms().setdefault(cap, dict(
            (str(k), v) for k, v in DEFAULT_PERMS.get(cap, {}).items()))
        table[rank] = allowed
        save_config()
        return await json_resp("200 OK", admin_state())

    if method == "POST" and path == "/admin/api/account":

        d = jbody()
        uname = clean_base_name(d.get("username", ""))
        if not uname or len(uname) < 2:
            return await json_resp("400 Bad Request", {"error": "Name zu kurz"})
        key = uname.lower()
        if key in ACCOUNTS:
            return await json_resp("409 Conflict", {"error": "Name existiert"})
        _tok = uuid.uuid4().hex + uuid.uuid4().hex
        acc = {"username": uname, "token_hash": token_hash(_tok),
               "rank": RANK_MEMBER, "created": now_ms()}
        ACCOUNTS[key] = acc
        save_accounts()
        st = admin_state(); st["newToken"] = acc["token"]; st["newName"] = uname
        return await json_resp("200 OK", st)

    if method == "POST" and path == "/admin/api/account/delete":

        key = str(jbody().get("username", "")).strip().lower()
        ACCOUNTS.pop(key, None)
        save_accounts()
        return await json_resp("200 OK", admin_state())

    if method == "POST" and path == "/admin/api/room":

        d = jbody()
        name = str(d.get("name", ""))
        action = str(d.get("action", ""))
        rm = ROOMS.get(name)
        if not rm:
            return await json_resp("404 Not Found", {"error": "Room not found"})
        if rm.name in BUILTIN_ROOMS and action in ("temporary", "delete"):
            return await json_resp("400 Bad Request", {"error": "Standardraum"})
        if action in ("permanent", "approve"):
            rm.persistent = True; rm.perm_requested = False; save_rooms()
            await broadcast(rm, {"t": "roomstate", "persistent": True,
                                 "permRequested": False})
        elif action == "temporary":
            rm.persistent = False; rm.perm_requested = False; save_rooms()
            await broadcast(rm, {"t": "roomstate", "persistent": False,
                                 "permRequested": False})
        elif action == "deny":
            rm.perm_requested = False
            await broadcast(rm, {"t": "roomstate", "persistent": rm.persistent,
                                 "permRequested": False})
        elif action == "delete":
            for u in list(rm.users.values()):
                await join_room(u, start_room())
            ROOMS.pop(rm.name, None); save_rooms(); await push_rooms()
        else:
            return await json_resp("400 Bad Request", {"error": "Aktion?"})
        return await json_resp("200 OK", admin_state())

    if method == "POST" and path == "/admin/api/user":

        d = jbody()
        uid = str(d.get("id", ""))
        action = str(d.get("action", ""))
        u = users_by_id(uid)
        if not u:
            return await json_resp("404 Not Found", {"error": "User offline"})
        if action == "gag":
            u.gagged = True
            if u.room:
                await broadcast(u.room, {"t": "gagged", "id": u.id, "on": True})
            await send(u, {"t": "sysmsg", "text": "You were gagged (by the admin)."})
        elif action == "ungag":
            u.gagged = False
            if u.room:
                await broadcast(u.room, {"t": "gagged", "id": u.id, "on": False})
            await send(u, {"t": "sysmsg", "text": "Your gag was removed."})
        elif action == "pin":
            u.pinned = True; u.x, u.y = 40, 60
            if u.room:
                await broadcast(u.room, {"t": "move", "id": u.id, "x": 40, "y": 60})
                await broadcast(u.room, {"t": "pinned", "id": u.id, "on": True})
            await send(u, {"t": "sysmsg", "text": "Du wurdest festgesetzt (Admin)."})
        elif action == "unpin":
            u.pinned = False
            if u.room:
                await broadcast(u.room, {"t": "pinned", "id": u.id, "on": False})
            await send(u, {"t": "sysmsg", "text": "You can move again."})
        elif action in ("kick", "ban"):
            if action == "ban":
                BANS["names"].add(u.base.lower()); BANS["ips"].add(u.ws.ip)
            await send(u, {"t": "killed",
                           "msg": "You were disconnected by the admin"
                                  + (" and banned." if action == "ban" else ".")})
            try:
                await u.ws.close()
            except Exception:
                pass
        else:
            return await json_resp("400 Bad Request", {"error": "Aktion?"})
        mod_log(u.room.name if u.room else "-", u.base, "ADMIN", action)
        return await json_resp("200 OK", admin_state())

    if method == "GET" and path == "/admin/api/log":
        date = os.path.basename(query.get("date", ""))
        p = os.path.join(MOD_DIR, f"{date}.txt")
        if date and os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return await http_respond(writer, "200 OK", f.read(),
                                          "text/plain; charset=utf-8")
        return await http_respond(writer, "404 Not Found", "(no log)")

    return await json_resp("404 Not Found", {"error": "unbekannt"})

PORTAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#08070c">
<meta name="description" content="Pixplace – 2D chat portal: live presence, comments and the app to install.">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/icon-192.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Pixplace">
<title>Pixplace – Portal</title>
<style>
:root{
  /* Base: deep black with slightly violet-tinted surfaces */
  --bg:#08070c;
  --bg-2:#0d0b13;
  --panel:rgba(23,19,32,.72);
  --panel-solid:#17131f;
  --panel-2:rgba(33,27,46,.78);
  --panel-3:#2a2239;
  --line:rgba(150,110,225,.16);
  --line-2:rgba(150,110,225,.28);
  --ink:#f1ecfb;
  --dim:#a89dc0;
  --faint:#746a8c;
  /* Accents exclusively purple / violet */
  --accent:#a855f7;
  --accent-2:#c77dff;
  --accent-3:#7c3aed;
  --accent-press:#9333ea;
  --accent-soft:rgba(168,85,247,.14);
  --accent-line:rgba(168,85,247,.42);
  --glow:0 0 28px rgba(168,85,247,.34);
  --glow-soft:0 0 18px rgba(168,85,247,.18);
  --ok:#4bbe83;--wiz:#c77dff;--own:#e0a63a;
  --r:16px;--r-sm:11px;--r-xs:8px;
  --shadow:0 18px 60px rgba(0,0,0,.62);
  --body:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,system-ui,sans-serif;
  --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
html,body{min-height:100%}
body{font-family:var(--body);background:var(--bg);color:var(--ink);
  -webkit-font-smoothing:antialiased;line-height:1.6;letter-spacing:-.005em;
  padding:env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
  position:relative;overflow-x:hidden}
/* Soft, deep purple veils in the background */
body::before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;
  background:
    radial-gradient(60% 50% at 15% -5%,rgba(124,58,237,.20),transparent 62%),
    radial-gradient(52% 44% at 92% 6%,rgba(168,85,247,.15),transparent 60%),
    radial-gradient(70% 55% at 50% 108%,rgba(99,44,190,.16),transparent 64%),
    var(--bg)}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  opacity:.5;background-image:
    linear-gradient(rgba(168,85,247,.045) 1px,transparent 1px),
    linear-gradient(90deg,rgba(168,85,247,.045) 1px,transparent 1px);
  background-size:64px 64px;
  -webkit-mask-image:radial-gradient(70% 55% at 50% 0%,#000,transparent 78%);
  mask-image:radial-gradient(70% 55% at 50% 0%,#000,transparent 78%)}
a{color:var(--accent-2);text-decoration:none;transition:color .18s ease}
a:hover{color:#e2c4ff}
.wrap{max-width:1080px;margin:0 auto;padding:0 22px}

/* ---------- Header bar: glass with a fine purple edge ---------- */
.top{position:sticky;top:0;z-index:50;
  background:linear-gradient(180deg,rgba(12,10,18,.86),rgba(12,10,18,.62));
  backdrop-filter:blur(18px) saturate(150%);
  -webkit-backdrop-filter:blur(18px) saturate(150%);
  border-bottom:1px solid var(--line)}
.top::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent-line),transparent)}
.topbar{display:flex;align-items:center;gap:22px;padding:13px 22px;
  max-width:1080px;margin:0 auto}
.brand{display:flex;align-items:center;gap:10px;font-weight:750;font-size:17px;
  color:var(--ink);text-decoration:none;letter-spacing:-.02em}
.brand:hover{color:var(--ink)}
.brand .logo{display:inline-grid;place-items:center;width:30px;height:30px;
  border-radius:9px;color:#fff;font-size:15px;
  background:linear-gradient(140deg,var(--accent-3),var(--accent) 55%,var(--accent-2));
  box-shadow:var(--glow-soft);transition:box-shadow .25s ease,transform .25s ease}
.brand:hover .logo{box-shadow:var(--glow);transform:translateY(-1px)}
.brand .logo svg.pxp{display:block}
.brand .logo{overflow:hidden}

.mainnav{display:flex;gap:4px;flex:1;flex-wrap:wrap}
.mainnav a{color:var(--dim);text-decoration:none;font-size:14px;font-weight:500;
  padding:7px 12px;border-radius:9px;position:relative;transition:color .18s ease,background .18s ease}
.mainnav a:hover{color:var(--ink);background:var(--accent-soft)}
.topright{display:flex;align-items:center;gap:10px;position:relative}

/* ---------- Sprachumschalter ---------- */
.langbtn{display:inline-flex;align-items:center;gap:7px;
  background:var(--panel-2);border:1px solid var(--line);color:var(--ink);
  border-radius:10px;height:36px;padding:0 12px;font:inherit;font-size:13px;
  font-weight:600;cursor:pointer;letter-spacing:.02em;
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  transition:border-color .2s ease,background .2s ease,box-shadow .2s ease}
.langbtn:hover{background:var(--panel-3);border-color:var(--accent-line);
  box-shadow:var(--glow-soft)}
.langbtn .globe{font-size:14px;line-height:1;opacity:.9}
.langbtn .code{font-family:var(--mono);font-size:12px;letter-spacing:.06em}
.langbtn .chev{font-size:9px;opacity:.6;transition:transform .2s ease}
.langbtn[aria-expanded="true"] .chev{transform:rotate(180deg)}
.langbtn[aria-expanded="true"]{border-color:var(--accent-line);box-shadow:var(--glow-soft)}
.langmenu{display:none;position:absolute;right:0;top:46px;
  background:rgba(20,16,28,.94);backdrop-filter:blur(20px) saturate(160%);
  -webkit-backdrop-filter:blur(20px) saturate(160%);
  border:1px solid var(--line-2);border-radius:13px;padding:6px;min-width:196px;
  box-shadow:var(--shadow),var(--glow-soft);z-index:60;
  max-height:min(420px,70vh);overflow:auto}
.langmenu.open{display:block;animation:langIn .18s ease}
@keyframes langIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.langitem{display:flex;align-items:center;gap:10px;width:100%;padding:9px 11px;
  background:none;border:0;color:var(--dim);font:inherit;font-size:13.5px;
  text-align:left;border-radius:9px;cursor:pointer;transition:background .15s ease,color .15s ease}
.langitem:hover{background:var(--accent-soft);color:var(--ink)}
.langitem.on{background:linear-gradient(90deg,rgba(168,85,247,.26),rgba(168,85,247,.10));
  color:#fff;font-weight:600;box-shadow:inset 2px 0 0 var(--accent)}

/* ---------- Buttons ---------- */
.cta,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  font:inherit;font-weight:650;font-size:14px;cursor:pointer;text-decoration:none;
  border-radius:11px;padding:10px 18px;border:1px solid transparent;
  transition:transform .2s ease,box-shadow .25s ease,background .2s ease,border-color .2s ease}
.cta{color:#fff;position:relative;overflow:hidden;
  background:linear-gradient(135deg,var(--accent-3),var(--accent) 58%,var(--accent-2));
  box-shadow:0 6px 22px rgba(124,58,237,.34)}
.cta::after{content:"";position:absolute;inset:0;
  background:linear-gradient(120deg,transparent 20%,rgba(255,255,255,.22),transparent 62%);
  transform:translateX(-120%);transition:transform .6s ease}
.cta:hover{transform:translateY(-2px);color:#fff;
  box-shadow:0 10px 34px rgba(168,85,247,.48),var(--glow)}
.cta:hover::after{transform:translateX(120%)}
.cta:active{transform:translateY(0)}
.cta.big{padding:15px 30px;font-size:16px;border-radius:14px;margin-top:10px}
.btn{background:var(--panel-2);border-color:var(--line);color:var(--ink);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
.btn:hover{background:var(--panel-3);border-color:var(--accent-line);
  box-shadow:var(--glow-soft)}
.btn.primary{background:linear-gradient(135deg,var(--accent-3),var(--accent));
  border-color:transparent;color:#fff}
.btn.primary:hover{box-shadow:var(--glow)}
.btn.big{padding:14px 24px;font-size:15px;border-radius:var(--r)}

/* ---------- Hero ---------- */
.hero{padding:82px 22px 62px;text-align:center;position:relative;
  max-width:1080px;margin:0 auto}
.hero h1{font-size:clamp(40px,7vw,68px);line-height:1.03;margin:0 0 14px;
  font-weight:800;letter-spacing:-.035em;
  background:linear-gradient(180deg,#fff 20%,#cdb4f0 65%,#a855f7);
  -webkit-background-clip:text;background-clip:text;color:transparent;
  filter:drop-shadow(0 4px 30px rgba(168,85,247,.28))}
.lead{color:var(--accent-2);font-size:clamp(16px,2.3vw,19px);font-weight:550;
  margin:0 0 16px;letter-spacing:-.01em}
.herotext{color:var(--dim);max-width:600px;margin:0 auto 8px;line-height:1.75;
  font-size:15.5px}

/* ---------- Abschnitte ---------- */
main section{padding:64px 0 56px;border-top:1px solid var(--line);position:relative}
main section::before{content:"";position:absolute;top:-1px;left:12%;right:12%;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent-line),transparent)}
.hero+section{border-top:0}
.hero+section::before{display:none}
main h2{font-size:clamp(21px,3vw,27px);margin:0 0 22px;font-weight:730;
  letter-spacing:-.025em}

/* ---------- Karten: Glasoptik ---------- */
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(258px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  padding:22px;position:relative;overflow:hidden;
  backdrop-filter:blur(16px) saturate(140%);
  -webkit-backdrop-filter:blur(16px) saturate(140%);
  transition:transform .28s ease,border-color .28s ease,box-shadow .28s ease}
.card::before{content:"";position:absolute;inset:0;border-radius:inherit;
  padding:1px;pointer-events:none;opacity:0;transition:opacity .28s ease;
  background:linear-gradient(140deg,var(--accent-line),transparent 45%,rgba(199,125,255,.3));
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude}
.card:hover{transform:translateY(-4px);border-color:transparent;
  box-shadow:0 18px 46px rgba(0,0,0,.5),var(--glow-soft)}
.card:hover::before{opacity:1}
.card .ic{font-size:24px;margin-bottom:10px;display:inline-grid;place-items:center;
  width:44px;height:44px;border-radius:12px;
  background:linear-gradient(140deg,rgba(124,58,237,.22),rgba(168,85,247,.10));
  border:1px solid var(--line);transition:box-shadow .28s ease}
.card:hover .ic{box-shadow:var(--glow-soft)}
.card h3{font-size:15.5px;margin:0 0 7px;font-weight:660;letter-spacing:-.015em}
.card p{color:var(--dim);font-size:13.5px;line-height:1.68;margin:0}

/* ---------- Steps ---------- */
.steps{counter-reset:s;list-style:none;padding:0;margin:0;display:grid;gap:13px}
.steps li{counter-increment:s;position:relative;padding:14px 18px 14px 58px;
  color:var(--dim);font-size:14.5px;line-height:1.68;
  background:var(--panel);border:1px solid var(--line);border-radius:13px;
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  transition:border-color .25s ease,transform .25s ease}
.steps li:hover{border-color:var(--line-2);transform:translateX(3px)}
.steps+.small{margin-top:16px;display:block}
.steps li::before{content:counter(s);position:absolute;left:16px;top:13px;
  width:28px;height:28px;display:grid;place-items:center;border-radius:9px;
  background:linear-gradient(140deg,var(--accent-3),var(--accent));
  color:#fff;font-weight:750;font-size:13px;box-shadow:var(--glow-soft)}

/* ---------- Hinweiskarten ---------- */
.notecards{display:grid;gap:13px;grid-template-columns:repeat(auto-fit,minmax(278px,1fr))}
.note{display:flex;gap:13px;background:var(--panel);border:1px solid var(--line);
  border-radius:13px;padding:17px;backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);transition:border-color .25s ease}
.note:hover{border-color:var(--line-2)}
.note b{font-size:18px;line-height:1.3;flex:none}
.note p{margin:0;color:var(--dim);font-size:13.5px;line-height:1.68}

/* ---------- Kleinkram ---------- */
.small{font-size:13px;color:var(--dim)}
.small a{color:var(--accent-2)}
.foot{padding:32px 22px 46px;border-top:1px solid var(--line);text-align:center;
  color:var(--faint);position:relative}
.foot::before{content:"";position:absolute;top:-1px;left:20%;right:20%;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent-line),transparent)}
.foot .small{color:var(--faint)}
.skip{position:absolute;left:-9999px}
.skip:focus{left:12px;top:12px;background:var(--accent);color:#fff;padding:9px 14px;
  border-radius:9px;z-index:100}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:6px}

/* ---------- Presence / comments (portal cards) ---------- */
.pill{font-family:var(--mono);font-size:11.5px;background:var(--panel-2);
  border:1px solid var(--line);border-radius:999px;padding:3px 11px;color:var(--dim)}
.pill.live{color:#e6d2ff;border-color:var(--accent-line);background:var(--accent-soft)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--accent);
  display:inline-block;box-shadow:0 0 0 3px var(--accent-soft)}
.dot.off{background:var(--faint);box-shadow:0 0 0 3px rgba(116,106,140,.18)}
.list{max-height:340px;overflow:auto}
.u{display:flex;align-items:center;gap:11px;padding:11px 18px;
  border-bottom:1px solid var(--line)}
.u:last-child{border-bottom:0}
.av{width:31px;height:31px;border-radius:10px;flex:none;display:inline-flex;
  align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:13px;
  background:linear-gradient(140deg,var(--accent-3),var(--accent))}
.u .meta{flex:1;min-width:0}
.u .nm{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.u .rm{color:var(--faint);font-size:12px}
.role{font-size:10.5px;font-weight:700;border-radius:999px;padding:2px 9px}
.role.user{background:var(--panel-2);color:var(--dim)}
.role.member{background:var(--accent-soft);color:var(--accent-2)}
.role.wizard{background:rgba(199,125,255,.16);color:var(--wiz)}
.role.owner{background:rgba(224,166,58,.15);color:var(--own)}
.empty{padding:28px 18px;color:var(--faint);text-align:center;font-size:13px}
.cbox{padding:15px 18px;border-bottom:1px solid var(--line)}
.cbox .row{display:flex;gap:9px}
input,textarea{width:100%;background:rgba(10,8,15,.6);border:1px solid var(--line);
  color:var(--ink);border-radius:var(--r-sm);padding:11px 13px;font:inherit;
  transition:border-color .2s ease,box-shadow .2s ease,background .2s ease}
input::placeholder,textarea::placeholder{color:var(--faint)}
input:focus,textarea:focus{outline:none;border-color:var(--accent-line);
  background:rgba(23,19,32,.8);box-shadow:0 0 0 3px var(--accent-soft)}
input#c-name{max-width:180px}
textarea{margin-top:9px;resize:vertical;min-height:46px}
.cmsg{padding:13px 18px;border-bottom:1px solid var(--line)}
.cmsg:last-child{border-bottom:0}
.cmsg .h{display:flex;align-items:baseline;gap:9px;margin-bottom:4px}
.cmsg .nm{font-weight:650;font-size:13.5px}
.cmsg .t{color:var(--faint);font-size:11px;font-family:var(--mono)}
.cmsg .bd{color:var(--ink);font-size:14px;white-space:pre-wrap;word-break:break-word}

/* ---------- Install bar / sheet ---------- */
#install-bar{position:fixed;left:0;right:0;bottom:0;z-index:50;
  background:rgba(20,16,28,.92);backdrop-filter:blur(18px);
  -webkit-backdrop-filter:blur(18px);border-top:1px solid var(--line-2);
  padding:calc(13px + env(safe-area-inset-bottom)) 17px 13px;display:none;
  align-items:center;gap:13px;box-shadow:0 -10px 40px rgba(0,0,0,.55)}
#install-bar.show{display:flex}
#install-bar .txt{flex:1;font-size:13.5px}
#install-bar .txt b{display:block}
#install-bar .txt span{color:var(--dim);font-size:12px}
.overlay{position:fixed;inset:0;background:rgba(6,5,10,.76);
  backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
  display:none;align-items:flex-end;justify-content:center;z-index:60;padding:0}
.overlay.show{display:flex}
.sheet{background:rgba(23,19,32,.96);backdrop-filter:blur(20px);
  -webkit-backdrop-filter:blur(20px);
  border:1px solid var(--line-2);border-bottom:0;border-radius:22px 22px 0 0;
  width:min(520px,100%);
  padding:24px 24px calc(24px + env(safe-area-inset-bottom));box-shadow:var(--shadow)}
.sheet h3{font-size:17px;margin-bottom:7px;font-weight:680}
.sheet p{color:var(--dim);font-size:13.5px;margin-bottom:17px}
.step{display:flex;gap:13px;align-items:flex-start;padding:10px 0}
.step .n{width:27px;height:27px;border-radius:9px;
  background:linear-gradient(140deg,var(--accent-3),var(--accent));color:#fff;
  font-weight:750;display:inline-flex;align-items:center;justify-content:center;
  flex:none;font-size:13px}
.step .d{font-size:14px}
.sheet .close{margin-top:17px;width:100%;justify-content:center}
.hidden{display:none!important}

@media(max-width:640px){
  .hero{padding:56px 20px 44px}
  .mainnav{display:none}
  .topbar{gap:12px;padding:11px 16px}
  .langbtn .code{display:none}
}
@media(prefers-reduced-motion:reduce){
  *{transition:none!important;animation:none!important;scroll-behavior:auto!important}
  .card:hover,.steps li:hover,.cta:hover{transform:none}
}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>

<header class="top">
  <div class="wrap topbar">
    <a class="brand" href="#main"><span class="logo"><svg class="pxp" width="16" height="16" viewBox="0 0 6 7" fill="#fff" aria-hidden="true" shape-rendering="crispEdges"><rect x="0" y="0" width="1" height="1"/><rect x="1" y="0" width="1" height="1"/><rect x="2" y="0" width="1" height="1"/><rect x="3" y="0" width="1" height="1"/><rect x="4" y="0" width="1" height="1"/><rect x="0" y="1" width="1" height="1"/><rect x="1" y="1" width="1" height="1"/><rect x="4" y="1" width="1" height="1"/><rect x="5" y="1" width="1" height="1"/><rect x="0" y="2" width="1" height="1"/><rect x="1" y="2" width="1" height="1"/><rect x="4" y="2" width="1" height="1"/><rect x="5" y="2" width="1" height="1"/><rect x="0" y="3" width="1" height="1"/><rect x="1" y="3" width="1" height="1"/><rect x="2" y="3" width="1" height="1"/><rect x="3" y="3" width="1" height="1"/><rect x="4" y="3" width="1" height="1"/><rect x="0" y="4" width="1" height="1"/><rect x="1" y="4" width="1" height="1"/><rect x="0" y="5" width="1" height="1"/><rect x="1" y="5" width="1" height="1"/><rect x="0" y="6" width="1" height="1"/><rect x="1" y="6" width="1" height="1"/></svg></span>Pixplace</a>
    <nav class="mainnav">
      <a href="#features" data-i18n="web.nav.features">Features</a>
      <a href="#howto" data-i18n="web.nav.howto">Getting started</a>
      <a href="#safety" data-i18n="web.nav.safety">Safety</a>
      <a href="#legal" data-i18n="web.nav.legal">Legal</a>
    </nav>
    <div class="topright">
      <button id="langbtn" class="langbtn" aria-haspopup="true"
        aria-expanded="false" title="Language"><span class="globe">◈</span><span class="code" id="langcode">EN</span><span class="chev">▼</span></button>
      <div id="langmenu" class="langmenu" role="menu"></div>
      <a class="cta" href="/app" data-i18n="web.enter">Enter chat</a>
    </div>
  </div>
</header>

<main id="main">

  <section class="hero wrap">
    <h1>Pixplace</h1>
    <p class="lead" data-i18n="web.tagline">2D chat with your own avatars and rooms</p>
    <p class="herotext" data-i18n="web.hero.text">A chat that looks like a
      place. You move through rooms as a picture, speak in bubbles and
      set everything up yourself – in the browser, no installation.</p>
    <a class="cta big" href="/app" data-i18n="web.enter">Enter chat</a>
  </section>

  <section id="features" class="wrap">
    <h2 data-i18n="web.nav.features">Features</h2>
    <div class="grid">
      <article class="card"><div class="ic">🎭</div>
        <h3 data-i18n="web.f.avatars.h">Your own avatars</h3>
        <p data-i18n="web.f.avatars.p">Upload pictures, cut out the background and
          wear up to twelve layered on top of each other. Everything lands in your bag and
          stays there.</p></article>
      <article class="card"><div class="ic">🚪</div>
        <h3 data-i18n="web.f.rooms.h">Rooms and doors</h3>
        <p data-i18n="web.f.rooms.p">Your own rooms with their own background,
          linked by doors. Lock your room with one click if you like.
          </p></article>
      <article class="card"><div class="ic">🛡</div>
        <h3 data-i18n="web.f.guilds.h">Guilds and clans</h3>
        <p data-i18n="web.f.guilds.p">Found a group, hand out custom
          rank names and rights, earn renown and unlock perks
          with it.</p></article>
      <article class="card"><div class="ic">🎬</div>
        <h3 data-i18n="web.f.media.h">Watch together</h3>
        <p data-i18n="web.f.media.p">Share a video in the room – it plays for
          everyone at once. Switch to audio only if you just want to listen.</p></article>
      <article class="card"><div class="ic">🔒</div>
        <h3 data-i18n="web.f.whisper.h">Whisper and group chat</h3>
        <p data-i18n="web.f.whisper.p">Private messages across rooms,
          plus a channel only group members can read.</p></article>
      <article class="card"><div class="ic">⌨</div>
        <h3 data-i18n="web.f.script.h">Program your rooms</h3>
        <p data-i18n="web.f.script.p">With PPScript rooms react to
          events – greet, count, redirect. One line, one
          command.</p></article>
    </div>
  </section>

  <section id="howto" class="wrap">
    <h2 data-i18n="web.howto.h">Join in three steps</h2>
    <ol class="steps">
      <li data-i18n="web.howto.1">Tap "Enter chat". As a guest you get
        a name right away – nothing else needed.</li>
      <li data-i18n="web.howto.2">Put a picture into your bag as an avatar and
        put it on.</li>
      <li data-i18n="web.howto.3">Want your own rooms or a guild? Become a
        member. Then your name is reserved for you.</li>
    </ol>
    <p class="small"><a href="/manual">Scripting manual</a></p>
  </section>

  <section id="safety" class="wrap">
    <h2 data-i18n="web.safety.h">How moderation works here</h2>
    <div class="notecards">
      <div class="note"><b>🤖</b><p data-i18n="web.safety.filter">Moderation
        is mostly automatic: filters act on blocked words, floods
        and conspicuous content. The use of automated methods
        including AI is possible but currently not in use.</p></div>
      <div class="note"><b>👁</b><p data-i18n="web.safety.noread">Nobody
        reads along. There is no permanent monitoring of conversations.
        Logs are only looked at when there is a reason – e.g. after a
        report or a concrete suspicion.</p></div>
      <div class="note"><b>📋</b><p data-i18n="web.safety.logged">To make that
        possible, rooms are logged. The notice "moderated &amp;
        logged" stays visible in the chat window.</p></div>
      <div class="note"><b>⚖</b><p data-i18n="web.safety.own">Participation
        is at your own risk. Content comes from the users,
        not from the operator.</p></div>
    </div>
    <p class="small" data-i18n="web.safety.report">Report problems: with ::page
      you reach moderation directly in the chat.</p>
  </section>

  <section id="legal" class="wrap">
    <h2 data-i18n="web.nav.legal">Legal</h2>
    <p class="small">
      <a href="/imprint" data-i18n="web.legal.imprint">Imprint</a> ·
      <a href="/privacy" data-i18n="web.legal.privacy">Privacy</a> ·
      <a href="/terms" data-i18n="web.legal.terms">Terms</a>
    </p>
  </section>

</main>

<footer class="wrap foot">
  <p class="small" data-i18n="web.footer.note">Privately run
    hobby project. No guarantee of availability.</p>
  <p class="small">
    <a href="/imprint" data-i18n="web.legal.imprint">Imprint</a> ·
    <a href="/privacy" data-i18n="web.legal.privacy">Privacy</a> ·
    <a href="/terms" data-i18n="web.legal.terms">Terms</a> ·
    <a href="/status" data-i18n="web.status">Status</a>
  </p>
</footer>

<script>
/* Language system of the website – uses the same files as the chat, so
   a change here also applies in the chat (same localStorage key). */
let LANGS=[],TR={},TR_EN={},LANG="en";   // default language: English
function parseLang(txt){
  const out={};
  for(const raw of String(txt||"").split(/\r?\n/)){
    const ln=raw.trim();
    if(!ln||ln.startsWith("#"))continue;
    const i=ln.indexOf(" = ");
    if(i>0)out[ln.slice(0,i).trim()]=ln.slice(i+3).trim();
  }
  return out;
}
async function fetchLang(c){
  const r=await fetch("/lang/"+c+".lang",{cache:"no-store"});
  if(!r.ok)throw new Error("missing "+c);
  return parseLang(await r.text());
}
function applyLang(){
  document.querySelectorAll("[data-i18n]").forEach(el=>{
    const v=TR[el.dataset.i18n]||TR_EN[el.dataset.i18n];
    if(v!==undefined)el.textContent=v;
  });
  document.documentElement.lang=LANG;
  document.title="Pixplace – "+(TR["web.tagline"]||"Portal");
}
async function setLang(c){
  try{
    // English is the fallback: if a key is missing anywhere, English is used
    if(!Object.keys(TR_EN).length)TR_EN=await fetchLang("en");
    TR=(c==="en")?TR_EN:await fetchLang(c);
    LANG=c;
    try{localStorage.setItem("pp_lang",c);}catch(e){}
    // Kuerzel im Umschalter mitfuehren (DE | EN | ...)
    const lc=document.getElementById("langcode");
    if(lc)lc.textContent=c.toUpperCase();
    applyLang();renderMenu();
  }catch(e){}
}
function renderMenu(){
  const m=document.getElementById("langmenu");
  if(!m)return;
  m.innerHTML="";
  for(const l of LANGS){
    const b=document.createElement("button");
    b.className="langitem"+(l.code===LANG?" on":"");
    b.innerHTML="<span>"+l.flag+"</span><span>"+l.name+"</span>";
    b.onclick=()=>{setLang(l.code);m.classList.remove("open");
      document.getElementById("langbtn").setAttribute("aria-expanded","false");};
    m.appendChild(b);
  }
}
(async()=>{
  try{
    const r=await fetch("/lang/list",{cache:"no-store"});
    LANGS=(await r.json()).langs||[];
  }catch(e){LANGS=[];}
  let want=null;
  try{want=localStorage.getItem("pp_lang");}catch(e){}
  if(!want){
    const n=(navigator.language||"en").slice(0,2).toLowerCase();
    if(LANGS.some(l=>l.code===n))want=n;
  }
  await setLang(want||"en");
})();
const lb=document.getElementById("langbtn");
if(lb)lb.onclick=()=>{
  const m=document.getElementById("langmenu");
  const on=m.classList.toggle("open");
  lb.setAttribute("aria-expanded",on?"true":"false");
};
addEventListener("click",e=>{
  if(e.target.closest("#langbtn")||e.target.closest("#langmenu"))return;
  const m=document.getElementById("langmenu");
  if(m)m.classList.remove("open");
});
</script>
</body></html>
"""

MANIFEST_JSON = r"""{
  "name": "Pixplace – 2D Chat",
  "short_name": "Pixplace",
  "description": "2D chat room with avatars, your own rooms and live presence.",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "any",
  "background_color": "#15171d",
  "theme_color": "#15171d",
  "categories": ["social", "communication"],
  "lang": "en",
  "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any" },
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "maskable" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable" }
  ],
  "shortcuts": [
    { "name": "Open app", "url": "/app", "description": "Straight into the chat" }
  ]
}
"""

SW_JS = r"""/* Pixplace Service Worker – app-shell caching + offline behaviour */
/* __STAMP__ – changes with every new program version so old
   caches are reliably discarded. */
const VERSION = 'pixplace-__STAMP__';
const SHELL = ['/manifest.json', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(VERSION).then(cache => cache.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Never serve dynamic content from the cache
  if (url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/media/') ||
      url.pathname.startsWith('/admin') ||
      req.headers.get('upgrade') === 'websocket') {
    event.respondWith(fetch(req));
    return;
  }

  // Always fetch pages from the network first. Previously it worked the other way
  // round: after an update you would get the old app from the cache for weeks –
  // with exactly the bugs that were long fixed.
  const isPage = req.mode === 'navigate' ||
                 (req.headers.get('accept') || '').includes('text/html');
  if (isPage) {
    event.respondWith(
      fetch(req).then(res => {
        if (res && res.status === 200) {
          const copy = res.clone();
          caches.open(VERSION).then(c => c.put(req, copy));
        }
        return res;
      }).catch(() => caches.match(req).then(c => c || caches.match('/')))
    );
    return;
  }

  // Images/manifest: cache first, refresh in the background
  event.respondWith(
    caches.match(req).then(cached => {
      const network = fetch(req).then(res => {
        if (res && res.status === 200 && res.type === 'basic') {
          const copy = res.clone();
          caches.open(VERSION).then(c => c.put(req, copy));
        }
        return res;
      }).catch(() => cached);
      return cached || network;
    })
  );
});
"""

def sw_js() -> str:
    stamp = PP_VERSION
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        cp = os.path.join(here, "client.html")
        if not os.path.isfile(cp):
            cp = os.path.join(os.path.dirname(here), "client", "client.html")
        st = os.stat(cp)
        stamp = f"{PP_VERSION}-{int(st.st_mtime)}-{st.st_size}"
    except Exception:
        pass
    return SW_JS.replace("__STAMP__", stamp)

COMMENTS_FILE = dpath("palace_comments.json")
COMMENTS: list = []
COMMENTS_MAX = 200
WATCHERS: set = set()
RL_COMMENT = RateLimiter(limit=6, window_s=120)

ICON_192_B64 = (
    "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"
    "frQG0SZtlgAAAABJRU5ErkJggg=="
)
ICON_512_B64 = (
    "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"
)

def load_comments():
    global COMMENTS
    try:
        with open(COMMENTS_FILE, encoding="utf-8") as f:
            COMMENTS = json.load(f)[-COMMENTS_MAX:]
    except FileNotFoundError:
        COMMENTS = []
    except Exception as e:
        print("Could not load comments:", e)
        COMMENTS = []

def save_comments():
    try:
        with open(COMMENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(COMMENTS[-COMMENTS_MAX:], f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("Could not save comments:", e)

def presence_snapshot() -> dict:
    users = []

    show_names = not privacy_off("presence_public")
    online = 0
    for u in all_users():
        if u.hidden:
            continue
        online += 1
        if not show_names:
            continue
        users.append({"name": u.base, "role": RANK_NAME.get(u.rank, "user"),
                      "room": u.room.name if u.room else "-"})
    users.sort(key=lambda x: (x["room"], x["name"].lower()))
    rooms = [{"name": r.name, "users": len(r.users), "locked": bool(r.password),
              "persistent": r.persistent}
             for r in ROOMS.values() if not r.hidden]
    return {"online": online, "users": users, "rooms": rooms}

async def push_presence():
    if not WATCHERS:
        return
    snap = {"t": "presence", **presence_snapshot()}
    for w in list(WATCHERS):
        try:
            await send(w, snap)
        except Exception:
            WATCHERS.discard(w)

async def push_comment(comment: dict):
    for w in list(WATCHERS):
        try:
            await send(w, {"t": "comment", "comment": comment})
        except Exception:
            WATCHERS.discard(w)

def add_comment(name: str, text: str) -> dict | None:
    if privacy_off("comments"):
        return None
    name = clean_base_name(name or "Guest", 24)
    text = re.sub(r"\s+", " ", str(text or "")).strip()[:280]
    if not text:
        return None
    c = {"name": name, "text": text, "ts": now_ms()}
    COMMENTS.append(c)
    del COMMENTS[:-COMMENTS_MAX]
    save_comments()
    return c

def html_escape(x) -> str:
    return (str(x).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))

def status_snapshot() -> dict:
    up = max(0, int(time.time() - START_TIME))
    d, r = divmod(up, 86400)
    h, r = divmod(r, 3600)
    m, sec = divmod(r, 60)
    if d:
        uptime = f"{d} d, {h} h {m} min"
    elif h:
        uptime = f"{h} h {m} min"
    else:
        uptime = f"{m} min {sec} s"
    rooms = [r_ for r_ in ROOMS.values() if not r_.hidden]
    return {
        "ok": True,
        "service": CONFIG.get("servername", "Pixplace"),
        "version": PP_VERSION,
        "uptime": uptime,
        "uptime_seconds": up,
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(START_TIME)),
        "online": sum(1 for u in all_users() if not u.hidden),
        "rooms": len(rooms),
        "components": {
            "chat": True,
            "website": True,
            "uploads": os.path.isdir(MEDIA_DIR),
            "login_providers": [OAUTH_PROVIDERS[p]["name"]
                                for p in OAUTH_PROVIDERS if oauth_enabled(p)],
        },
        "privacy": {
            "privacy_mode": bool(CONFIG.get("privacy_mode")),
            "store_ip": not privacy_off("store_ip"),
            "chat_logs": not privacy_off("chat_logs"),
            "comments": not privacy_off("comments"),
            "presence_public": not privacy_off("presence_public"),
            "moderation_mode": CONFIG.get("moderation_mode", "full"),
            "log_retention_days": CONFIG.get("log_retention_days", 7),
        },
    }

def status_page() -> str:
    s = status_snapshot()
    p = s["privacy"]

    def dot(ok, label):
        cls = "up" if ok else "down"
        return (f'<li><span class="dot {cls}"></span>{html_escape(label)}'
                f'<b class="{cls}">{"operational" if ok else "off"}</b></li>')

    prov = s["components"]["login_providers"]
    prov_txt = ", ".join(prov) if prov else "none configured"
    yn = lambda b: "on" if b else "off"
    modes = {"full": "full", "events": "events only", "off": "off"}
    keep = s["privacy"]["log_retention_days"]
    keep_txt = f"{keep} days" if keep else "no automatic deletion"
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"robots\" content=\"noindex\">"
        f"<title>Status – {html_escape(s['service'])}</title>"
        "<style>" + PPS_DOC_CSS + """
.state{display:flex;align-items:center;gap:12px;background:rgba(75,190,131,.10);
  border:1px solid rgba(75,190,131,.34);border-radius:12px;padding:14px 18px;
  margin:0 0 22px}
.state .big{font-size:17px;font-weight:700;color:#7fe0a8}
ul.svc{list-style:none;padding:0;margin:0}
ul.svc li{display:flex;align-items:center;gap:11px;padding:10px 0;
  border-bottom:1px solid var(--line)}
ul.svc li:last-child{border-bottom:0}
ul.svc li b{margin-left:auto;font-size:12.5px;font-weight:600}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.dot.up{background:#4bbe83;box-shadow:0 0 0 3px rgba(75,190,131,.20)}
.dot.down{background:#746a8c;box-shadow:0 0 0 3px rgba(116,106,140,.18)}
b.up{color:#7fe0a8}b.down{color:var(--faint)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:7px 18px;font-size:14px}
.kv div:nth-child(odd){color:var(--dim)}
</style></head><body>
<nav><b>""" + html_escape(s["service"]) + """</b>
<a href="/">Website</a><a href="/app">Chat</a><a href="/status">Status</a></nav>
<main>
<h1>Status</h1>
<div class="state"><span class="dot up"></span>
  <span class="big">All systems operational</span></div>

<h2>Dienste</h2>
<ul class="svc">"""
        + dot(s["components"]["website"], "Website")
        + dot(s["components"]["chat"], "Chat-Server")
        + dot(s["components"]["uploads"], "Image uploads")
        + f'<li><span class="dot up"></span>Sign-in via provider'
          f'<b class="up">{html_escape(prov_txt)}</b></li>'
        + """</ul>

<h2>Betrieb</h2>
<div class="kv">
  <div>Laufzeit</div><div>""" + html_escape(s["uptime"]) + """</div>
  <div>Start</div><div>""" + html_escape(s["started"]) + """</div>
  <div>Version</div><div>""" + html_escape(s["version"]) + """</div>
  <div>Rooms</div><div>""" + str(s["rooms"]) + """</div>
  <div>Gerade online</div><div>""" + str(s["online"]) + """</div>
</div>

<h2>Datenverarbeitung</h2>
<p>What this server records about visitors – and what it does not.</p>
<div class="kv">
  <div>Datensparmodus</div><div>""" + yn(p["privacy_mode"]) + """</div>
  <div>Store IP addresses</div><div>""" + yn(p["store_ip"]) + """</div>
  <div>Chat history on disk</div><div>""" + yn(p["chat_logs"]) + """</div>
  <div>Pinnwand</div><div>""" + yn(p["comments"]) + """</div>
  <div>Show names publicly</div><div>""" + yn(p["presence_public"]) + """</div>
  <div>Moderationsprotokoll</div><div>"""
        + html_escape(modes.get(p["moderation_mode"], p["moderation_mode"])) + """</div>
  <div>Keep logs</div><div>""" + html_escape(keep_txt) + """</div>
</div>
<p class="lead" style="font-size:13px;margin-top:18px">
  Machine-readable at <a href="/api/status">/api/status</a>.</p>
</main></body></html>""")

def admin_base() -> str:
    v = str(CONFIG.get("admin_path") or "admin").strip().strip("/")
    v = "".join(c for c in v if c.isalnum() or c in "-_")
    return v or "admin"

def is_admin_path(path: str) -> bool:
    b = "/" + admin_base()
    return path == b or path.startswith(b + "/")

def test_cookie_value() -> str:
    return hmac.new(("pp-test:" + str(CONFIG.get("test_key", ""))).encode(),
                    b"preview", hashlib.sha256).hexdigest()[:32]

def has_test_pass(headers) -> bool:
    raw = headers.get("cookie", "") or ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "pp_preview" and hmac.compare_digest(v, test_cookie_value()):
            return True
    return False

def maintenance_page() -> bytes:
    name = html_escape(CONFIG.get("servername", "Pixplace"))
    return ("""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>""" + name + """</title>
<style>
:root{--bg:#08070c;--ink:#f1ecfb;--dim:#a89dc0;--accent:#a855f7;--accent-2:#c77dff}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:grid;place-items:center;background:var(--bg);
  color:var(--ink);font:16px/1.7 'Inter',system-ui,Segoe UI,sans-serif;
  text-align:center;padding:24px;position:relative;overflow:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;
  background:radial-gradient(60% 50% at 50% 0%,rgba(124,58,237,.20),transparent 62%),
    radial-gradient(50% 44% at 50% 100%,rgba(168,85,247,.13),transparent 60%),var(--bg)}
.box{max-width:440px}
.sign{font-size:60px;line-height:1;margin-bottom:22px;
  filter:drop-shadow(0 6px 26px rgba(168,85,247,.35))}
h1{font-size:27px;font-weight:750;letter-spacing:-.02em;margin-bottom:12px;
  background:linear-gradient(180deg,#fff 30%,#cdb4f0);
  -webkit-background-clip:text;background-clip:text;color:transparent}
p{color:var(--dim);font-size:15px}
.bar{margin:26px auto 0;width:190px;height:5px;border-radius:99px;
  background:rgba(168,85,247,.16);overflow:hidden}
.bar i{display:block;width:38%;height:100%;border-radius:99px;
  background:linear-gradient(90deg,var(--accent),var(--accent-2));
  animation:s 1.9s ease-in-out infinite}
@keyframes s{0%{transform:translateX(-100%)}100%{transform:translateX(360%)}}
@media(prefers-reduced-motion:reduce){.bar i{animation:none;width:100%}}
</style></head><body><div class="box">
<div class="sign">🚧</div>
<h1>Under construction</h1>
<p>Something is being built here. Please check back later.</p>
<div class="bar"><i></i></div>
</div></body></html>""").encode("utf-8")

_PIXEL_P_SVG = (
    '<svg width="17" height="17" viewBox="0 0 6 7" fill="#fff" shape-rendering="crispEdges"><rect x="0" y="0" width="1" height="1"/><rect x="1" y="0" width="1" height="1"/><rect x="2" y="0" width="1" height="1"/><rect x="3" y="0" width="1" height="1"/><rect x="4" y="0" width="1" height="1"/><rect x="0" y="1" width="1" height="1"/><rect x="1" y="1" width="1" height="1"/><rect x="4" y="1" width="1" height="1"/><rect x="5" y="1" width="1" height="1"/><rect x="0" y="2" width="1" height="1"/><rect x="1" y="2" width="1" height="1"/><rect x="4" y="2" width="1" height="1"/><rect x="5" y="2" width="1" height="1"/><rect x="0" y="3" width="1" height="1"/><rect x="1" y="3" width="1" height="1"/><rect x="2" y="3" width="1" height="1"/><rect x="3" y="3" width="1" height="1"/><rect x="4" y="3" width="1" height="1"/><rect x="0" y="4" width="1" height="1"/><rect x="1" y="4" width="1" height="1"/><rect x="0" y="5" width="1" height="1"/><rect x="1" y="5" width="1" height="1"/><rect x="0" y="6" width="1" height="1"/><rect x="1" y="6" width="1" height="1"/></svg>'
)

def reset_page(token: str) -> bytes:
    name = html_escape(CONFIG.get("servername", "Pixplace"))
    return (r"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Set a new password</title>
<style>
:root{--bg:#08070c;--panel:rgba(23,19,32,.78);--line:rgba(150,110,225,.22);
 --ink:#f1ecfb;--dim:#a89dc0;--faint:#746a8c;--accent:#a855f7;
 --accent-2:#c77dff;--accent-3:#7c3aed}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:grid;place-items:center;background:var(--bg);
 color:var(--ink);font:15px/1.6 'Inter',system-ui,Segoe UI,sans-serif;padding:22px}
body::before{content:"";position:fixed;inset:0;z-index:-1;
 background:radial-gradient(60% 48% at 50% -4%,rgba(124,58,237,.20),transparent 62%),
 radial-gradient(52% 42% at 50% 104%,rgba(168,85,247,.12),transparent 60%),var(--bg)}
.box{width:min(400px,100%);background:var(--panel);border:1px solid var(--line);
 border-radius:18px;padding:28px 26px;backdrop-filter:blur(18px);
 box-shadow:0 18px 60px rgba(0,0,0,.6)}
h1{font-size:19px;font-weight:750;margin-bottom:4px}
.sub{color:var(--faint);font-size:13px;margin-bottom:18px}
label{display:block;font-size:12.5px;color:var(--dim);margin:14px 0 6px;font-weight:550}
input{width:100%;background:rgba(10,8,15,.6);border:1px solid var(--line);
 color:var(--ink);border-radius:11px;padding:12px 13px;font:inherit}
input:focus{outline:none;border-color:rgba(168,85,247,.45);
 box-shadow:0 0 0 3px rgba(168,85,247,.14)}
.meter{height:5px;border-radius:99px;background:rgba(168,85,247,.16);margin-top:8px;
 overflow:hidden}.meter i{display:block;height:100%;width:0;border-radius:99px;
 background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .2s}
.hint{font-size:11.5px;color:var(--faint);margin-top:5px}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:11px;
 font:inherit;font-weight:650;color:#fff;cursor:pointer;
 background:linear-gradient(135deg,var(--accent-3),var(--accent))}
button:disabled{opacity:.5;cursor:default}
.msg{margin-top:14px;font-size:13px;display:none;padding:10px 12px;border-radius:10px}
.err{background:rgba(224,90,74,.14);color:#f0a49c;display:block}
.ok{background:rgba(75,190,131,.14);color:#8fe0b0;display:block}
</style></head><body><div class="box">
<h1>New password</h1>
<div class="sub">""" + name + r"""</div>
<div id="form">
  <label for="p">New password</label>
  <input id="p" type="password" autocomplete="new-password">
  <div class="meter"><i id="mtr"></i></div>
  <div class="hint">At least 8 characters. Longer is much safer.</div>
  <label for="p2">Wiederholen</label>
  <input id="p2" type="password" autocomplete="new-password">
  <button id="go">Save password</button>
</div>
<div class="msg" id="msg"></div>
</div>
<script>
const TOK=""" + json.dumps(token) + r""";
const $=s=>document.querySelector(s);
function show(t,ok){const m=$("#msg");m.textContent=t;m.className="msg "+(ok?"ok":"err");}
function strength(p){let s=0;if(p.length>=8)s++;if(p.length>=12)s++;if(p.length>=16)s++;
  if(/[a-z]/.test(p)&&/[A-Z]/.test(p))s++;if(/\d/.test(p))s++;
  if(/[^\w]/.test(p))s++;return Math.min(s,6);}
$("#p").addEventListener("input",e=>{
  $("#mtr").style.width=(strength(e.target.value)/6*100)+"%";});
$("#go").onclick=async()=>{
  const p=$("#p").value,p2=$("#p2").value;
  if(p.length<8)return show("Mindestens 8 Zeichen.",false);
  if(p!==p2)return show("The two entries do not match.",false);
  $("#go").disabled=true;
  try{
    const r=await fetch("/api/reset",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({token:TOK,password:p})});
    const d=await r.json();
    if(!r.ok||!d.ok){$("#go").disabled=false;
      return show(d.error||"That did not work.",false);}
    $("#form").style.display="none";
    show("Done. You can sign in now.",true);
    setTimeout(()=>location.href="/app",1400);
  }catch(e){$("#go").disabled=false;show("Verbindungsfehler.",false);}
};
["#p","#p2"].forEach(s=>$(s).addEventListener("keydown",
  e=>{if(e.key==="Enter")$("#go").click();}));
</script></body></html>""").encode("utf-8")

def invite_page(code: str) -> bytes:
    name = html_escape(CONFIG.get("servername", "Pixplace"))
    c = html_escape(code)
    return (r"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Invitation – """ + name + """</title>
<style>
:root{--bg:#08070c;--panel:rgba(23,19,32,.78);--line:rgba(150,110,225,.22);
 --ink:#f1ecfb;--dim:#a89dc0;--faint:#746a8c;--accent:#a855f7;
 --accent-2:#c77dff;--accent-3:#7c3aed}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:grid;place-items:center;background:var(--bg);
 color:var(--ink);font:15px/1.6 'Inter',system-ui,Segoe UI,sans-serif;padding:22px}
body::before{content:"";position:fixed;inset:0;z-index:-1;
 background:radial-gradient(60% 48% at 50% -4%,rgba(124,58,237,.20),transparent 62%),
 radial-gradient(52% 42% at 50% 104%,rgba(168,85,247,.12),transparent 60%),var(--bg)}
.box{width:min(420px,100%);background:var(--panel);border:1px solid var(--line);
 border-radius:18px;padding:28px 26px;backdrop-filter:blur(18px);
 -webkit-backdrop-filter:blur(18px);box-shadow:0 18px 60px rgba(0,0,0,.6)}
h1{font-size:19px;font-weight:750;letter-spacing:-.02em;margin-bottom:4px}
.sub{color:var(--faint);font-size:13px;margin-bottom:20px}
label{display:block;font-size:12.5px;color:var(--dim);margin:14px 0 6px;font-weight:550}
input{width:100%;background:rgba(10,8,15,.6);border:1px solid var(--line);
 color:var(--ink);border-radius:11px;padding:12px 13px;font:inherit}
input:focus{outline:none;border-color:rgba(168,85,247,.45);
 box-shadow:0 0 0 3px rgba(168,85,247,.14)}
.hint{font-size:11.5px;color:var(--faint);margin-top:5px}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:11px;
 font:inherit;font-weight:650;color:#fff;cursor:pointer;
 background:linear-gradient(135deg,var(--accent-3),var(--accent))}
button:disabled{opacity:.5;cursor:default}
.msg{margin-top:14px;font-size:13px;display:none;padding:10px 12px;border-radius:10px}
.err{background:rgba(224,90,74,.14);color:#f0a49c;display:block}
.ok{background:rgba(75,190,131,.14);color:#8fe0b0;display:block}
.meter{height:5px;border-radius:99px;background:rgba(168,85,247,.16);margin-top:8px;
 overflow:hidden}.meter i{display:block;height:100%;width:0;border-radius:99px;
 background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .2s}
code{background:rgba(10,8,15,.6);padding:2px 6px;border-radius:6px;font-size:12px}
</style></head><body><div class="box" id="box">
<h1>Welcome to """ + name + """</h1>
<div class="sub" id="sub">Choose your name and password.</div>
<div id="form">
  <label for="u">Name</label>
  <input id="u" maxlength="22" autocapitalize="none" spellcheck="false"
         autocomplete="username">
  <div class="hint">This is how others see you in the chat. Can be changed later.</div>
  <label for="e">E-mail address</label>
  <input id="e" type="email" autocomplete="email" inputmode="email">
  <div class="hint">Only for "Forgot password". You can also use it to
    sign in later.</div>
  <label for="p">Password</label>
  <input id="p" type="password" autocomplete="new-password">
  <div class="meter"><i id="mtr"></i></div>
  <div class="hint">At least 8 characters. Longer is much safer.</div>
  <label for="p2">Repeat password</label>
  <input id="p2" type="password" autocomplete="new-password">
  <button id="go">Create account</button>
</div>
<div class="msg" id="msg"></div>
</div>
<script>
const CODE=""" + json.dumps(code) + r""";
const $=s=>document.querySelector(s);
function show(t,ok){const m=$("#msg");m.textContent=t;m.className="msg "+(ok?"ok":"err");}
function strength(p){
  let s=0;if(p.length>=8)s++;if(p.length>=12)s++;if(p.length>=16)s++;
  if(/[a-z]/.test(p)&&/[A-Z]/.test(p))s++;if(/\d/.test(p))s++;
  if(/[^\w]/.test(p))s++;return Math.min(s,6);}
$("#p").addEventListener("input",e=>{
  $("#mtr").style.width=(strength(e.target.value)/6*100)+"%";});
fetch("/api/invite/check",{method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({code:CODE})}).then(r=>r.json()).then(d=>{
    if(!d.ok){$("#form").style.display="none";
      $("#sub").textContent="";
      show("This invitation is no longer valid. Please contact the person who sent it to you.",false);}
    else if(d.note){$("#sub").textContent=d.note;}
  }).catch(()=>{});
$("#go").onclick=async()=>{
  const u=$("#u").value.trim(),p=$("#p").value,p2=$("#p2").value;
  const e=$("#e").value.trim();
  if(u.length<2)return show("Please enter a name with at least 2 characters.",false);
  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e))
    return show("Please enter a valid e-mail address.",false);
  if(p.length<8)return show("The password needs at least 8 characters.",false);
  if(p!==p2)return show("The two passwords do not match.",false);
  $("#go").disabled=true;show("Creating account …",true);
  try{
    const r=await fetch("/api/invite/redeem",{method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({code:CODE,username:u,password:p,email:e})});
    const d=await r.json();
    if(!r.ok||!d.ok){$("#go").disabled=false;
      return show(d.error||"That did not work.",false);}
    try{localStorage.setItem("pp_membername",d.username);
        localStorage.setItem("pp_token",d.token);}catch(e){}
    $("#form").style.display="none";
    show("Done! You are being redirected to the chat …",true);
    setTimeout(()=>location.href="/app",900);
  }catch(e){$("#go").disabled=false;show("Verbindungsfehler.",false);}
};
["#u","#e","#p","#p2"].forEach(s=>$(s).addEventListener("keydown",
  e=>{if(e.key==="Enter")$("#go").click();}));
</script></body></html>""").encode("utf-8")

def private_landing() -> bytes:
    name = html_escape(CONFIG.get("servername", "Pixplace"))
    return ("""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>""" + name + """</title>
<style>
:root{--bg:#08070c;--panel:rgba(23,19,32,.76);--line:rgba(150,110,225,.20);
  --ink:#f1ecfb;--dim:#a89dc0;--faint:#746a8c;--accent:#a855f7;--accent-2:#c77dff;
  --accent-3:#7c3aed}
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:grid;place-items:center;background:var(--bg);
  color:var(--ink);font:15px/1.6 'Inter',system-ui,Segoe UI,sans-serif;padding:24px}
body::before{content:"";position:fixed;inset:0;z-index:-1;
  background:radial-gradient(60% 48% at 50% -4%,rgba(124,58,237,.20),transparent 62%),
    radial-gradient(52% 42% at 50% 104%,rgba(168,85,247,.12),transparent 60%),var(--bg)}
.box{width:min(370px,100%);background:var(--panel);border:1px solid var(--line);
  border-radius:18px;padding:30px 26px;backdrop-filter:blur(18px);
  -webkit-backdrop-filter:blur(18px);box-shadow:0 18px 60px rgba(0,0,0,.6)}
.mark{display:flex;align-items:center;justify-content:center;gap:10px;
  margin-bottom:6px}
.mark .sq{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;
  background:linear-gradient(140deg,var(--accent-3),var(--accent) 60%,var(--accent-2));
  box-shadow:0 0 20px rgba(168,85,247,.30)}
.mark b{font-size:19px;font-weight:750;letter-spacing:-.02em}
.sub{text-align:center;color:var(--faint);font-size:12.5px;margin-bottom:24px}
label{display:block;font-size:12.5px;color:var(--dim);margin:14px 0 6px;
  font-weight:550}
input{width:100%;background:rgba(10,8,15,.6);border:1px solid var(--line);
  color:var(--ink);border-radius:11px;padding:12px 13px;font:inherit;
  transition:border-color .2s,box-shadow .2s}
input:focus{outline:none;border-color:rgba(168,85,247,.45);
  box-shadow:0 0 0 3px rgba(168,85,247,.14)}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:11px;
  font:inherit;font-weight:650;color:#fff;cursor:pointer;
  background:linear-gradient(135deg,var(--accent-3),var(--accent));
  box-shadow:0 6px 20px rgba(124,58,237,.32);transition:transform .2s,box-shadow .25s}
button:hover{transform:translateY(-1px);box-shadow:0 10px 28px rgba(168,85,247,.44)}
.note{margin-top:18px;text-align:center;color:var(--faint);font-size:12px;
  line-height:1.6}
.err{margin-top:14px;text-align:center;font-size:12.5px;color:#f0a49c;display:none}
</style></head><body>
<div class="box">
  <div class="mark"><span class="sq">""" + _PIXEL_P_SVG + """</span><b>"""
        + name + """</b></div>
  <div class="sub">Access by invitation only</div>
  <label for="u">Username</label>
  <input id="u" autocomplete="username" autocapitalize="none" spellcheck="false">
  <label for="t">Password</label>
  <input id="t" type="password" autocomplete="current-password">
  <div id="otpbox" style="display:none">
    <label for="otp">Code from your authenticator app</label>
    <input id="otp" inputmode="numeric" maxlength="10" autocomplete="one-time-code">
  </div>
  <button id="go">Sign in</button>
  <div class="err" id="err">Access not recognised.</div>
  <p class="note">No access? Access is handed out personally.</p>
</div>
<script>
const $=s=>document.querySelector(s);
function fail(t){const e=$("#err");e.textContent=t;e.style.display="block";}
async function go(){
  const u=$("#u").value.trim(), t=$("#t").value;
  if(!u||!t)return fail("Please enter name and password.");
  $("#go").disabled=true;$("#err").style.display="none";
  const body={login:u,password:t};
  const otpEl=$("#otp");
  if(otpEl&&otpEl.value.trim())body.otp=otpEl.value.trim();
  try{
    const r=await fetch("/api/login",{method:"POST",
      headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.otpRequired){
      // Second factor: show the field instead of redirecting
      $("#otpbox").style.display="";$("#go").disabled=false;
      if(d.error)fail(d.error);else $("#otp").focus();
      return;
    }
    if(!r.ok||!d.ok){$("#go").disabled=false;
      return fail(d.error||"Sign-in failed.");}
    try{localStorage.setItem("pp_membername",d.username);
        localStorage.setItem("pp_token",d.token);}catch(e){}
    location.href="/app";
  }catch(e){$("#go").disabled=false;fail("Verbindungsfehler.");}
}
$("#go").onclick=go;
for(const id of ["#u","#t","#otp"])
  {const el=$(id);if(el)el.addEventListener("keydown",
     e=>{if(e.key==="Enter")go();});}
</script>
</body></html>""").encode("utf-8")

async def handle_portal_http(writer, method, target, headers, body, client_ip):
    path = target.split("?")[0]

    async def json_resp(status, obj):
        return await http_respond(writer, status, json.dumps(obj, ensure_ascii=False),
                                  "application/json")

    if method == "GET" and path == "/manifest.json":
        return await http_respond(writer, "200 OK", MANIFEST_JSON,
                                  "application/manifest+json")
    if method == "GET" and path == "/sw.js":
        return await http_respond(writer, "200 OK", sw_js(),
                                  "text/javascript; charset=utf-8",
                                  extra={"Service-Worker-Allowed": "/",
                                         "Cache-Control": "no-cache"})
    if method == "GET" and path in ("/icon-192.png", "/icon-512.png"):
        raw = base64.b64decode(ICON_192_B64 if "192" in path else ICON_512_B64)
        return await http_respond(writer, "200 OK", raw, "image/png",
                                  extra={"Cache-Control": "public, max-age=604800"})
    if method == "GET" and path == "/api/status":
        return await json_resp("200 OK", status_snapshot())
    if method == "GET" and path == "/status":
        return await http_respond(writer, "200 OK",
                                  status_page().encode("utf-8"),
                                  "text/html; charset=utf-8")
    if method == "GET" and path == "/api/online":
        return await json_resp("200 OK", presence_snapshot())
    if method == "GET" and path == "/api/comments":
        return await json_resp("200 OK", {"comments": COMMENTS[-100:]})
    if method == "POST" and path == "/api/comments":
        if not RL_COMMENT.allow(client_ip):
            return await json_resp("429 Too Many Requests",
                                   {"error": "Too many comments. Please wait a moment."})
        try:
            d = json.loads(body or b"{}")
        except Exception:
            d = {}
        if privacy_off("comments"):
            return await json_resp("403 Forbidden",
                                   {"error": "The comment board is switched off."})
        c = add_comment(d.get("name", ""), d.get("text", ""))
        if not c:
            return await json_resp("400 Bad Request", {"error": "Leerer Kommentar"})
        await push_comment(c)
        return await json_resp("200 OK", {"comment": c})
    return None

async def log_purge_ticker():
    while True:
        try:
            n = purge_old_logs()
            if n:
                print(f"[i] {n} old log file(s) deleted "
                      f"(older than {CONFIG.get('log_retention_days')} days)")
            await asyncio.sleep(6 * 3600)
        except asyncio.CancelledError:
            return
        except Exception as e:
            print("Log cleanup:", e)
            await asyncio.sleep(3600)

async def clan_points_ticker():
    while True:
        try:
            await asyncio.sleep(60)
            seen = set()
            for u in all_users():
                if u.observer or u.base.lower() in seen:
                    continue
                seen.add(u.base.lower())

                add_clan_points(u.base, 1, minutes=1)

                set_user_points(u, user_points(u) + 1)
                try:
                    await send(u, {"t": "points", "points": user_points(u)})
                except Exception:
                    pass
        except asyncio.CancelledError:
            return
        except Exception as e:
            print("Points ticker:", e)

async def main(host, port, tls_cert=None, tls_key=None):
    load_config()
    default_rooms()
    loop = asyncio.get_running_loop()
    SERVER["stop"] = loop.create_future()
    asyncio.ensure_future(clan_points_ticker())
    asyncio.ensure_future(log_purge_ticker())
    ssl_ctx = None
    if tls_cert and tls_key:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(tls_cert, tls_key)
    server = await asyncio.start_server(on_connection, host, port, ssl=ssl_ctx)
    shown = host if host != "0.0.0.0" else "<your-ip>"
    scheme = "https" if ssl_ctx else "http"
    wscheme = "wss" if ssl_ctx else "ws"
    print("=" * 64)
    print(f"  {CONFIG['servername']} v{PP_VERSION} — server on  {host}:{port}"
          f"  ({'TLS/encrypted' if ssl_ctx else 'unencrypted'})")
    print(f"  {wscheme}:// chat + {scheme}:// image hosting on the same port.")
    print(f"  Rooms: {', '.join(ROOMS)}")

    if NEW_SECRETS:
        print()
        print("  " + "-" * 58)
        print("  ONE-TIME CREDENTIALS – note them now, they will never")
        print("  appear here again:")
        if NEW_SECRETS.get("owner"):
            print(f"      Owner password : {NEW_SECRETS['owner']}")
        if NEW_SECRETS.get("wizard"):
            print(f"      Wizard password: {NEW_SECRETS['wizard']}")
        print("  Temporary – please change after the first sign-in.")
        print("  " + "-" * 58)
        NEW_SECRETS.clear()
    if not CONFIG.get("wizard_pass"):
        print("  Wizards are appointed by name: admin page -> \"Roles\"")
        print("  or invitation with rank \"Wizard\". A shared password")
        print("  deliberately no longer exists.")
    if CONFIG.get("private_mode") and not CONFIG.get("test_mode"):
        print()
        print("  🔒 CLOSED CIRCLE – the start page shows only a")
        print("     login form. No public pages, no")
        print("     self-registration. You hand out access on the")
        print("     admin page under \"Member accounts\".")
    if CONFIG.get("test_mode"):
        print()
        print("  🚧 TEST MODE is on – outsiders see only a")
        print("     construction page. To unlock, open this link once")
        print("     in the browser (valid for 30 days afterwards):")
        _pub = ((CONFIG.get("oauth") or {}).get("public_url") or "").rstrip("/")
        _base = _pub or f"{scheme}://{shown}:{port}"
        print(f"       {_base}/preview/{CONFIG.get('test_key','')}")
        print("     Switch it later on the admin page.")
    else:
        temp = []
        if CONFIG.get("owner_pass_temp"):
            temp.append("Owner")
        if CONFIG.get("wizard_pass") and CONFIG.get("wizard_pass_temp"):
            temp.append("Wizard")
        if temp:
            print(f"  ⚠ {' and '.join(temp)} password is still the temporary one "
                  f"– please change it.")
    print(f"  Moderation log: "
          f"{'ON' if CONFIG['moderation_logging'] else 'OFF'}  →  ./{MOD_DIR}/")
    print(f"  Rate limits active: connections, chat flood, uploads, admin login.")

    pub = ((CONFIG.get("oauth") or {}).get("public_url") or "").rstrip("/")
    if pub:
        print(f"  Public:   {pub}/   (via the reverse proxy)")
        print(f"               {pub}/app   ·   {pub}/admin")
        print(f"  Internal: {scheme}://{shown}:{port}/  (on the server only)")
    print(f"  Portal:      {scheme}://{shown}:{port}/       (PWA, installable)")
    print(f"  Chat app: {scheme}://{shown}:{port}/app")
    print(f"  Admin:    {scheme}://{shown}:{port}/admin   (owner password)")
    if not ssl_ctx:
        print("  ⚠ Without TLS: for public operation put a reverse proxy (Caddy/nginx)")
        print("     in front or pass --tls-cert/--tls-key. See the guide.")
    print("=" * 64)
    async with server:
        await SERVER["stop"]
    print("Server beendet.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9998)
    ap.add_argument("--owner-pass", default=None)
    ap.add_argument("--wizard-pass", default=None)
    ap.add_argument("--tls-cert", default=None,
                    help="Path to the TLS certificate (fullchain.pem) for wss/https")
    ap.add_argument("--tls-key", default=None,
                    help="Path to the TLS key (privkey.pem)")
    a = ap.parse_args()
    load_config()
    if a.owner_pass:
        CONFIG["owner_pass"] = a.owner_pass; save_config()
    if a.wizard_pass:
        CONFIG["wizard_pass"] = a.wizard_pass; save_config()
    try:
        asyncio.run(main(a.host, a.port, a.tls_cert, a.tls_key))
    except KeyboardInterrupt:
        print("\nAbbruch.")
