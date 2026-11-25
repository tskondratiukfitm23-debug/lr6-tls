"""Shared application protocol helpers (used by server, client and tests).

Wire format: one JSON object per line (UTF-8, '\n' terminated) inside the TLS channel.
Application-level integrity: HMAC-SHA256 over the canonical JSON of the message
(all fields except "hmac"), keyed with the per-session key issued by the server
after successful authentication.
"""
import hashlib
import hmac
import json
from typing import Any, Dict

PROTOCOL_VERSION = "lr6/1"
MAX_LINE = 4 * 1024 * 1024          # 4 MiB per JSON line
MAX_FILE_BYTES = 1 * 1024 * 1024    # 1 MiB per uploaded file

# Application response codes (HTTP-like, documented in docs/REPORT.md)
CODES = {
    200: "ok",
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    409: "replay_detected",
    413: "payload_too_large",
    419: "token_expired",
    422: "integrity_error",
    423: "account_locked",
    500: "server_error",
}


def canonical(obj: Dict[str, Any]) -> bytes:
    """Deterministic serialisation used as HMAC input (the 'hmac' field is excluded)."""
    body = {k: v for k, v in obj.items() if k != "hmac"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(obj: Dict[str, Any], key: bytes) -> Dict[str, Any]:
    out = dict(obj)
    out["hmac"] = hmac.new(key, canonical(out), hashlib.sha256).hexdigest()
    return out


def verify(obj: Dict[str, Any], key: bytes) -> bool:
    tag = obj.get("hmac")
    if not isinstance(tag, str):
        return False
    expected = hmac.new(key, canonical(obj), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, tag)


def encode(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
