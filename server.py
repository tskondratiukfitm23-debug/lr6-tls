"""LR6 — secure TLS client/server: server part.

Features
  * TLS 1.2+/1.3 (optional TLS 1.3 only), ECDHE + AEAD cipher suites only, no compression/renegotiation
  * optional mutual TLS (client certificate signed by the local CA)
  * login/password authentication against bcrypt hashes (users.json)
  * brute-force protection: per-account and per-IP failure counters with temporary lockout
  * session token with TTL + per-session HMAC key, sequence numbers against replay
  * role-based access control (user / admin)
  * structured JSON logging with secret masking and log rotation
  * TLS handshake failures (untrusted certificate, plain TCP, missing client cert) are logged too
"""
import argparse
import asyncio
import base64
import binascii
import collections
import json
import logging
import logging.handlers
import os
import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional

import bcrypt

import protocol as P

# --------------------------------------------------------------------------- logging

SECRET_FIELDS = {"password", "session_key", "hmac", "data_b64"}
TOKEN_FIELDS = {"token"}


def mask(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Never write secrets to the log: passwords/keys are replaced, tokens are truncated."""
    out = {}
    for k, v in fields.items():
        if k in SECRET_FIELDS:
            out[k] = "***"
        elif k in TOKEN_FIELDS and isinstance(v, str):
            out[k] = v[:6] + "…" if v else ""
        else:
            out[k] = v
    return out


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, timezone.utc)
        rec = {
            "ts": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        rec.update(mask(getattr(record, "fields", {})))
        return json.dumps(rec, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        f = mask(getattr(record, "fields", {}))
        brief = " ".join(f"{k}={v}" for k, v in f.items() if k not in ("cipher",))
        return f"{time.strftime('%H:%M:%S')} {record.levelname:<7} {record.getMessage():<22} {brief}"


LOG = logging.getLogger("lr6.server")


def setup_logging(log_dir: str, max_bytes: int, backups: int) -> str:
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, "server.jsonl")
    LOG.setLevel(logging.INFO)
    LOG.handlers.clear()
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
    fh.setFormatter(JsonFormatter())
    ch = logging.StreamHandler()
    ch.setFormatter(ConsoleFormatter())
    LOG.addHandler(fh)
    LOG.addHandler(ch)
    LOG.propagate = False
    return path


def log(event: str, level: int = logging.INFO, **fields):
    LOG.log(level, event, extra={"fields": fields})


# --------------------------------------------------------------------------- state

ROLE_PERMISSIONS = {
    "user": {"echo", "file", "whoami", "logout"},
    "admin": {"echo", "file", "whoami", "logout", "stats"},
}


@dataclass
class Session:
    user: str
    role: str
    key: bytes
    expires: float
    conn_id: str
    last_seq: int = 0


@dataclass
class Config:
    token_ttl: int = 300
    max_fails: int = 5
    fail_window: int = 300
    lock_seconds: int = 120
    upload_dir: str = "uploads"


@dataclass
class ServerState:
    users: Dict[str, Dict[str, str]]
    cfg: Config
    sessions: Dict[str, Session] = field(default_factory=dict)
    fails_user: Dict[str, Deque[float]] = field(default_factory=lambda: collections.defaultdict(collections.deque))
    fails_ip: Dict[str, Deque[float]] = field(default_factory=lambda: collections.defaultdict(collections.deque))
    locked_until: Dict[str, float] = field(default_factory=dict)
    counters: collections.Counter = field(default_factory=collections.Counter)
    started: float = field(default_factory=time.time)

    # ---- brute-force protection
    def _prune(self, dq: Deque[float], now: float):
        while dq and now - dq[0] > self.cfg.fail_window:
            dq.popleft()

    def lock_key_active(self, key: str, now: float) -> float:
        until = self.locked_until.get(key, 0)
        return until - now if until > now else 0

    def register_fail(self, user: str, ip: str, now: float) -> Optional[str]:
        """Returns the key that became locked (user:<name> / ip:<addr>) or None."""
        for key, dq in ((f"user:{user}", self.fails_user[user]), (f"ip:{ip}", self.fails_ip[ip])):
            dq.append(now)
            self._prune(dq, now)
            limit = self.cfg.max_fails if key.startswith("user:") else self.cfg.max_fails * 3
            if len(dq) >= limit and not self.lock_key_active(key, now):
                self.locked_until[key] = now + self.cfg.lock_seconds
                dq.clear()
                return key
        return None

    def reset_fails(self, user: str):
        self.fails_user.pop(user, None)

    def purge_sessions(self, now: float):
        for tok in [t for t, s in self.sessions.items() if s.expires <= now]:
            self.sessions.pop(tok, None)


STATE: ServerState  # initialised in main()/run_server()
SSL_CTX: ssl.SSLContext
DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=12))


# --------------------------------------------------------------------------- TLS

def make_ssl_context(cert: str, key: str, ca: Optional[str], require_client_cert: bool,
                     tls13_only: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3 if tls13_only else ssl.TLSVersion.TLSv1_2
    # TLS 1.2: forward secrecy (ECDHE) + AEAD only. TLS 1.3 suites are AEAD by design.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!SHA1:!RSA")
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        ctx.options |= ssl.OP_NO_RENEGOTIATION
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    if ca:
        ctx.load_verify_locations(cafile=ca)
    if require_client_cert:
        if not ca:
            raise SystemExit("--require-client-cert needs --ca")
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def tls_error_reason(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLError):
        return getattr(exc, "reason", None) or exc.__class__.__name__
    if isinstance(exc, asyncio.TimeoutError):
        return "HANDSHAKE_TIMEOUT"
    return exc.__class__.__name__


def cert_cn(cert: Optional[dict]) -> Optional[str]:
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return None


# --------------------------------------------------------------------------- request handling

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


def response(code: int, seq: Optional[int] = None, **data) -> Dict[str, Any]:
    r = {"ok": code == 200, "code": code, "status": P.CODES.get(code, "error")}
    if seq is not None:
        r["seq"] = seq
    r.update(data)
    return r


async def authenticate(msg: Dict[str, Any], ip: str, ctx: Dict[str, Any]):
    """Returns (response_dict, session_token_or_None)."""
    now = time.time()
    user = str(msg.get("username", ""))[:64]
    pwd = str(msg.get("password", ""))
    base = dict(ctx, user=user)

    for key in (f"user:{user}", f"ip:{ip}"):
        left = STATE.lock_key_active(key, now)
        if left:
            STATE.counters["auth_locked"] += 1
            log("auth.locked", logging.WARNING, **base, code=423, lock_key=key, retry_after=round(left))
            return response(423, err="account temporarily locked", retry_after=round(left)), None

    rec = STATE.users.get(user)
    stored = rec["hash"].encode() if rec else DUMMY_HASH          # constant-ish time for unknown users
    ok = await asyncio.to_thread(bcrypt.checkpw, pwd.encode("utf-8"), stored)
    if not (rec and ok):
        STATE.counters["auth_fail"] += 1
        locked = STATE.register_fail(user, ip, now)
        log("auth.fail", logging.WARNING, **base, code=401,
            reason="unknown_user" if not rec else "bad_password")
        if locked:
            log("auth.lockout", logging.ERROR, **base, code=423, lock_key=locked,
                lock_seconds=STATE.cfg.lock_seconds)
        return response(401, err="invalid credentials"), None

    STATE.reset_fails(user)
    token = secrets.token_urlsafe(32)
    key = secrets.token_bytes(32)
    STATE.sessions[token] = Session(user=user, role=rec.get("role", "user"), key=key,
                                    expires=now + STATE.cfg.token_ttl, conn_id=ctx["conn_id"])
    STATE.counters["auth_ok"] += 1
    log("auth.ok", **base, role=rec.get("role", "user"), code=200, token=token, ttl=STATE.cfg.token_ttl)
    return response(200, token=token, session_key=key.hex(), role=rec.get("role", "user"),
                    expires_in=STATE.cfg.token_ttl, tls=ctx.get("tls")), token


def handle_op(op: str, sess: Session, msg: Dict[str, Any], seq: int, ctx: Dict[str, Any]) -> Dict[str, Any]:
    if op == "echo":
        text = str(msg.get("message", ""))
        log("data.ok", **ctx, user=sess.user, op=op, code=200, bytes=len(text.encode()),
            sha256=P.sha256_hex(text.encode()))
        return response(200, seq, echo=text, sha256=P.sha256_hex(text.encode()))

    if op == "file":
        name = SAFE_NAME.sub("_", os.path.basename(str(msg.get("name", "upload.bin"))))[:100] or "upload.bin"
        try:
            data = base64.b64decode(str(msg.get("data_b64", "")), validate=True)
        except (binascii.Error, ValueError):
            log("data.bad_request", logging.WARNING, **ctx, user=sess.user, op=op, code=400, reason="bad_base64")
            return response(400, seq, err="bad base64")
        if len(data) > P.MAX_FILE_BYTES:
            log("data.too_large", logging.WARNING, **ctx, user=sess.user, op=op, code=413, bytes=len(data))
            return response(413, seq, err="file too large")
        digest = P.sha256_hex(data)
        if digest != str(msg.get("sha256", "")).lower():
            log("integrity.digest_mismatch", logging.WARNING, **ctx, user=sess.user, op=op, code=422, file=name)
            return response(422, seq, err="sha256 mismatch")
        udir = os.path.join(STATE.cfg.upload_dir, sess.user)
        os.makedirs(udir, exist_ok=True)
        with open(os.path.join(udir, name), "wb") as f:
            f.write(data)
        log("file.ok", **ctx, user=sess.user, op=op, code=200, file=name, bytes=len(data), sha256=digest)
        return response(200, seq, stored=name, bytes=len(data), sha256=digest)

    if op == "whoami":
        log("data.ok", **ctx, user=sess.user, op=op, code=200)
        return response(200, seq, user=sess.user, role=sess.role,
                        expires_in=round(sess.expires - time.time()))

    if op == "stats":
        log("admin.stats", **ctx, user=sess.user, op=op, code=200)
        return response(200, seq, uptime_s=round(time.time() - STATE.started),
                        active_sessions=len(STATE.sessions), counters=dict(STATE.counters),
                        locked=[k for k, v in STATE.locked_until.items() if v > time.time()])
    return response(400, seq, err="unsupported op")


async def serve_connection(conn: socket.socket, addr) -> None:
    """Performs the TLS handshake on an accepted TCP socket so that failures can be logged."""
    loop = asyncio.get_running_loop()
    ip, port = str(addr[0]), addr[1]
    ctx: Dict[str, Any] = {"conn_id": secrets.token_hex(4), "peer": f"{ip}:{port}"}
    STATE.counters["connections"] += 1
    log("conn.open", **ctx)
    reader = asyncio.StreamReader(limit=P.MAX_LINE)
    protocol = asyncio.StreamReaderProtocol(reader)
    try:
        transport, _ = await loop.connect_accepted_socket(lambda: protocol, conn, ssl=SSL_CTX,
                                                          ssl_handshake_timeout=10)
    except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError) as exc:
        STATE.counters["tls_fail"] += 1
        log("tls.handshake_fail", logging.WARNING, **ctx, code=495, reason=tls_error_reason(exc),
            err=str(exc)[:200])
        conn.close()
        log("conn.closed", **ctx)
        return
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    await handle(reader, writer, ctx, ip)


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ctx: Dict[str, Any], ip: str):
    sslobj: ssl.SSLObject = writer.get_extra_info("ssl_object")
    name, proto, bits = sslobj.cipher()
    peer_cert = sslobj.getpeercert()
    ctx["tls"] = {"version": sslobj.version(), "cipher": name, "bits": bits}
    STATE.counters["tls_ok"] += 1
    log("tls.handshake_ok", **ctx, client_cert_cn=cert_cn(peer_cert))

    async def send(obj: Dict[str, Any], key: Optional[bytes] = None):
        writer.write(P.encode(P.sign(obj, key) if key else obj))
        await writer.drain()

    tokens_issued = []
    try:
        # ---- 2. AUTH (first message must be auth; up to 3 attempts per connection)
        session_token = None
        for _ in range(3):
            line = await asyncio.wait_for(reader.readline(), timeout=60)
            if not line:
                break
            try:
                msg = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                await send(response(400, err="bad json"))
                log("proto.bad_json", logging.WARNING, **ctx, code=400)
                continue
            if msg.get("op") == "quit":
                await send(response(200, bye=True))
                break
            if msg.get("op") != "auth":
                await send(response(401, err="authenticate first"))
                log("acl.unauthenticated", logging.WARNING, **ctx, code=401, op=str(msg.get("op")))
                continue
            resp, session_token = await authenticate(msg, ip, ctx)
            await send(resp)
            if session_token or resp["code"] == 423:
                break
        if not session_token:
            return
        tokens_issued.append(session_token)

        # ---- 3. Authenticated requests, each signed with the session HMAC key
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=300)
            if not line:
                break
            try:
                msg = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                await send(response(400, err="bad json"))
                log("proto.bad_json", logging.WARNING, **ctx, code=400)
                continue
            op = str(msg.get("op", ""))
            if op == "quit":
                await send(response(200, bye=True))
                break

            now = time.time()
            token = str(msg.get("token", ""))
            sess = STATE.sessions.get(token)
            if sess is None:
                log("token.invalid", logging.WARNING, **ctx, op=op, code=401, token=token)
                await send(response(401, err="invalid token"))
                continue
            if sess.expires <= now:
                STATE.sessions.pop(token, None)
                log("token.expired", logging.WARNING, **ctx, user=sess.user, op=op, code=419, token=token)
                await send(response(419, err="token expired, re-authenticate"))
                continue
            if not P.verify(msg, sess.key):
                log("integrity.bad_hmac", logging.WARNING, **ctx, user=sess.user, op=op, code=422)
                await send(response(422, err="bad hmac"))
                continue
            seq = msg.get("seq")
            if not isinstance(seq, int) or seq <= sess.last_seq:
                log("integrity.replay", logging.WARNING, **ctx, user=sess.user, op=op, code=409,
                    seq=seq, last_seq=sess.last_seq)
                await send(response(409, err="replayed or out-of-order message"), sess.key)
                continue
            sess.last_seq = seq
            if op not in ROLE_PERMISSIONS.get(sess.role, set()):
                log("acl.denied", logging.WARNING, **ctx, user=sess.user, role=sess.role, op=op, code=403)
                await send(response(403, seq, err=f"role '{sess.role}' may not '{op}'"), sess.key)
                continue
            if op == "logout":
                STATE.sessions.pop(token, None)
                log("auth.logout", **ctx, user=sess.user, code=200, token=token)
                await send(response(200, seq, logged_out=True), sess.key)
                continue
            await send(handle_op(op, sess, msg, seq, ctx), sess.key)
    except asyncio.TimeoutError:
        log("conn.idle_timeout", logging.WARNING, **ctx)
    except (ConnectionError, ssl.SSLError, OSError) as exc:
        log("conn.error", logging.WARNING, **ctx, err=str(exc)[:200])
    except Exception as exc:  # noqa: BLE001 — never crash the server on one client
        log("conn.error", logging.ERROR, **ctx, err=repr(exc)[:200])
    finally:
        STATE.purge_sessions(time.time())
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:  # noqa: BLE001
            pass
        log("conn.closed", **ctx)


# --------------------------------------------------------------------------- entry point

def load_users(path: str) -> Dict[str, Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        users = json.load(f)
    for name, rec in users.items():
        if not isinstance(rec, dict) or not str(rec.get("hash", "")).startswith("$2"):
            raise SystemExit(f"users file: bad record for '{name}' (use scripts/add_user.py)")
    return users


async def run_server(args) -> None:
    global STATE, SSL_CTX
    log_path = setup_logging(args.log_dir, args.log_max_bytes, args.log_backups)
    SSL_CTX = make_ssl_context(args.cert, args.key, args.ca, args.require_client_cert, args.tls13_only)
    STATE = ServerState(users=load_users(args.users),
                        cfg=Config(token_ttl=args.token_ttl, max_fails=args.max_fails,
                                   fail_window=args.fail_window, lock_seconds=args.lock_seconds,
                                   upload_dir=args.upload_dir))
    lsock = socket.create_server((args.host, args.port), reuse_port=False, backlog=128)
    lsock.setblocking(False)
    addr = str(lsock.getsockname())
    log("server.start", addr=addr, mtls=args.require_client_cert,
        min_tls="TLSv1.3" if args.tls13_only else "TLSv1.2", users=len(STATE.users),
        token_ttl=args.token_ttl, max_fails=args.max_fails, lock_seconds=args.lock_seconds, log=log_path)
    print(f"TLS server listening on {addr}  (Ctrl+C to stop)", flush=True)
    loop = asyncio.get_running_loop()
    tasks = set()
    with lsock:
        while True:
            conn, peer = await loop.sock_accept(lsock)
            conn.setblocking(False)
            t = asyncio.create_task(serve_connection(conn, peer))
            tasks.add(t)
            t.add_done_callback(tasks.discard)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="LR6 TLS server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", default="certs/server.crt")
    ap.add_argument("--key", default="certs/server.key")
    ap.add_argument("--ca", default="certs/ca.crt", help="CA used to verify client certificates (mTLS)")
    ap.add_argument("--require-client-cert", action="store_true", help="enable mutual TLS")
    ap.add_argument("--tls13-only", action="store_true")
    ap.add_argument("--users", default="users.json")
    ap.add_argument("--token-ttl", type=int, default=300)
    ap.add_argument("--max-fails", type=int, default=5)
    ap.add_argument("--fail-window", type=int, default=300)
    ap.add_argument("--lock-seconds", type=int, default=120)
    ap.add_argument("--log-dir", default="logs")
    ap.add_argument("--log-max-bytes", type=int, default=1_000_000)
    ap.add_argument("--log-backups", type=int, default=5)
    ap.add_argument("--upload-dir", default="uploads")
    return ap.parse_args(argv)


if __name__ == "__main__":
    try:
        asyncio.run(run_server(parse_args()))
    except KeyboardInterrupt:
        log("server.stop")
        print("\nServer stopped.")
