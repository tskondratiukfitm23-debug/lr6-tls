"""LR6 — secure TLS client/server: client part.

Steps shown on the console:
  1. TCP connect → TLS handshake with server-certificate verification (local CA bundle + hostname check)
  2. Printout of negotiated parameters: protocol, cipher suite, certificate CN/SAN/issuer/validity/fingerprint,
     verified trust chain
  3. AUTH {username, password} → session token + per-session HMAC key
  4. Signed request (echo message or file with SHA-256) → server verifies HMAC/seq → signed response,
     the client verifies the response HMAC
  5. logout / quit

Negative-test switches (--tamper-hmac, --replay, --bad-token) exist only to demonstrate the server's reaction.
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
import socket
import ssl
import sys
from typing import Any, Dict, Optional

import protocol as P


class ProtocolError(Exception):
    pass


def make_ssl_context(ca: str, cert: Optional[str] = None, key: Optional[str] = None,
                     tls13_only: bool = False) -> ssl.SSLContext:
    # create_default_context => CERT_REQUIRED + check_hostname=True (verification is NEVER disabled)
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3 if tls13_only else ssl.TLSVersion.TLSv1_2
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def _name(rdns) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def describe_tls(sock: ssl.SSLSocket) -> Dict[str, Any]:
    cert = sock.getpeercert()
    der = sock.getpeercert(binary_form=True)
    name, proto, bits = sock.cipher()
    info = {
        "protocol": sock.version(),
        "cipher": name,
        "cipher_protocol": proto,
        "key_bits": bits,
        "compression": sock.compression(),
        "subject": _name(cert.get("subject", ())),
        "issuer": _name(cert.get("issuer", ())),
        "san": ", ".join(f"{t}:{v}" for t, v in cert.get("subjectAltName", ())),
        "serial": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "sha256_fingerprint": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()),
        "chain": [],
    }
    if hasattr(sock, "get_verified_chain"):          # Python 3.13+
        try:
            for c in sock.get_verified_chain():
                d = c.get_info()
                info["chain"].append(_name(d.get("subject", ())))
        except Exception:  # noqa: BLE001
            pass
    if not info["chain"]:
        info["chain"] = [info["subject"], info["issuer"] + "  (trusted via --ca)"]
    return info


def print_tls(info: Dict[str, Any]) -> None:
    print("──── TLS-сесію встановлено ─────────────────────────────")
    print(f"  Протокол        : {info['protocol']}")
    print(f"  Cipher suite    : {info['cipher']} ({info['key_bits']}-bit key)")
    print(f"  Стиснення       : {info['compression'] or 'немає'}")
    print(f"  Сертифікат      : {info['subject']}")
    print(f"  SAN             : {info['san']}")
    print(f"  Видавець (CA)   : {info['issuer']}")
    print(f"  Дійсний         : {info['not_before']}  →  {info['not_after']}")
    print(f"  Серійний номер  : {info['serial']}")
    print(f"  SHA-256 відбиток: {info['sha256_fingerprint']}")
    print("  Ланцюжок довіри : " + "  ⇐  ".join(info["chain"]))
    print("  Перевірка       : сертифікат підписано довіреним CA, ім'я хоста збігається ✔")
    print("─────────────────────────────────────────────────────────")


class SecureClient:
    def __init__(self, host: str, port: int, ca: str, server_name: str = "localhost",
                 cert: Optional[str] = None, key: Optional[str] = None, timeout: float = 10,
                 tls13_only: bool = False):
        self.host, self.port, self.server_name = host, port, server_name
        self.ctx = make_ssl_context(ca, cert, key, tls13_only)
        self.timeout = timeout
        self.sock: Optional[ssl.SSLSocket] = None
        self.rfile = None
        self.token: Optional[str] = None
        self.key: Optional[bytes] = None
        self.seq = 0
        self.tls: Dict[str, Any] = {}

    # ---- transport
    def connect(self) -> Dict[str, Any]:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            self.sock = self.ctx.wrap_socket(raw, server_hostname=self.server_name)
        except Exception:
            raw.close()
            raise
        self.rfile = self.sock.makefile("rb")
        self.tls = describe_tls(self.sock)
        return self.tls

    def send_raw(self, obj: Dict[str, Any]) -> None:
        self.sock.sendall(P.encode(obj))

    def recv(self) -> Dict[str, Any]:
        line = self.rfile.readline(P.MAX_LINE)
        if not line:
            raise ProtocolError("server closed the connection")
        return json.loads(line.decode("utf-8"))

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = None

    # ---- application protocol
    def auth(self, username: str, password: str) -> Dict[str, Any]:
        self.send_raw({"op": "auth", "v": P.PROTOCOL_VERSION, "username": username, "password": password})
        r = self.recv()
        if r.get("ok"):
            self.token = r["token"]
            self.key = bytes.fromhex(r["session_key"])
            self.seq = 0
        return r

    def build(self, op: str, **fields) -> Dict[str, Any]:
        if self.key is None:
            raise RuntimeError("сесію не автентифіковано (AUTH не вдався) — немає сесійного HMAC-ключа")
        self.seq += 1
        return P.sign({"op": op, "token": self.token, "seq": self.seq, **fields}, self.key)

    def request(self, op: str, **fields) -> Dict[str, Any]:
        return self.exchange(self.build(op, **fields))

    def exchange(self, signed_msg: Dict[str, Any]) -> Dict[str, Any]:
        self.send_raw(signed_msg)
        r = self.recv()
        # responses to authenticated requests are signed by the server with the session key
        r["_hmac_valid"] = P.verify(r, self.key) if "hmac" in r else None
        return r

    def send_file(self, path: str) -> Dict[str, Any]:
        with open(path, "rb") as f:
            data = f.read()
        return self.request("file", name=os.path.basename(path),
                            data_b64=base64.b64encode(data).decode(), sha256=P.sha256_hex(data))

    def quit(self) -> None:
        try:
            self.send_raw({"op": "quit"})
            self.recv()
        except Exception:  # noqa: BLE001
            pass
        self.close()


# --------------------------------------------------------------------------- CLI

def show(label: str, r: Dict[str, Any]) -> None:
    shown = {k: v for k, v in r.items() if k not in ("hmac", "session_key", "token")}
    hv = r.get("_hmac_valid")
    mark = "" if hv is None else ("  [HMAC відповіді: OK ✔]" if hv else "  [HMAC відповіді: НЕВІРНИЙ ✘]")
    print(f"{label}: {json.dumps({k: v for k, v in shown.items() if k != '_hmac_valid'}, ensure_ascii=False)}{mark}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LR6 TLS client")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--server-name", default="localhost", help="expected name in the server certificate (SNI)")
    ap.add_argument("--ca", default="certs/ca.crt", help="CA bundle used to verify the server")
    ap.add_argument("--cert", help="client certificate (mTLS)")
    ap.add_argument("--key", help="client private key (mTLS)")
    ap.add_argument("--tls13-only", action="store_true")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", help="insecure on shared machines; prefer env LR6_PASSWORD or the prompt")
    ap.add_argument("--msg", help="text message to send")
    ap.add_argument("--file", help="file to upload (integrity: SHA-256 + HMAC)")
    ap.add_argument("--whoami", action="store_true")
    ap.add_argument("--stats", action="store_true", help="admin-only operation (ACL demo)")
    ap.add_argument("--tamper-hmac", action="store_true", help="DEMO: modify message after signing")
    ap.add_argument("--replay", action="store_true", help="DEMO: send the same signed message twice")
    ap.add_argument("--bad-token", action="store_true", help="DEMO: use a forged token")
    args = ap.parse_args(argv)

    password = args.password or os.environ.get("LR6_PASSWORD") or getpass.getpass(f"Пароль для {args.user}: ")
    cli = SecureClient(args.host, args.port, args.ca, args.server_name, args.cert, args.key,
                       tls13_only=args.tls13_only)
    print(f"[1] TCP-з'єднання з {args.host}:{args.port}, TLS handshake (SNI={args.server_name}) ...")
    try:
        print_tls(cli.connect())
    except ssl.SSLCertVerificationError as e:
        print(f"[✘] Сертифікат сервера ВІДХИЛЕНО: {e.verify_message} (код {e.verify_code}). З'єднання розірвано.")
        return 2
    except (ssl.SSLError, ConnectionError, OSError) as e:
        print(f"[✘] Помилка TLS/мережі: {e}")
        return 3

    try:
        print(f"[2] AUTH як '{args.user}' (пароль передається лише всередині TLS) ...")
        r = cli.auth(args.user, password)
        if not r.get("ok"):
            print(f"[✘] AUTH FAIL: code={r.get('code')} {r.get('status')} {r.get('err', '')}"
                  + (f", retry_after={r['retry_after']}s" if "retry_after" in r else ""))
            return 4
        print(f"[✔] AUTH OK: role={r['role']}, token={r['token'][:6]}… (TTL {r['expires_in']} c), "
              f"отримано сесійний HMAC-ключ (256 біт)")
        if args.bad_token:
            cli.token = "forged-" + cli.token[7:]

        step = 3
        if args.msg is not None:
            msg = cli.build("echo", message=args.msg)
            print(f"[{step}] DATA echo: '{args.msg}' seq={msg['seq']} hmac={msg['hmac'][:16]}…")
            if args.tamper_hmac:
                msg["message"] = args.msg + " (змінено після підпису)"
                print("    DEMO: повідомлення змінено ПІСЛЯ обчислення HMAC")
            show("    RESP", cli.exchange(msg))
            if args.replay:
                print("    DEMO: повторна відправка того самого підписаного повідомлення (replay)")
                show("    RESP", cli.exchange(msg))
            step += 1
        if args.file:
            print(f"[{step}] FILE {args.file} (SHA-256 {P.sha256_hex(open(args.file, 'rb').read())[:16]}…)")
            show("    RESP", cli.send_file(args.file))
            step += 1
        if args.whoami:
            show(f"[{step}] WHOAMI", cli.request("whoami"))
            step += 1
        if args.stats:
            show(f"[{step}] STATS", cli.request("stats"))
            step += 1
        show(f"[{step}] LOGOUT", cli.request("logout"))
    finally:
        cli.quit()
    print("[✔] Сесію закрито.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
