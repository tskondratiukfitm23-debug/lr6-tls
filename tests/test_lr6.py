"""End-to-end tests: real TLS server process + client library."""
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import analyze_logs  # noqa: E402
import protocol as P  # noqa: E402
from client import SecureClient  # noqa: E402

PW = {"alice": secrets.token_urlsafe(12), "bob": secrets.token_urlsafe(12), "admin": secrets.token_urlsafe(12)}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("certs")
    subprocess.run(["bash", os.path.join(ROOT, "scripts", "gencerts.sh")], check=True,
                   env={**os.environ, "CERT_DIR": str(d)}, capture_output=True)
    return d


@pytest.fixture(scope="session")
def users(tmp_path_factory):
    f = tmp_path_factory.mktemp("u") / "users.json"
    for name, role in (("alice", "user"), ("bob", "user"), ("admin", "admin")):
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "add_user.py"), name, "--role", role,
                        "--users", str(f), "--rounds", "4"], check=True, capture_output=True,
                       env={**os.environ, "LR6_NEW_PASSWORD": PW[name]})
    return f


def start_server(pki, users, tmp, *extra):
    port = free_port()
    logdir = tmp / "logs"
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "server.py"), "--port", str(port),
         "--cert", str(pki / "server.crt"), "--key", str(pki / "server.key"), "--ca", str(pki / "ca.crt"),
         "--users", str(users), "--log-dir", str(logdir), "--upload-dir", str(tmp / "up"),
         "--max-fails", "3", "--lock-seconds", "30", *extra],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return proc, port, logdir / "server.jsonl"


@pytest.fixture()
def server(pki, users, tmp_path):
    proc, port, log = start_server(pki, users, tmp_path, "--token-ttl", "2")
    yield port, log
    proc.terminate()
    proc.wait(5)


@pytest.fixture()
def mtls_server(pki, users, tmp_path):
    proc, port, log = start_server(pki, users, tmp_path, "--require-client-cert")
    yield port, log
    proc.terminate()
    proc.wait(5)


def cli(pki, port, **kw):
    params = dict(host="127.0.0.1", port=port, ca=str(pki / "ca.crt"))
    params.update(kw)
    return SecureClient(**params)


def login(pki, port, user="alice", pwd=None, **kw):
    c = cli(pki, port, **kw)
    c.connect()
    r = c.auth(user, PW[user] if pwd is None else pwd)
    return c, r


def events(log):
    time.sleep(0.2)
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


# ---------------------------------------------------------------- protocol unit tests

def test_hmac_sign_verify_and_tamper():
    key = secrets.token_bytes(32)
    m = P.sign({"op": "echo", "seq": 1, "message": "hi"}, key)
    assert P.verify(m, key)
    m["message"] = "HI"
    assert not P.verify(m, key)
    assert not P.verify(P.sign({"a": 1}, key), secrets.token_bytes(32))


# ---------------------------------------------------------------- TLS parameters

def test_tls_parameters_and_certificate(server, pki):
    c = cli(pki, server[0])
    info = c.connect()
    assert info["protocol"] in ("TLSv1.3", "TLSv1.2")
    assert "GCM" in info["cipher"] or "CHACHA20" in info["cipher"]
    assert "commonName=localhost" in info["subject"]
    assert "LR6 Demo Root CA" in info["issuer"]
    assert "DNS:localhost" in info["san"]
    c.close()


def test_tls12_client_gets_aead_ecdhe(server, pki):
    c = cli(pki, server[0])
    c.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    info = c.connect()
    assert info["protocol"] == "TLSv1.2" and info["cipher"].startswith("ECDHE-")
    c.close()


def test_old_tls_rejected(server, pki):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(pki / "ca.crt"))
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, ssl.SSLError):
        pytest.skip("local OpenSSL cannot offer TLS 1.1")
    with pytest.raises((ssl.SSLError, OSError)):
        with socket.create_connection(("127.0.0.1", server[0])) as s:
            ctx.wrap_socket(s, server_hostname="localhost")


def test_untrusted_ca_and_hostname_mismatch(server, pki):
    with pytest.raises(ssl.SSLCertVerificationError):
        cli(pki, server[0], ca=str(pki / "rogue_ca.crt")).connect()
    with pytest.raises(ssl.SSLCertVerificationError):
        cli(pki, server[0], server_name="evil.example").connect()
    reasons = {e.get("reason") for e in events(server[1]) if e["event"] == "tls.handshake_fail"}
    assert "TLSV1_ALERT_UNKNOWN_CA" in reasons


def test_plaintext_connection_rejected(server):
    s = socket.create_connection(("127.0.0.1", server[0]), timeout=5)
    s.sendall(b'{"op":"auth","username":"alice","password":"x"}\n')
    assert s.recv(100) == b""
    s.close()
    # OpenSSL 3.0-3.4 reports WRONG_VERSION_NUMBER, OpenSSL 3.5+ reports RECORD_LAYER_FAILURE
    plaintext_reasons = {"WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE"}
    assert any(e.get("event") == "tls.handshake_fail" and e.get("reason") in plaintext_reasons
               for e in events(server[1]))


# ---------------------------------------------------------------- auth / access control

def test_auth_ok_echo_file_and_response_hmac(server, pki):
    c, r = login(pki, server[0])
    assert r["code"] == 200 and r["role"] == "user" and len(r["session_key"]) == 64
    e = c.request("echo", message="Привіт")
    assert e["code"] == 200 and e["echo"] == "Привіт" and e["_hmac_valid"] is True
    f = c.send_file(os.path.join(ROOT, "samples", "test_message.txt"))
    assert f["code"] == 200 and f["_hmac_valid"]
    c.quit()


def test_wrong_password_and_unknown_user(server, pki):
    c, r = login(pki, server[0], pwd="wrong-password")
    assert r["code"] == 401
    c.quit()
    c, r = login(pki, server[0], user="alice", pwd="x")
    c.quit()
    c = cli(pki, server[0]); c.connect()
    assert c.auth("nobody", "whatever")["code"] == 401
    c.quit()


def test_lockout_after_max_fails(server, pki):
    codes = []
    for _ in range(4):
        c, r = login(pki, server[0], user="bob", pwd="bad-guess")
        codes.append(r["code"])
        c.quit()
    assert codes == [401, 401, 401, 423]
    c, r = login(pki, server[0], user="bob")           # even the right password is refused while locked
    assert r["code"] == 423
    c.quit()
    ev = [e["event"] for e in events(server[1])]
    assert "auth.lockout" in ev and "auth.locked" in ev


def test_acl_user_vs_admin(server, pki):
    c, _ = login(pki, server[0])
    assert c.request("stats")["code"] == 403
    c.quit()
    c, _ = login(pki, server[0], user="admin")
    s = c.request("stats")
    assert s["code"] == 200 and "counters" in s
    c.quit()


def test_request_without_auth(server, pki):
    c = cli(pki, server[0]); c.connect()
    c.send_raw({"op": "echo", "message": "x"})
    assert c.recv()["code"] == 401
    c.close()


# ---------------------------------------------------------------- integrity / tokens

def test_tamper_replay_forged_token(server, pki):
    c, _ = login(pki, server[0])
    m = c.build("echo", message="original"); m["message"] = "tampered"
    assert c.exchange(m)["code"] == 422
    m = c.build("echo", message="pay")
    assert c.exchange(m)["code"] == 200
    assert c.exchange(m)["code"] == 409
    good = c.token
    c.token = "forged"
    assert c.request("echo", message="x")["code"] == 401
    c.token = good
    assert c.request("logout")["code"] == 200
    assert c.request("echo", message="x")["code"] == 401
    c.quit()


def test_file_digest_mismatch(server, pki):
    c, _ = login(pki, server[0])
    r = c.request("file", name="a.txt", data_b64="aGVsbG8=", sha256="00" * 32)
    assert r["code"] == 422
    c.quit()


def test_token_expiry(server, pki):
    c, _ = login(pki, server[0])
    time.sleep(2.2)
    assert c.request("echo", message="late")["code"] == 419
    c.quit()


# ---------------------------------------------------------------- mTLS

def test_mtls(mtls_server, pki):
    port, log = mtls_server
    c, r = login(pki, port, cert=str(pki / "client.crt"), key=str(pki / "client.key"))
    assert r["code"] == 200
    c.quit()
    for kw in ({}, {"cert": str(pki / "rogue_client.crt"), "key": str(pki / "rogue_client.key")}):
        with pytest.raises((ssl.SSLError, OSError, Exception)):
            c, r = login(pki, port, **kw)
            assert r["code"] == 200
    ok = [e for e in events(log) if e["event"] == "tls.handshake_ok"]
    assert ok[0]["client_cert_cn"] == "demo-client"


# ---------------------------------------------------------------- logging / analysis

def test_logs_masked_and_analyzer(server, pki):
    c, _ = login(pki, server[0])
    c.request("echo", message="x")
    c.quit()
    for _ in range(3):
        c, _ = login(pki, server[0], user="bob", pwd="bad")
        c.quit()
    raw = open(server[1], encoding="utf-8").read()
    assert PW["alice"] not in raw and "bad" not in raw.replace("bad_password", "").replace("bad_", "")
    for e in events(server[1]):
        if "token" in e:
            assert len(e["token"]) <= 8
    res = analyze_logs.analyse(analyze_logs.load(str(server[1])), 3, 60)
    titles = " ".join(f["title"] for f in res["findings"])
    assert "Перебір пароля" in titles and "Блокування user:bob" in titles
    assert any(f["title"] == "Маскування секретів" for f in res["findings"])
