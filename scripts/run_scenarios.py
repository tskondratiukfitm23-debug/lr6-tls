"""Runs the demo scenarios (successful and failing) against a running server.

  python scripts/run_scenarios.py                 # server started normally
  python scripts/run_scenarios.py --mtls          # server started with --require-client-cert

Passwords are asked interactively (hidden) or taken from LR6_PASS_ALICE / LR6_PASS_ADMIN.
"""
import argparse
import getpass
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from client import SecureClient  # noqa: E402

RESULTS = []


def row(n, title, expected, got):
    ok = expected == got
    RESULTS.append((n, title, expected, got, ok))
    print(f"  {'✔' if ok else '✘'} #{n:<2} {title:<48} очікувано={expected:<26} отримано={got}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--certs", default="certs")
    ap.add_argument("--mtls", action="store_true", help="server runs with --require-client-cert")
    ap.add_argument("--sample", default="samples/test_message.txt")
    a = ap.parse_args()
    c = lambda n: os.path.join(a.certs, n)  # noqa: E731
    mt = dict(cert=c("client.crt"), key=c("client.key")) if a.mtls else {}

    alice_pw = os.environ.get("LR6_PASS_ALICE") or getpass.getpass("Пароль alice: ")
    admin_pw = os.environ.get("LR6_PASS_ADMIN") or getpass.getpass("Пароль admin: ")

    def client(**kw):
        params = dict(host=a.host, port=a.port, ca=c("ca.crt"), **mt)
        params.update(kw)
        return SecureClient(**params)

    def session(user, pwd, **kw):
        cl = client(**kw)
        cl.connect()
        r = cl.auth(user, pwd)
        return cl, r

    print(f"\n=== Сценарії ЛР6 → {a.host}:{a.port} {'(mTLS)' if a.mtls else ''} ===")

    # 1. normal echo
    cl, r = session("alice", alice_pw)
    print(f"  TLS: {cl.tls['protocol']} / {cl.tls['cipher']} / {cl.tls['subject']}")
    e = cl.request("echo", message="Привіт, TLS! Тестове повідомлення ЛР6")
    row(1, "AUTH alice + echo, HMAC відповіді", "200 + HMAC OK", f"{e['code']} + HMAC {'OK' if e['_hmac_valid'] else 'BAD'}")
    # 2. file upload
    f = cl.send_file(a.sample)
    row(2, "Передача файлу (SHA-256 + HMAC)", "200", str(f["code"]))
    # 3. ACL: user -> stats
    s = cl.request("stats")
    row(3, "ACL: роль user викликає stats", "403", str(s["code"]))
    # 4. tampered message
    m = cl.build("echo", message="original")
    m["message"] = "tampered"
    row(4, "Підміна даних після HMAC", "422", str(cl.exchange(m)["code"]))
    # 5. replay
    m = cl.build("echo", message="pay 100 UAH")
    cl.exchange(m)
    row(5, "Replay того самого повідомлення", "409", str(cl.exchange(m)["code"]))
    # 6. forged token
    good = cl.token
    cl.token = "forged-token-" + good[:10]
    row(6, "Підроблений токен", "401", str(cl.request("echo", message="x")["code"]))
    cl.token = good
    # 7. logout -> token reuse
    cl.request("logout")
    row(7, "Повторне використання токена після logout", "401", str(cl.request("echo", message="x")["code"]))
    cl.quit()

    # 8. admin stats
    cl, r = session("admin", admin_pw)
    row(8, "ACL: роль admin викликає stats", "200", str(cl.request("stats")["code"]))
    cl.quit()

    # 9. unknown user
    cl, r = session("mallory", "whatever-password")
    row(9, "Невідомий користувач", "401", str(r["code"]))
    cl.quit()

    # 10. brute force -> lockout
    codes = []
    for _ in range(6):
        cl, r = session("bob", "wrong-password-guess")
        codes.append(r["code"])
        cl.quit()
    row(10, "6 невдалих паролів bob → блокування", "401x5,423", f"401x{codes[:5].count(401)},{codes[5]}")

    # 11. untrusted CA on the client side
    try:
        client(ca=c("rogue_ca.crt")).connect()
        got = "з'єднано (ПОГАНО)"
    except ssl.SSLCertVerificationError as ex:
        got = f"відхилено: {ex.verify_message}"[:40]
    row(11, "Клієнт не довіряє CA сервера", "відхилено", got.split(":")[0])

    # 12. hostname mismatch
    try:
        client(server_name="evil.example").connect()
        got = "з'єднано (ПОГАНО)"
    except ssl.SSLCertVerificationError as ex:
        got = "відхилено"
        print(f"      ({ex.verify_message})")
    row(12, "Невідповідність імені хоста (SAN)", "відхилено", got)

    # 13. plain TCP without TLS
    s = socket.create_connection((a.host, a.port), timeout=5)
    s.sendall(b'{"op":"auth","username":"alice","password":"plaintext"}\n')
    try:
        data = s.recv(100)
        got = "закрито сервером" if not data else "відповідь у відкритому вигляді (ПОГАНО)"
    except OSError:
        got = "закрито сервером"
    s.close()
    row(13, "Підключення без TLS (відкритий текст)", "закрито сервером", got)

    if a.mtls:
        # 14. no client certificate
        try:
            cl = SecureClient(a.host, a.port, c("ca.crt"))
            cl.connect()
            cl.auth("alice", alice_pw)
            got = "доступ (ПОГАНО)"
        except (ssl.SSLError, OSError, Exception):
            got = "відхилено"
        row(14, "mTLS: клієнт без сертифіката", "відхилено", got)
        # 15. client certificate from rogue CA
        try:
            cl = SecureClient(a.host, a.port, c("ca.crt"), cert=c("rogue_client.crt"), key=c("rogue_client.key"))
            cl.connect()
            cl.auth("alice", alice_pw)
            got = "доступ (ПОГАНО)"
        except (ssl.SSLError, OSError, Exception):
            got = "відхилено"
        row(15, "mTLS: сертифікат від чужого CA", "відхилено", got)

    time.sleep(0.3)
    passed = sum(1 for r in RESULTS if r[4])
    print(f"\n=== Результат: {passed}/{len(RESULTS)} сценаріїв поводяться як очікувано ===")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
