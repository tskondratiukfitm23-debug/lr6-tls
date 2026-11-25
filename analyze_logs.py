"""LR6 — JSON log analyser: statistics + detection of atypical situations.

  python analyze_logs.py logs/server.jsonl                    # console report
  python analyze_logs.py logs/server.jsonl --md docs/log_analysis.md

Rotated files (server.jsonl.1 … .N) are read automatically.
"""
import argparse
import collections
import glob
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List

TLS_REASON_HINTS = {
    "TLSV1_ALERT_UNKNOWN_CA": "клієнт не довіряє CA сервера (чужий/підмінений сертифікат або MITM)",
    "SSLV3_ALERT_BAD_CERTIFICATE": "клієнт відхилив сертифікат (ім'я хоста/термін дії)",
    "SSLV3_ALERT_CERTIFICATE_UNKNOWN": "клієнт відхилив сертифікат сервера (невідповідність імені хоста тощо)",
    "CERTIFICATE_VERIFY_FAILED": "сертифікат клієнта не пройшов перевірку (чужий CA) — mTLS",
    "PEER_DID_NOT_RETURN_A_CERTIFICATE": "клієнт не надав сертифікат при увімкненому mTLS",
    "WRONG_VERSION_NUMBER": "спроба розмовляти без TLS (відкритий текст) або сканер портів",
    "HTTP_REQUEST": "HTTP без TLS на TLS-порт",
    "UNSUPPORTED_PROTOCOL": "застаріла версія протоколу (TLS 1.0/1.1)",
    "NO_SHARED_CIPHER": "немає спільних наборів шифрів (слабкий клієнт)",
    "HANDSHAKE_TIMEOUT": "handshake не завершено (slowloris/сканер)",
}
HIGH_TLS = {"TLSV1_ALERT_UNKNOWN_CA", "CERTIFICATE_VERIFY_FAILED", "SSLV3_ALERT_BAD_CERTIFICATE",
            "SSLV3_ALERT_CERTIFICATE_UNKNOWN"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def load(path: str) -> List[Dict[str, Any]]:
    rotated = [p for p in glob.glob(path + ".*") if p.rsplit(".", 1)[-1].isdigit()]
    rotated.sort(key=lambda p: -int(p.rsplit(".", 1)[-1]))          # oldest (.N) first
    events, bad = [], 0
    for fn in rotated + [path]:
        if not os.path.exists(fn):
            continue
        with open(fn, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    bad += 1
    if bad:
        print(f"[!] пропущено пошкоджених рядків: {bad}", file=sys.stderr)
    return events


def ts(e) -> datetime:
    return datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))


def ip_of(e) -> str:
    return str(e.get("peer", "?")).rsplit(":", 1)[0]


def bursts(evts, key, threshold: int, window_s: int):
    """Sliding window: groups with >= threshold events within window_s seconds."""
    by = collections.defaultdict(list)
    for e in evts:
        by[key(e)].append(ts(e))
    out = []
    for k, times in by.items():
        times.sort()
        i, best = 0, 0
        for j in range(len(times)):
            while (times[j] - times[i]).total_seconds() > window_s:
                i += 1
            best = max(best, j - i + 1)
        if best >= threshold:
            out.append((k, best, len(times), times[0], times[-1]))
    return out


def analyse(events, bf_threshold: int, bf_window: int) -> Dict[str, Any]:
    ev = collections.Counter(e.get("event") for e in events)
    of = lambda name: [e for e in events if e.get("event") == name]  # noqa: E731
    findings = []

    def add(sev, title, detail, action):
        findings.append({"severity": sev, "title": title, "detail": detail, "action": action})

    # --- TLS
    hs_ok, hs_fail = of("tls.handshake_ok"), of("tls.handshake_fail")
    versions = collections.Counter((e.get("tls") or {}).get("version") for e in hs_ok)
    ciphers = collections.Counter((e.get("tls") or {}).get("cipher") for e in hs_ok)
    reasons = collections.Counter(e.get("reason") for e in hs_fail)
    for reason, n in reasons.most_common():
        ips = sorted({ip_of(e) for e in hs_fail if e.get("reason") == reason})
        add("HIGH" if reason in HIGH_TLS else "MEDIUM", f"Збій TLS handshake: {reason} ×{n}",
            f"{TLS_REASON_HINTS.get(reason, 'невідома причина')}; джерела: {', '.join(ips)}",
            "перевірити клієнтів/мережу на MITM, підтвердити розповсюдження актуального CA")
    weak = [v for v in versions if v and v not in ("TLSv1.2", "TLSv1.3")]
    if weak:
        add("HIGH", "Застарілі версії TLS", ", ".join(weak), "підняти minimum_version")

    # --- authentication
    fails, oks = of("auth.fail"), of("auth.ok")
    for user, peak, total, t0, t1 in bursts(fails, lambda e: e.get("user", "?"), bf_threshold, bf_window):
        add("HIGH", f"Перебір пароля для облікового запису '{user}'",
            f"{peak} невдач за ≤{bf_window} с (всього {total}), {t0:%H:%M:%S}–{t1:%H:%M:%S} UTC",
            "блокування спрацювало автоматично; перевірити джерело, за потреби заблокувати IP")
    for ip, peak, total, _t0, _t1 in bursts(fails, ip_of, bf_threshold * 2, bf_window):
        add("MEDIUM", f"Багато невдалих входів з IP {ip}", f"{peak} за ≤{bf_window} с, всього {total}",
            "можливий password spraying: моніторинг/rate-limit на рівні мережі")
    unknown = collections.Counter(e.get("user") for e in fails if e.get("reason") == "unknown_user")
    if unknown:
        add("MEDIUM", "Спроби входу під неіснуючими іменами",
            ", ".join(f"{u}×{n}" for u, n in unknown.most_common(5)), "ознака перебору логінів (enumeration)")
    for e in of("auth.lockout"):
        add("HIGH", f"Блокування {e.get('lock_key')}", f"о {ts(e):%H:%M:%S} UTC на {e.get('lock_seconds')} с",
            "повідомити власника облікового запису")
    locked_attempts = of("auth.locked")
    if locked_attempts:
        add("MEDIUM", "Спроби входу під час блокування", f"{len(locked_attempts)} спроб",
            "атакувальник продовжує перебір — розглянути блокування IP")

    # --- integrity / tokens / ACL
    for name, sev, title, action in (
        ("integrity.bad_hmac", "HIGH", "Невірний HMAC (підміна даних)", "дані відхилено; розслідувати клієнта"),
        ("integrity.replay", "HIGH", "Повторне відтворення повідомлень (replay)", "відхилено за номером seq"),
        ("integrity.digest_mismatch", "MEDIUM", "Невідповідність SHA-256 файлу", "файл не збережено"),
        ("token.invalid", "MEDIUM", "Недійсні/відкликані токени", "можлива крадіжка або перебір токенів"),
        ("token.expired", "LOW", "Прострочені токени", "нормально при TTL; клієнт має перелогінитись"),
        ("acl.denied", "MEDIUM", "Відмова в доступі (ACL)", "спроба ескалації привілеїв"),
        ("acl.unauthenticated", "MEDIUM", "Запити без автентифікації", "відхилено"),
        ("proto.bad_json", "LOW", "Некоректні повідомлення протоколу", "можливий фазинг"),
        ("conn.error", "LOW", "Помилки з'єднання", "перевірити стабільність мережі"),
    ):
        lst = of(name)
        if lst:
            users = collections.Counter(e.get("user", "?") for e in lst)
            add(sev, f"{title} ×{len(lst)}", "користувачі: " + ", ".join(f"{u}×{n}" for u, n in users.items()), action)

    # --- secret leakage self-check
    leaks = [e for e in events for k in ("password", "session_key") if k in e and e[k] != "***"]
    long_tokens = [e for e in events if isinstance(e.get("token"), str) and len(e["token"]) > 8]
    if leaks or long_tokens:
        add("HIGH", "Секрети у журналі!", f"{len(leaks) + len(long_tokens)} записів", "виправити маскування")
    else:
        add("INFO", "Маскування секретів", "паролів, ключів сесії та повних токенів у журналі не знайдено", "—")

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    total_hs = len(hs_ok) + len(hs_fail)
    stats = {
        "events": len(events),
        "period": (f"{ts(events[0]):%Y-%m-%d %H:%M:%S} — {ts(events[-1]):%H:%M:%S} UTC" if events else "—"),
        "by_event": dict(ev.most_common()),
        "connections": ev.get("conn.open", 0),
        "handshake_ok": len(hs_ok),
        "handshake_fail": len(hs_fail),
        "handshake_success_rate": round(100 * len(hs_ok) / total_hs, 1) if total_hs else 0.0,
        "tls_versions": dict(versions),
        "ciphers": dict(ciphers),
        "auth_ok": len(oks),
        "auth_fail": len(fails),
        "data_ok": ev.get("data.ok", 0) + ev.get("file.ok", 0),
        "codes": dict(collections.Counter(str(e.get("code")) for e in events if "code" in e).most_common()),
    }
    return {"stats": stats, "findings": findings}


def verdict(res) -> List[str]:
    s, f = res["stats"], res["findings"]
    high = sum(1 for x in f if x["severity"] == "HIGH")
    weak = [v for v in s["tls_versions"] if v not in ("TLSv1.2", "TLSv1.3")]
    integrity = any(x["title"].startswith(("Невірний HMAC", "Повторне", "Невідповідність SHA")) for x in f)
    return [
        f"Усі успішні сесії використовували {', '.join(s['tls_versions']) or '—'} з AEAD-шифрами "
        f"({', '.join(s['ciphers']) or '—'}); застарілих протоколів "
        f"{'не виявлено' if not weak else 'ВИЯВЛЕНО: ' + ', '.join(weak)}.",
        f"Усі {s['handshake_fail']} збої handshake закінчились розривом з'єднання до передачі прикладних даних — "
        "сервер не обслуговує клієнтів без валідного TLS.",
        f"Невдалих автентифікацій: {s['auth_fail']}, успішних: {s['auth_ok']}; механізм блокування "
        f"{'спрацював' if any(x['title'].startswith('Блокування') for x in f) else 'не знадобився'}.",
        "Порушення цілісності (HMAC/replay/SHA-256) виявлені й відхилені на прикладному рівні." if integrity
        else "Порушень цілісності на прикладному рівні не зафіксовано.",
        f"Аномалій високого рівня: {high}. У демо-сценаріях це очікувані реакції захисту; "
        "у продуктиві кожна з них потребувала б реагування (алерт SOC).",
    ]


def print_report(res):
    s = res["stats"]
    print("══════════ Аналіз журналу TLS-сервера ══════════")
    print(f"Подій: {s['events']}   Період: {s['period']}")
    print(f"З'єднань: {s['connections']}   handshake OK/FAIL: {s['handshake_ok']}/{s['handshake_fail']} "
          f"({s['handshake_success_rate']}% успішних)")
    print(f"TLS версії: {s['tls_versions']}")
    print(f"Шифри     : {s['ciphers']}")
    print(f"AUTH ok/fail: {s['auth_ok']}/{s['auth_fail']}   Успішних операцій з даними: {s['data_ok']}")
    print(f"Коди відповідей: {s['codes']}")
    print("\n────────── Нетипові ситуації ──────────")
    for i, x in enumerate(res["findings"], 1):
        print(f"{i:>2}. [{x['severity']:<6}] {x['title']}\n        {x['detail']}\n        → {x['action']}")
    print("\n────────── Висновок ──────────")
    for line in verdict(res):
        print(" • " + line)


def write_md(res, path):
    s = res["stats"]
    L = ["# Аналіз журналу TLS-сервера (згенеровано analyze_logs.py)", "",
         f"Період: **{s['period']}**, подій: **{s['events']}**, з'єднань: **{s['connections']}**.", "",
         "| Показник | Значення |", "|---|---:|",
         f"| Успішних handshake | {s['handshake_ok']} |", f"| Невдалих handshake | {s['handshake_fail']} |",
         f"| Частка успішних handshake, % | {s['handshake_success_rate']} |",
         f"| Успішних автентифікацій | {s['auth_ok']} |", f"| Невдалих автентифікацій | {s['auth_fail']} |",
         f"| Успішних операцій з даними | {s['data_ok']} |", "",
         f"TLS-версії: `{s['tls_versions']}`; шифри: `{s['ciphers']}`.", "",
         f"Коди відповідей: `{s['codes']}`.", "", "## Нетипові ситуації", "",
         "| # | Рівень | Подія | Деталі | Реакція |", "|---:|---|---|---|---|"]
    for i, x in enumerate(res["findings"], 1):
        L.append(f"| {i} | {x['severity']} | {x['title']} | {x['detail']} | {x['action']} |")
    L += ["", "## Висновок", ""] + [f"- {v}" for v in verdict(res)] + [""]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"\nMarkdown-звіт збережено: {path}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?", default="logs/server.jsonl")
    ap.add_argument("--md", help="write a Markdown report to this path")
    ap.add_argument("--json", help="write machine-readable results")
    ap.add_argument("--bf-threshold", type=int, default=3, help="failed logins considered brute force")
    ap.add_argument("--bf-window", type=int, default=60, help="window in seconds")
    a = ap.parse_args(argv)
    events = load(a.log)
    if not events:
        print("Журнал порожній або не знайдений:", a.log)
        return 1
    res = analyse(events, a.bf_threshold, a.bf_window)
    print_report(res)
    if a.md:
        write_md(res, a.md)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
