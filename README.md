# ЛР №6 — Безпечний клієнт-серверний застосунок з SSL/TLS

Кондратюк Тимофій Сергійович, група 22340 (КУБГ, ФІТУ). Дисципліна «Прикладні аспекти програмування в системах інформаційної та кібербезпеки».

Python 3.10+ (asyncio + `ssl`), локальний CA (OpenSSL), bcrypt, HMAC-SHA256, JSON-журнали.
Технічний звіт щодо безпеки з'єднання: **[docs/REPORT.md](docs/REPORT.md)**.

## Можливості

| Вимога | Реалізація |
|---|---|
| TLS-сервер із сертифікатом | локальний CA (ECDSA P-384) → серверний сертифікат CN/SAN=localhost, 127.0.0.1, EKU serverAuth; TLS 1.2+ (за замовчуванням узгоджується TLS 1.3), лише ECDHE + AEAD |
| Доступ лише після автентифікації | перше повідомлення — `auth`; пароль перевіряється за солоним bcrypt-хешем; блокування після 5 невдач; токен сесії з TTL; ролі `user`/`admin` (ACL) |
| Клієнт із перевіркою цілісності | перевірка сертифіката й імені хоста (ніколи не вимикається), вивід параметрів сесії, HMAC-SHA256 кожного запиту й відповіді, номер `seq` проти replay, SHA-256 файлів |
| Опційно mTLS | `--require-client-cert` на сервері, `--cert/--key` на клієнті |
| Журналювання й аналіз | JSON Lines з часовими мітками (мс, UTC), кодами відповідей і обсягом даних; маскування секретів; ротація; `analyze_logs.py` знаходить аномалії (чужі сертифікати, перебір паролів, підміна, replay, ACL тощо) |

## Структура

```
server.py               TLS-сервер (автентифікація, ACL, HMAC, журнал)
client.py               TLS-клієнт (CLI + клас SecureClient)
protocol.py             спільні функції протоколу (канонічний JSON, HMAC, коди)
analyze_logs.py         аналізатор журналу (консоль / Markdown / JSON)
scripts/gencerts.sh     локальний CA, серверний і клієнтський сертифікати (+ «чужий» CA для тестів)
scripts/add_user.py     створення користувача (лише bcrypt-хеш)
scripts/run_scenarios.py  13 (або 15 з mTLS) сценаріїв: успішні та збійні
tests/test_lr6.py       16 автотестів pytest (реальний сервер + клієнт)
samples/test_message.txt  тестовий файл для передачі
docs/REPORT.md          технічний звіт щодо безпеки з'єднання
docs/log_analysis.md    результат роботи analyze_logs.py
docs/logs/              журнали «до» (заготовка) і «після» (фінальна версія), вивід сценаріїв
```

## Запуск (Linux / Ubuntu)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

bash scripts/gencerts.sh                     # 1. сертифікати → ./certs
python scripts/add_user.py alice             # 2. користувачі (пароль вводиться приховано, мін. 8 символів)
python scripts/add_user.py bob
python scripts/add_user.py admin --role admin

python server.py                             # 3. сервер на 127.0.0.1:8443 (окремий термінал)

python client.py --user alice --msg "hello TLS" --file samples/test_message.txt --whoami   # 4. клієнт
python scripts/run_scenarios.py              # 5. усі сценарії (успішні та збійні)
python analyze_logs.py logs/server.jsonl --md docs/log_analysis.md                          # 6. аналіз журналу
python -m pytest -q                          # 7. автотести
```

mTLS: `python server.py --require-client-cert` і клієнт з `--cert certs/client.crt --key certs/client.key`
(або `python scripts/run_scenarios.py --mtls`).

Пароль клієнт запитує приховано; для автоматизації можна задати змінну `LR6_PASSWORD`
(для сценаріїв — `LR6_PASS_ALICE`, `LR6_PASS_ADMIN`). Параметр `--password` є, але небажаний: пароль
потрапляє в історію shell.

Корисні параметри сервера: `--tls13-only`, `--token-ttl 300`, `--max-fails 5`, `--lock-seconds 120`,
`--log-max-bytes 1000000 --log-backups 5`.

## Безпека репозиторію

`certs/`, `*.key`, `users.json`, `logs/` внесені до `.gitignore`: ключі й хеші генеруються локально
і не публікуються. У `docs/logs/` лежать лише демонстраційні журнали; секретів у них немає
(паролі, сесійні ключі й HMAC замасковані, токени обрізані до 6 символів).
