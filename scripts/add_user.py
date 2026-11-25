"""Create or update a user in users.json (password stored ONLY as a salted bcrypt hash).

Usage:
  python scripts/add_user.py alice                 # asks for the password twice (hidden input)
  python scripts/add_user.py admin --role admin
  LR6_NEW_PASSWORD=... python scripts/add_user.py bob   # non-interactive (CI/tests)
"""
import argparse
import getpass
import json
import os
import sys

import bcrypt


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("username")
    ap.add_argument("--role", choices=["user", "admin"], default="user")
    ap.add_argument("--users", default="users.json")
    ap.add_argument("--rounds", type=int, default=12, help="bcrypt cost factor (2^rounds iterations)")
    a = ap.parse_args(argv)

    pwd = os.environ.get("LR6_NEW_PASSWORD")
    if not pwd:
        pwd = getpass.getpass(f"Новий пароль для {a.username}: ")
        if pwd != getpass.getpass("Повторіть пароль: "):
            print("Паролі не збігаються", file=sys.stderr)
            return 1
    if len(pwd) < 8:
        print("Пароль має містити щонайменше 8 символів", file=sys.stderr)
        return 1

    users = {}
    if os.path.exists(a.users):
        with open(a.users, encoding="utf-8") as f:
            users = json.load(f)
    h = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt(rounds=a.rounds)).decode()
    users[a.username] = {"hash": h, "role": a.role}
    tmp = a.users + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    os.replace(tmp, a.users)
    try:
        os.chmod(a.users, 0o600)
    except OSError:
        pass
    print(f"Користувача '{a.username}' (роль {a.role}) збережено у {a.users}; хеш {h[:7]}… (bcrypt, cost={a.rounds})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
