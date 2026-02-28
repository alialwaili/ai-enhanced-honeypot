"""
setup_users.py — Run this script ONCE to populate the users table.
Delete or keep this file private after running it.

Usage:
    python setup_users.py add <username> <email> <password> [--active]

Examples:
    python setup_users.py add johndoe john@example.com MyPassword@1 --active
    python setup_users.py add janedoe jane@example.com MyPassword@2
    python setup_users.py list
"""

import sys
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_PATH = "honeypot.db"


def ensure_table(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    NOT NULL UNIQUE,
            email     TEXT    NOT NULL UNIQUE,
            password  TEXT    NOT NULL,
            created   TEXT    NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 0
        )
    """)


def cmd_add(args):
    if len(args) < 3:
        print("Usage: python setup_users.py add <username> <email> <password> [--active]")
        sys.exit(1)

    username  = args[0]
    email     = args[1]
    password  = args[2]
    is_active = 1 if "--active" in args else 0

    db = sqlite3.connect(DB_PATH)
    ensure_table(db)
    try:
        db.execute(
            "INSERT INTO users (username, email, password, created, is_active) VALUES (?,?,?,?,?)",
            (username, email, generate_password_hash(password),
             datetime.utcnow().isoformat(), is_active),
        )
        db.commit()
        status = "active" if is_active else "inactive"
        print(f"User '{username}' created ({status}).")
    except sqlite3.IntegrityError as e:
        print(f"Error: {e}")
    finally:
        db.close()


def cmd_list():
    db = sqlite3.connect(DB_PATH)
    ensure_table(db)
    rows = db.execute("SELECT id, username, email, is_active, created FROM users").fetchall()
    db.close()
    if not rows:
        print("No users found.")
        return
    print(f"{'ID':<4} {'Username':<20} {'Email':<30} {'Active':<8} Created")
    print("-" * 80)
    for row in rows:
        active = "yes" if row[3] else "no"
        print(f"{row[0]:<4} {row[1]:<20} {row[2]:<30} {active:<8} {row[4]}")


def cmd_activate(args):
    if not args:
        print("Usage: python setup_users.py activate <username>")
        sys.exit(1)
    db = sqlite3.connect(DB_PATH)
    db.execute("UPDATE users SET is_active = 1 WHERE username = ?", (args[0],))
    db.commit()
    db.close()
    print(f"User '{args[0]}' activated.")


def cmd_deactivate(args):
    if not args:
        print("Usage: python setup_users.py deactivate <username>")
        sys.exit(1)
    db = sqlite3.connect(DB_PATH)
    db.execute("UPDATE users SET is_active = 0 WHERE username = ?", (args[0],))
    db.commit()
    db.close()
    print(f"User '{args[0]}' deactivated.")


def cmd_delete(args):
    if not args:
        print("Usage: python setup_users.py delete <username>")
        sys.exit(1)
    db = sqlite3.connect(DB_PATH)
    db.execute("DELETE FROM users WHERE username = ?", (args[0],))
    db.commit()
    db.close()
    print(f"User '{args[0]}' deleted.")


COMMANDS = {
    "add":        cmd_add,
    "list":       lambda _: cmd_list(),
    "activate":   cmd_activate,
    "deactivate": cmd_deactivate,
    "delete":     cmd_delete,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Commands: add | list | activate | deactivate | delete")
        sys.exit(1)

    COMMANDS[sys.argv[1]](sys.argv[2:])
