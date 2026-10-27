from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL,
          last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS public_keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          key_type TEXT NOT NULL,
          public_key_pem TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS friends (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          friend_id INTEGER NOT NULL,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          UNIQUE(user_id, friend_id),
          FOREIGN KEY(user_id) REFERENCES users(id),
          FOREIGN KEY(friend_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS offline_messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          receiver_id INTEGER NOT NULL,
          sender_id INTEGER NOT NULL,
          packet_json TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL,
          FOREIGN KEY(receiver_id) REFERENCES users(id),
          FOREIGN KEY(sender_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS files (
          file_id TEXT PRIMARY KEY,
          sender_id INTEGER NOT NULL,
          receiver_id INTEGER NOT NULL,
          package_json TEXT NOT NULL,
          cipher_sha256 TEXT NOT NULL,
          size INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'stored',
          created_at TEXT NOT NULL,
          FOREIGN KEY(sender_id) REFERENCES users(id),
          FOREIGN KEY(receiver_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor TEXT,
          action TEXT NOT NULL,
          target TEXT,
          result TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
