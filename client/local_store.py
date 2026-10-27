from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class LocalChatStore:
    """SQLite state used by the graphical client."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS friends (
              username TEXT PRIMARY KEY,
              signing_public_key_pem TEXT NOT NULL,
              encryption_public_key_pem TEXT NOT NULL,
              signing_fingerprint TEXT NOT NULL,
              encryption_fingerprint TEXT NOT NULL,
              trust_status TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
              peer TEXT PRIMARY KEY,
              envelope_json TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              peer TEXT NOT NULL,
              direction TEXT NOT NULL,
              packet_json TEXT NOT NULL,
              plaintext TEXT,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS files (
              file_id TEXT PRIMARY KEY,
              peer TEXT NOT NULL,
              direction TEXT NOT NULL,
              manifest_json TEXT NOT NULL,
              local_path TEXT,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def upsert_friend(
        self,
        *,
        username: str,
        signing_public_key_pem: str,
        encryption_public_key_pem: str,
        signing_fingerprint: str,
        encryption_fingerprint: str,
        trust_status: str = "trusted",
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO friends(
              username, signing_public_key_pem, encryption_public_key_pem,
              signing_fingerprint, encryption_fingerprint, trust_status, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
              signing_public_key_pem = excluded.signing_public_key_pem,
              encryption_public_key_pem = excluded.encryption_public_key_pem,
              signing_fingerprint = excluded.signing_fingerprint,
              encryption_fingerprint = excluded.encryption_fingerprint,
              trust_status = excluded.trust_status,
              updated_at = excluded.updated_at
            """,
            (
                username,
                signing_public_key_pem,
                encryption_public_key_pem,
                signing_fingerprint,
                encryption_fingerprint,
                trust_status,
                _now(),
            ),
        )
        self.conn.commit()

    def get_friend(self, username: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM friends WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def list_friends(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM friends ORDER BY username COLLATE NOCASE").fetchall()
        return [dict(row) for row in rows]

    def save_session(self, peer: str, envelope: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO sessions(peer, envelope_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(peer) DO UPDATE SET envelope_json = excluded.envelope_json, updated_at = excluded.updated_at
            """,
            (peer, _json(envelope), _now()),
        )
        self.conn.commit()

    def get_session(self, peer: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT envelope_json FROM sessions WHERE peer = ?", (peer,)).fetchone()
        return json.loads(row["envelope_json"]) if row else None

    def save_message(
        self,
        *,
        peer: str,
        direction: str,
        packet: dict[str, Any],
        plaintext: str | None,
        status: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO messages(peer, direction, packet_json, plaintext, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (peer, direction, _json(packet), plaintext, status, _now()),
        )
        self.conn.commit()

    def list_messages(self, peer: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT direction, packet_json, plaintext, status, created_at
            FROM messages
            WHERE peer = ?
            ORDER BY id ASC
            """,
            (peer,),
        ).fetchall()
        return [
            {
                "direction": row["direction"],
                "packet": json.loads(row["packet_json"]),
                "plaintext": row["plaintext"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def save_file_record(
        self,
        *,
        file_id: str,
        peer: str,
        direction: str,
        manifest: dict[str, Any],
        local_path: str | None,
        status: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO files(file_id, peer, direction, manifest_json, local_path, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(file_id) DO UPDATE SET
              peer = excluded.peer,
              direction = excluded.direction,
              manifest_json = excluded.manifest_json,
              local_path = excluded.local_path,
              status = excluded.status,
              created_at = excluded.created_at
            """,
            (file_id, peer, direction, _json(manifest), local_path, status, _now()),
        )
        self.conn.commit()

    def get_file_record(self, file_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM files WHERE file_id = ?", (file_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["manifest"] = json.loads(data.pop("manifest_json"))
        return data

    def list_files(self, peer: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT file_id, direction, manifest_json, local_path, status, created_at
            FROM files
            WHERE peer = ?
            ORDER BY created_at ASC
            """,
            (peer,),
        ).fetchall()
        return [
            {
                "file_id": row["file_id"],
                "direction": row["direction"],
                "manifest": json.loads(row["manifest_json"]),
                "local_path": row["local_path"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
