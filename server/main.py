from __future__ import annotations

import hmac
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
    from pydantic import BaseModel
except ModuleNotFoundError:  # pragma: no cover - exercised by dependency checks.
    FastAPI = None
    BaseModel = object

from common.secure_chat import crypto_utils as crypto
from .database import connect, init_schema


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash_password(password: str) -> str:
    params = crypto.default_kdf_params()
    salt = crypto.random_bytes(16)
    digest = crypto.derive_storage_key(password, salt, params)
    return _json({**params, "salt_b64": crypto.b64e(salt), "hash_b64": crypto.b64e(digest)})


def _verify_password(password: str, stored: str) -> bool:
    data = json.loads(stored)
    expected = crypto.b64d(data.pop("hash_b64"))
    salt = crypto.b64d(data.pop("salt_b64"))
    actual = crypto.derive_storage_key(password, salt, data)
    return hmac.compare_digest(expected, actual)


class EncryptedPayload(BaseModel):
    encrypted_payload_b64: str


class LoginStart(BaseModel):
    username: str


class LoginPassword(BaseModel):
    login_id: str
    encrypted_payload_b64: str


class LoginProof(BaseModel):
    login_id: str
    username: str
    signature_b64: str


class FriendRequest(BaseModel):
    friend_username: str


class OfflineMessage(BaseModel):
    receiver: str
    packet: dict[str, Any]


class FilePackage(BaseModel):
    receiver: str
    package: dict[str, Any]


def create_app(db_path: str | Path = "server_data/secure_chat.sqlite"):
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed. Run: python3 -m pip install -r requirements.txt")

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    init_schema(conn)
    server_private_key, server_public_key = crypto.generate_rsa_keypair()
    login_challenges: dict[str, dict[str, str]] = {}
    tokens: dict[str, str] = {}

    class ConnectionManager:
        def __init__(self) -> None:
            self._active: dict[str, set[WebSocket]] = {}

        async def connect(self, username: str, websocket: WebSocket) -> None:
            await websocket.accept()
            self._active.setdefault(username, set()).add(websocket)

        def disconnect(self, username: str, websocket: WebSocket) -> None:
            sockets = self._active.get(username)
            if not sockets:
                return
            sockets.discard(websocket)
            if not sockets:
                self._active.pop(username, None)

        async def send_to_user(self, username: str, event: dict[str, Any]) -> None:
            stale: list[WebSocket] = []
            for websocket in list(self._active.get(username, set())):
                try:
                    await websocket.send_json(event)
                except RuntimeError:
                    stale.append(websocket)
            for websocket in stale:
                self.disconnect(username, websocket)

    manager = ConnectionManager()

    app = FastAPI(title="SecureChat API")

    def audit(actor: str | None, action: str, target: str | None, result: str, detail: str) -> None:
        conn.execute(
            "INSERT INTO audit_logs(actor, action, target, result, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (actor, action, target, result, detail, _now()),
        )
        conn.commit()

    def user_by_username(username: str):
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def current_username(authorization: str = Header("")) -> str:
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization[len(prefix) :]
        username = tokens.get(token)
        if not username:
            raise HTTPException(status_code=401, detail="invalid token")
        return username

    def decrypt_payload(encrypted_payload_b64: str) -> dict[str, Any]:
        try:
            plaintext = crypto.rsa_oaep_decrypt(server_private_key, crypto.b64d(encrypted_payload_b64))
            return json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail="invalid encrypted payload") from exc

    @app.get("/api/auth/server-key")
    def server_key():
        return {"server_public_key_pem": crypto.public_key_to_pem(server_public_key), "nonce": secrets.token_urlsafe(24)}

    @app.websocket("/ws/{token}")
    async def websocket_events(websocket: WebSocket, token: str):
        username = tokens.get(token)
        if not username:
            await websocket.close(code=1008)
            return
        await manager.connect(username, websocket)
        audit(username, "websocket_connect", username, "success", "online realtime channel connected")
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(username, websocket)
            audit(username, "websocket_disconnect", username, "success", "online realtime channel disconnected")

    @app.post("/api/auth/register")
    def register(body: EncryptedPayload):
        payload = decrypt_payload(body.encrypted_payload_b64)
        username = payload["username"].strip()
        if user_by_username(username):
            raise HTTPException(status_code=409, detail="username exists")
        signing_public = crypto.load_public_key_pem(payload["signing_public_key_pem"])
        encryption_public = crypto.load_public_key_pem(payload["encryption_public_key_pem"])
        cursor = conn.execute(
            "INSERT INTO users(username, password_hash, status, created_at) VALUES (?, ?, 'active', ?)",
            (username, _hash_password(payload["password"]), _now()),
        )
        user_id = cursor.lastrowid
        conn.executemany(
            """
            INSERT INTO public_keys(user_id, key_type, public_key_pem, fingerprint, version, status, created_at)
            VALUES (?, ?, ?, ?, 1, 'active', ?)
            """,
            [
                (
                    user_id,
                    "signing",
                    payload["signing_public_key_pem"],
                    crypto.fingerprint_public_key(signing_public),
                    _now(),
                ),
                (
                    user_id,
                    "encryption",
                    payload["encryption_public_key_pem"],
                    crypto.fingerprint_public_key(encryption_public),
                    _now(),
                ),
            ],
        )
        conn.commit()
        audit(username, "register", username, "success", "registered public keys")
        return {"status": "ok", "username": username}

    @app.post("/api/auth/login/start")
    def login_start(body: LoginStart):
        if not user_by_username(body.username):
            raise HTTPException(status_code=404, detail="user not found")
        login_id = secrets.token_urlsafe(24)
        login_challenges[login_id] = {"username": body.username, "server_nonce": secrets.token_urlsafe(24)}
        return {
            "login_id": login_id,
            "server_nonce": login_challenges[login_id]["server_nonce"],
            "server_public_key_pem": crypto.public_key_to_pem(server_public_key),
        }

    @app.post("/api/auth/login/password")
    def login_password(body: LoginPassword):
        challenge = login_challenges.get(body.login_id)
        if not challenge:
            raise HTTPException(status_code=401, detail="invalid login id")
        payload = decrypt_payload(body.encrypted_payload_b64)
        if payload["username"] != challenge["username"]:
            raise HTTPException(status_code=401, detail="username mismatch")
        user = user_by_username(payload["username"])
        if not user or not _verify_password(payload["password"], user["password_hash"]):
            audit(payload.get("username"), "login_password", payload.get("username"), "failed", "bad password")
            raise HTTPException(status_code=401, detail="bad credentials")
        identity_challenge = secrets.token_urlsafe(32)
        challenge["identity_challenge"] = identity_challenge
        return {"identity_challenge": identity_challenge}

    @app.post("/api/auth/login/prove-key")
    def login_prove_key(body: LoginProof):
        challenge = login_challenges.get(body.login_id)
        if not challenge or challenge.get("username") != body.username or "identity_challenge" not in challenge:
            raise HTTPException(status_code=401, detail="invalid challenge")
        user = user_by_username(body.username)
        key_row = conn.execute(
            """
            SELECT public_key_pem FROM public_keys
            WHERE user_id = ? AND key_type = 'signing' AND status = 'active'
            """,
            (user["id"],),
        ).fetchone()
        try:
            crypto.rsa_pss_verify(
                crypto.load_public_key_pem(key_row["public_key_pem"]),
                challenge["identity_challenge"].encode("utf-8"),
                crypto.b64d(body.signature_b64),
            )
        except Exception as exc:
            audit(body.username, "login_prove_key", body.username, "failed", "bad private-key proof")
            raise HTTPException(status_code=401, detail="bad key proof") from exc
        token = secrets.token_urlsafe(32)
        tokens[token] = body.username
        conn.execute("UPDATE users SET last_login_at = ? WHERE username = ?", (_now(), body.username))
        conn.commit()
        audit(body.username, "login", body.username, "success", "password and key proof accepted")
        login_challenges.pop(body.login_id, None)
        return {"access_token": token, "token_type": "bearer"}

    @app.get("/api/keys/{username}")
    def key_directory(username: str, actor: str = Depends(current_username)):
        user = user_by_username(username)
        if not user:
            raise HTTPException(status_code=404, detail="user not found")
        rows = conn.execute(
            "SELECT key_type, public_key_pem, fingerprint FROM public_keys WHERE user_id = ? AND status = 'active'",
            (user["id"],),
        ).fetchall()
        keys = {row["key_type"]: row for row in rows}
        response = {
            "username": username,
            "signing_public_key_pem": keys["signing"]["public_key_pem"],
            "encryption_public_key_pem": keys["encryption"]["public_key_pem"],
            "signing_fingerprint": keys["signing"]["fingerprint"],
            "encryption_fingerprint": keys["encryption"]["fingerprint"],
            "status": user["status"],
        }
        response["directory_signature_b64"] = crypto.b64e(crypto.rsa_pss_sign(server_private_key, crypto.canonical_json(response)))
        audit(actor, "query_key", username, "success", "returned signed public key directory")
        return response

    @app.post("/api/friends/request")
    def request_friend(body: FriendRequest, actor: str = Depends(current_username)):
        user = user_by_username(actor)
        friend = user_by_username(body.friend_username)
        if not friend:
            raise HTTPException(status_code=404, detail="friend not found")
        conn.execute(
            "INSERT OR REPLACE INTO friends(user_id, friend_id, status, created_at) VALUES (?, ?, 'pending', ?)",
            (user["id"], friend["id"], _now()),
        )
        conn.commit()
        audit(actor, "friend_request", body.friend_username, "success", "request stored")
        return {"status": "pending"}

    @app.post("/api/friends/accept")
    def accept_friend(body: FriendRequest, actor: str = Depends(current_username)):
        user = user_by_username(actor)
        friend = user_by_username(body.friend_username)
        if not friend:
            raise HTTPException(status_code=404, detail="friend not found")
        conn.execute(
            "INSERT OR REPLACE INTO friends(user_id, friend_id, status, created_at) VALUES (?, ?, 'accepted', ?)",
            (friend["id"], user["id"], _now()),
        )
        conn.execute(
            "INSERT OR REPLACE INTO friends(user_id, friend_id, status, created_at) VALUES (?, ?, 'accepted', ?)",
            (user["id"], friend["id"], _now()),
        )
        conn.commit()
        audit(actor, "friend_accept", body.friend_username, "success", "relationship accepted")
        return {"status": "accepted"}

    @app.post("/api/messages/offline")
    async def store_offline_message(body: OfflineMessage, actor: str = Depends(current_username)):
        sender = user_by_username(actor)
        receiver = user_by_username(body.receiver)
        if not receiver:
            raise HTTPException(status_code=404, detail="receiver not found")
        conn.execute(
            """
            INSERT INTO offline_messages(receiver_id, sender_id, packet_json, status, created_at)
            VALUES (?, ?, ?, 'pending', ?)
            """,
            (receiver["id"], sender["id"], _json(body.packet), _now()),
        )
        conn.commit()
        audit(actor, "offline_message", body.receiver, "success", "stored encrypted packet")
        await manager.send_to_user(
            body.receiver,
            {
                "type": "message",
                "sender": actor,
                "receiver": body.receiver,
                "packet": body.packet,
                "created_at": _now(),
            },
        )
        return {"status": "stored"}

    @app.get("/api/messages/offline")
    def offline_messages(actor: str = Depends(current_username)):
        user = user_by_username(actor)
        rows = conn.execute(
            """
            SELECT m.id, u.username AS sender, m.packet_json, m.created_at
            FROM offline_messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.receiver_id = ? AND m.status = 'pending'
            ORDER BY m.id ASC
            """,
            (user["id"],),
        ).fetchall()
        messages = [
            {
                "id": row["id"],
                "sender": row["sender"],
                "packet": json.loads(row["packet_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        conn.execute("UPDATE offline_messages SET status = 'delivered' WHERE receiver_id = ?", (user["id"],))
        conn.commit()
        audit(actor, "offline_fetch", actor, "success", f"delivered {len(messages)} packets")
        return {"messages": messages}

    @app.post("/api/files/upload")
    async def upload_file_package(body: FilePackage, actor: str = Depends(current_username)):
        sender = user_by_username(actor)
        receiver = user_by_username(body.receiver)
        if not receiver:
            raise HTTPException(status_code=404, detail="receiver not found")
        manifest = body.package.get("manifest", {})
        file_id = manifest.get("file_id")
        if not file_id:
            raise HTTPException(status_code=400, detail="missing file id")
        conn.execute(
            """
            INSERT OR REPLACE INTO files(file_id, sender_id, receiver_id, package_json, cipher_sha256, size, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'stored', ?)
            """,
            (
                file_id,
                sender["id"],
                receiver["id"],
                _json(body.package),
                manifest.get("cipher_sha256", ""),
                int(manifest.get("size", 0)),
                _now(),
            ),
        )
        conn.commit()
        audit(actor, "file_upload", body.receiver, "success", f"stored encrypted file package {file_id}")
        await manager.send_to_user(
            body.receiver,
            {
                "type": "file",
                "sender": actor,
                "receiver": body.receiver,
                "file_id": file_id,
                "manifest": manifest,
                "created_at": _now(),
            },
        )
        return {"status": "stored", "file_id": file_id}

    @app.get("/api/files/{file_id}")
    def download_file_package(file_id: str, actor: str = Depends(current_username)):
        user = user_by_username(actor)
        row = conn.execute(
            """
            SELECT f.package_json, u.username AS sender
            FROM files f
            JOIN users u ON u.id = f.sender_id
            WHERE f.file_id = ? AND f.receiver_id = ?
            """,
            (file_id, user["id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="file package not found")
        audit(actor, "file_download", file_id, "success", "returned encrypted file package")
        return {"sender": row["sender"], "package": json.loads(row["package_json"])}

    @app.get("/api/audit/export")
    def audit_export(actor: str = Depends(current_username)):
        rows = conn.execute(
            "SELECT actor, action, target, result, detail, created_at FROM audit_logs ORDER BY id ASC"
        ).fetchall()
        return {"logs": [dict(row) for row in rows]}

    return app


app = create_app()
