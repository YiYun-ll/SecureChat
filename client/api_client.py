from __future__ import annotations

from typing import Any

import httpx

from common.secure_chat import crypto_utils as crypto
from common.secure_chat.key_store import UnlockedKeyStore, export_public_key_bundle


class SecureChatApiClient:
    """Small synchronous client for the FastAPI secure chat server."""

    def __init__(self, base_url_or_transport: str | Any = "http://127.0.0.1:8000"):
        if isinstance(base_url_or_transport, str):
            # Local chat traffic should not follow HTTP(S)/SOCKS proxy env vars.
            self._client = httpx.Client(
                base_url=base_url_or_transport.rstrip("/"),
                trust_env=False,
            )
        else:
            self._client = base_url_or_transport
        self.access_token: str | None = None

    def _headers(self) -> dict[str, str]:
        if not self.access_token:
            return {}
        return {"Authorization": f"Bearer {self.access_token}"}

    def _encrypt_for_server(self, payload: dict[str, Any], server_key_pem: str | None = None) -> str:
        if server_key_pem is None:
            response = self._client.get("/api/auth/server-key")
            response.raise_for_status()
            server_key_pem = response.json()["server_public_key_pem"]
        server_key = crypto.load_public_key_pem(server_key_pem)
        return crypto.b64e(crypto.rsa_oaep_encrypt(server_key, crypto.canonical_json(payload)))

    def register(self, store: UnlockedKeyStore, password: str) -> dict[str, Any]:
        bundle = export_public_key_bundle(store)
        encrypted_payload = self._encrypt_for_server(
            {
                "username": store.owner,
                "password": password,
                "signing_public_key_pem": bundle["signing_public_key_pem"],
                "encryption_public_key_pem": bundle["encryption_public_key_pem"],
            }
        )
        response = self._client.post("/api/auth/register", json={"encrypted_payload_b64": encrypted_payload})
        response.raise_for_status()
        return response.json()

    def login(self, store: UnlockedKeyStore, password: str) -> str:
        start = self._client.post("/api/auth/login/start", json={"username": store.owner})
        start.raise_for_status()
        start_data = start.json()
        encrypted_payload = self._encrypt_for_server(
            {"username": store.owner, "password": password, "client_nonce": crypto.b64e(crypto.random_bytes(16))},
            start_data["server_public_key_pem"],
        )
        challenge_response = self._client.post(
            "/api/auth/login/password",
            json={"login_id": start_data["login_id"], "encrypted_payload_b64": encrypted_payload},
        )
        challenge_response.raise_for_status()
        challenge = challenge_response.json()["identity_challenge"]
        signature = crypto.b64e(crypto.rsa_pss_sign(store.signing_private_key, challenge.encode("utf-8")))
        proof = self._client.post(
            "/api/auth/login/prove-key",
            json={"login_id": start_data["login_id"], "username": store.owner, "signature_b64": signature},
        )
        proof.raise_for_status()
        self.access_token = proof.json()["access_token"]
        return self.access_token

    def get_public_keys(self, username: str) -> dict[str, Any]:
        response = self._client.get(f"/api/keys/{username}", headers=self._headers())
        response.raise_for_status()
        return response.json()

    def request_friend(self, friend_username: str) -> dict[str, Any]:
        response = self._client.post(
            "/api/friends/request",
            headers=self._headers(),
            json={"friend_username": friend_username},
        )
        response.raise_for_status()
        return response.json()

    def accept_friend(self, friend_username: str) -> dict[str, Any]:
        response = self._client.post(
            "/api/friends/accept",
            headers=self._headers(),
            json={"friend_username": friend_username},
        )
        response.raise_for_status()
        return response.json()

    def store_offline_message(self, receiver: str, packet: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(
            "/api/messages/offline",
            headers=self._headers(),
            json={"receiver": receiver, "packet": packet},
        )
        response.raise_for_status()
        return response.json()

    def fetch_offline_messages(self) -> dict[str, Any]:
        response = self._client.get("/api/messages/offline", headers=self._headers())
        response.raise_for_status()
        return response.json()

    def upload_file_package(self, receiver: str, package: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(
            "/api/files/upload",
            headers=self._headers(),
            json={"receiver": receiver, "package": package},
        )
        response.raise_for_status()
        return response.json()

    def download_file_package(self, file_id: str) -> dict[str, Any]:
        response = self._client.get(f"/api/files/{file_id}", headers=self._headers())
        response.raise_for_status()
        return response.json()
