import json

from fastapi.testclient import TestClient

from common.secure_chat import crypto_utils as crypto
from common.secure_chat import key_store, messages
from server.main import create_app


def _encrypted_payload(client: TestClient, payload: dict) -> str:
    server_key_response = client.get("/api/auth/server-key")
    server_key_response.raise_for_status()
    public_key = crypto.load_public_key_pem(server_key_response.json()["server_public_key_pem"])
    return crypto.b64e(crypto.rsa_oaep_encrypt(public_key, crypto.canonical_json(payload)))


def _register(client: TestClient, tmp_path, username: str, password: str):
    store = key_store.create_key_store(username, password, tmp_path / f"{username}.json")
    bundle = key_store.export_public_key_bundle(store)
    encrypted = _encrypted_payload(
        client,
        {
            "username": username,
            "password": password,
            "signing_public_key_pem": bundle["signing_public_key_pem"],
            "encryption_public_key_pem": bundle["encryption_public_key_pem"],
        },
    )
    response = client.post("/api/auth/register", json={"encrypted_payload_b64": encrypted})
    response.raise_for_status()
    return store


def _login(client: TestClient, store, password: str) -> str:
    start = client.post("/api/auth/login/start", json={"username": store.owner})
    start.raise_for_status()
    login_id = start.json()["login_id"]
    server_key = crypto.load_public_key_pem(start.json()["server_public_key_pem"])
    encrypted_login = crypto.b64e(
        crypto.rsa_oaep_encrypt(
            server_key,
            crypto.canonical_json({"username": store.owner, "password": password, "client_nonce": "n1"}),
        )
    )
    assert password not in json.dumps({"encrypted_payload_b64": encrypted_login})
    challenge_response = client.post(
        "/api/auth/login/password",
        json={"login_id": login_id, "encrypted_payload_b64": encrypted_login},
    )
    challenge_response.raise_for_status()
    signature = crypto.b64e(
        crypto.rsa_pss_sign(store.signing_private_key, challenge_response.json()["identity_challenge"].encode("utf-8"))
    )
    proof = client.post(
        "/api/auth/login/prove-key",
        json={"login_id": login_id, "username": store.owner, "signature_b64": signature},
    )
    proof.raise_for_status()
    return proof.json()["access_token"]


def test_register_login_key_directory_friends_and_offline_message(tmp_path):
    client = TestClient(create_app(tmp_path / "server.sqlite"))
    alice = _register(client, tmp_path, "alice", "alice-password")
    bob = _register(client, tmp_path, "bob", "bob-password")
    alice_token = _login(client, alice, "alice-password")
    bob_token = _login(client, bob, "bob-password")

    key_response = client.get("/api/keys/bob", headers={"Authorization": f"Bearer {alice_token}"})
    key_response.raise_for_status()
    assert key_response.json()["username"] == "bob"
    assert key_response.json()["encryption_fingerprint"].startswith("SHA256:")
    assert key_response.json()["directory_signature_b64"]

    request = client.post(
        "/api/friends/request",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"friend_username": "bob"},
    )
    request.raise_for_status()
    accepted = client.post(
        "/api/friends/accept",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"friend_username": "alice"},
    )
    accepted.raise_for_status()

    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    packet = messages.encrypt_text_message(session, alice.signing_private_key, "offline hello")
    stored = client.post(
        "/api/messages/offline",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"receiver": "bob", "packet": packet},
    )
    stored.raise_for_status()
    offline = client.get("/api/messages/offline", headers={"Authorization": f"Bearer {bob_token}"})
    offline.raise_for_status()
    assert offline.json()["messages"][0]["packet"]["ciphertext_b64"] == packet["ciphertext_b64"]
    assert "offline hello" not in json.dumps(offline.json(), ensure_ascii=False)


def test_wrong_private_key_proof_fails(tmp_path):
    client = TestClient(create_app(tmp_path / "server.sqlite"))
    alice = _register(client, tmp_path, "alice", "alice-password")
    mallory = key_store.create_key_store("mallory", "pw", tmp_path / "mallory.json")
    start = client.post("/api/auth/login/start", json={"username": "alice"}).json()
    encrypted_login = crypto.b64e(
        crypto.rsa_oaep_encrypt(
            crypto.load_public_key_pem(start["server_public_key_pem"]),
            crypto.canonical_json({"username": "alice", "password": "alice-password", "client_nonce": "n1"}),
        )
    )
    challenge = client.post(
        "/api/auth/login/password",
        json={"login_id": start["login_id"], "encrypted_payload_b64": encrypted_login},
    ).json()["identity_challenge"]
    bad_signature = crypto.b64e(crypto.rsa_pss_sign(mallory.signing_private_key, challenge.encode("utf-8")))

    response = client.post(
        "/api/auth/login/prove-key",
        json={"login_id": start["login_id"], "username": alice.owner, "signature_b64": bad_signature},
    )

    assert response.status_code == 401


def test_websocket_receives_realtime_offline_message_event(tmp_path):
    client = TestClient(create_app(tmp_path / "server.sqlite"))
    alice = _register(client, tmp_path, "alice", "alice-password")
    bob = _register(client, tmp_path, "bob", "bob-password")
    alice_token = _login(client, alice, "alice-password")
    bob_token = _login(client, bob, "bob-password")
    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    packet = messages.encrypt_text_message(session, alice.signing_private_key, "live secret")

    with client.websocket_connect(f"/ws/{bob_token}") as websocket:
        stored = client.post(
            "/api/messages/offline",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={"receiver": "bob", "packet": packet},
        )
        stored.raise_for_status()
        event = websocket.receive_json()

    assert event["type"] == "message"
    assert event["sender"] == "alice"
    assert event["packet"]["ciphertext_b64"] == packet["ciphertext_b64"]
    assert "live secret" not in json.dumps(event, ensure_ascii=False)


def test_websocket_receives_realtime_file_event(tmp_path):
    client = TestClient(create_app(tmp_path / "server.sqlite"))
    alice = _register(client, tmp_path, "alice", "alice-password")
    bob = _register(client, tmp_path, "bob", "bob-password")
    alice_token = _login(client, alice, "alice-password")
    bob_token = _login(client, bob, "bob-password")
    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    package = {
        "session_envelope": session.envelope,
        "manifest": {
            "file_id": "file-1",
            "session_id": session.session_id,
            "safe_filename": "report.txt",
            "cipher_sha256": "cipher-hash",
            "size": 12,
        },
        "ciphertext_b64": "encrypted-file-only",
    }

    with client.websocket_connect(f"/ws/{bob_token}") as websocket:
        stored = client.post(
            "/api/files/upload",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={"receiver": "bob", "package": package},
        )
        stored.raise_for_status()
        event = websocket.receive_json()

    assert event["type"] == "file"
    assert event["sender"] == "alice"
    assert event["file_id"] == "file-1"
    assert event["manifest"]["safe_filename"] == "report.txt"
