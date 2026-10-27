import json

import pytest

from common.secure_chat import key_store


def test_key_store_encrypts_private_keys_on_disk(tmp_path):
    store_path = tmp_path / "alice_key_store.json"

    created = key_store.create_key_store("alice", "correct horse battery staple", store_path)
    raw = store_path.read_text(encoding="utf-8")
    data = json.loads(raw)

    assert created.owner == "alice"
    assert data["owner"] == "alice"
    assert "BEGIN PRIVATE KEY" not in raw
    assert data["cipher"]["name"] == "AES-256-GCM"
    assert key_store.unlock_key_store(store_path, "correct horse battery staple").owner == "alice"


def test_key_store_rejects_wrong_password(tmp_path):
    store_path = tmp_path / "bob_key_store.json"
    key_store.create_key_store("bob", "right-password", store_path)

    with pytest.raises(key_store.KeyStoreError):
        key_store.unlock_key_store(store_path, "wrong-password")


def test_public_key_export_has_matching_fingerprints(tmp_path):
    store_path = tmp_path / "alice_key_store.json"
    unlocked = key_store.create_key_store("alice", "password", store_path)

    exported = key_store.export_public_key_bundle(unlocked)

    assert exported["type"] == "secure-chat-public-key"
    assert exported["username"] == "alice"
    assert exported["signing_fingerprint"].startswith("SHA256:")
    assert exported["encryption_fingerprint"].startswith("SHA256:")
