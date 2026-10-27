from client.local_store import LocalChatStore


def test_local_store_saves_friend_session_messages_and_files(tmp_path):
    store = LocalChatStore(tmp_path / "client.sqlite")
    friend = {
        "username": "bob",
        "signing_public_key_pem": "signing-pem",
        "encryption_public_key_pem": "encryption-pem",
        "signing_fingerprint": "SHA256:sign",
        "encryption_fingerprint": "SHA256:enc",
        "trust_status": "trusted",
    }

    store.upsert_friend(**friend)
    store.save_session("bob", {"session_id": "s1", "from": "alice", "to": "bob"})
    store.save_message(
        peer="bob",
        direction="out",
        packet={"message_id": "m1", "ciphertext_b64": "secret"},
        plaintext="hello bob",
        status="verified",
    )
    store.save_file_record(
        file_id="f1",
        peer="bob",
        direction="out",
        manifest={"file_id": "f1", "safe_filename": "report.txt"},
        local_path="/tmp/report.txt",
        status="sent",
    )

    assert store.get_friend("bob")["encryption_fingerprint"] == "SHA256:enc"
    assert store.get_session("bob")["session_id"] == "s1"
    assert store.list_messages("bob")[0]["plaintext"] == "hello bob"
    assert store.list_files("bob")[0]["manifest"]["safe_filename"] == "report.txt"


def test_local_store_updates_existing_friend_without_duplicate(tmp_path):
    store = LocalChatStore(tmp_path / "client.sqlite")

    store.upsert_friend(
        username="bob",
        signing_public_key_pem="old-sign",
        encryption_public_key_pem="old-enc",
        signing_fingerprint="SHA256:old-sign",
        encryption_fingerprint="SHA256:old-enc",
        trust_status="pending",
    )
    store.upsert_friend(
        username="bob",
        signing_public_key_pem="new-sign",
        encryption_public_key_pem="new-enc",
        signing_fingerprint="SHA256:new-sign",
        encryption_fingerprint="SHA256:new-enc",
        trust_status="trusted",
    )

    friends = store.list_friends()
    assert len(friends) == 1
    assert friends[0]["trust_status"] == "trusted"
    assert friends[0]["signing_public_key_pem"] == "new-sign"
