from fastapi.testclient import TestClient

from client.api_client import SecureChatApiClient
from common.secure_chat import key_store
from server.main import create_app


def test_api_client_register_login_and_fetch_offline_message(tmp_path):
    transport = TestClient(create_app(tmp_path / "server.sqlite"))
    alice = key_store.create_key_store("alice", "alice-password", tmp_path / "alice.json")
    bob = key_store.create_key_store("bob", "bob-password", tmp_path / "bob.json")
    alice_client = SecureChatApiClient(transport)
    bob_client = SecureChatApiClient(transport)

    alice_client.register(alice, "alice-password")
    bob_client.register(bob, "bob-password")

    alice_client.login(alice, "alice-password")
    bob_client.login(bob, "bob-password")
    bob_keys = alice_client.get_public_keys("bob")
    alice_client.request_friend("bob")
    bob_client.accept_friend("alice")
    alice_client.store_offline_message("bob", {"ciphertext_b64": "encrypted-only", "sender": "alice"})

    assert bob_keys["username"] == "bob"
    assert bob_client.fetch_offline_messages()["messages"][0]["packet"]["ciphertext_b64"] == "encrypted-only"
