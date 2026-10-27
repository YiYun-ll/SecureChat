import copy

import pytest

from common.secure_chat import key_store, messages


def _users(tmp_path):
    alice = key_store.create_key_store("alice", "pw1", tmp_path / "alice.json")
    bob = key_store.create_key_store("bob", "pw2", tmp_path / "bob.json")
    return alice, bob


def test_secure_message_roundtrip(tmp_path):
    alice, bob = _users(tmp_path)
    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    receiver_session = messages.accept_session(session, alice.signing_public_key, bob.encryption_private_key)

    packet = messages.encrypt_text_message(session, alice.signing_private_key, "hello bob")

    tracker = messages.ReplayTracker()
    assert messages.decrypt_text_message(packet, receiver_session, alice.signing_public_key, tracker) == "hello bob"


def test_ciphertext_tamper_is_rejected(tmp_path):
    alice, bob = _users(tmp_path)
    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    receiver_session = messages.accept_session(session, alice.signing_public_key, bob.encryption_private_key)
    packet = messages.encrypt_text_message(session, alice.signing_private_key, "hello bob")
    packet["ciphertext_b64"] = packet["ciphertext_b64"][:-2] + "AA"

    with pytest.raises(messages.MessageSecurityError):
        messages.decrypt_text_message(packet, receiver_session, alice.signing_public_key, messages.ReplayTracker())


def test_metadata_tamper_is_rejected(tmp_path):
    alice, bob = _users(tmp_path)
    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    receiver_session = messages.accept_session(session, alice.signing_public_key, bob.encryption_private_key)
    packet = messages.encrypt_text_message(session, alice.signing_private_key, "hello bob")
    packet["sender"] = "mallory"

    with pytest.raises(messages.MessageSecurityError):
        messages.decrypt_text_message(packet, receiver_session, alice.signing_public_key, messages.ReplayTracker())


def test_replay_is_rejected(tmp_path):
    alice, bob = _users(tmp_path)
    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    receiver_session = messages.accept_session(session, alice.signing_public_key, bob.encryption_private_key)
    packet = messages.encrypt_text_message(session, alice.signing_private_key, "hello bob")
    tracker = messages.ReplayTracker()

    assert messages.decrypt_text_message(packet, receiver_session, alice.signing_public_key, tracker) == "hello bob"
    with pytest.raises(messages.MessageSecurityError):
        messages.decrypt_text_message(copy.deepcopy(packet), receiver_session, alice.signing_public_key, tracker)
