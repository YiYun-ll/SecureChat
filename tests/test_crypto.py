import pytest

from common.secure_chat import crypto_utils as crypto


def test_rsa_oaep_roundtrip_for_session_key():
    private_key, public_key = crypto.generate_rsa_keypair()
    session_key = crypto.random_bytes(32)

    wrapped = crypto.rsa_oaep_encrypt(public_key, session_key)

    assert wrapped != session_key
    assert crypto.rsa_oaep_decrypt(private_key, wrapped) == session_key


def test_rsa_pss_signature_rejects_tampered_payload():
    private_key, public_key = crypto.generate_rsa_keypair()
    payload = b"sender=alice&seq=1"
    signature = crypto.rsa_pss_sign(private_key, payload)

    crypto.rsa_pss_verify(public_key, payload, signature)
    with pytest.raises(crypto.SecurityError):
        crypto.rsa_pss_verify(public_key, b"sender=mallory&seq=1", signature)


def test_aes_gcm_rejects_tampered_ciphertext():
    key = crypto.random_bytes(32)
    aad = b"session=s1;seq=1"
    encrypted = crypto.aes_gcm_encrypt(key, b"hello bob", aad)
    tampered = encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1])

    with pytest.raises(crypto.SecurityError):
        crypto.aes_gcm_decrypt(key, encrypted.nonce, tampered, encrypted.tag, aad)


def test_public_key_fingerprint_is_stable():
    private_key, public_key = crypto.generate_rsa_keypair()
    pem = crypto.public_key_to_pem(public_key)
    loaded = crypto.load_public_key_pem(pem)

    assert crypto.fingerprint_public_key(public_key) == crypto.fingerprint_public_key(loaded)
    assert "SHA256:" in crypto.fingerprint_public_key(public_key)
