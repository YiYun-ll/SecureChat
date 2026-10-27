from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

from . import crypto_utils as crypto


class MessageSecurityError(Exception):
    """Raised when a secure message fails signature, integrity, or replay checks."""


@dataclass
class SecureSession:
    session_id: str
    sender: str
    receiver: str
    session_key: bytes
    envelope: dict
    next_seq: int = 1


@dataclass
class ReplayTracker:
    last_seen: dict[str, int] = field(default_factory=dict)

    def check_and_mark(self, session_id: str, seq: int) -> None:
        last = self.last_seen.get(session_id, 0)
        if seq <= last:
            raise MessageSecurityError("replay detected")
        self.last_seen[session_id] = seq


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _session_signing_payload(envelope: dict) -> bytes:
    data = {key: value for key, value in envelope.items() if key != "signature_b64"}
    return crypto.canonical_json(data)


def create_session(
    sender: str,
    receiver: str,
    sender_signing_private_key: rsa.RSAPrivateKey,
    receiver_encryption_public_key: rsa.RSAPublicKey,
) -> SecureSession:
    session_key = crypto.random_bytes(32)
    created_at = _now()
    envelope = {
        "session_id": str(uuid4()),
        "from": sender,
        "to": receiver,
        "algorithm": "AES-256-GCM",
        "wrapped_session_key_b64": crypto.b64e(crypto.rsa_oaep_encrypt(receiver_encryption_public_key, session_key)),
        "key_wrap_algorithm": "RSA-OAEP-SHA256",
        "receiver_encryption_key_fingerprint": crypto.fingerprint_public_key(receiver_encryption_public_key),
        "created_at": created_at,
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
    }
    envelope["signature_b64"] = crypto.b64e(crypto.rsa_pss_sign(sender_signing_private_key, _session_signing_payload(envelope)))
    return SecureSession(envelope["session_id"], sender, receiver, session_key, envelope)


def accept_session(
    session: SecureSession | dict,
    sender_signing_public_key: rsa.RSAPublicKey,
    receiver_encryption_private_key: rsa.RSAPrivateKey,
) -> SecureSession:
    envelope = copy.deepcopy(session.envelope if isinstance(session, SecureSession) else session)
    try:
        crypto.rsa_pss_verify(
            sender_signing_public_key,
            _session_signing_payload(envelope),
            crypto.b64d(envelope["signature_b64"]),
        )
    except InvalidSignature as exc:
        raise MessageSecurityError("session signature verification failed") from exc
    try:
        session_key = crypto.rsa_oaep_decrypt(receiver_encryption_private_key, crypto.b64d(envelope["wrapped_session_key_b64"]))
    except (ValueError, TypeError) as exc:
        raise MessageSecurityError("session key unwrap failed") from exc
    return SecureSession(envelope["session_id"], envelope["from"], envelope["to"], session_key, envelope)


def _aad(packet: dict) -> bytes:
    return crypto.canonical_json(
        {
            "message_id": packet["message_id"],
            "session_id": packet["session_id"],
            "sender": packet["sender"],
            "receiver": packet["receiver"],
            "seq": packet["seq"],
        }
    )


def _message_signing_payload(packet: dict) -> bytes:
    data = {key: value for key, value in packet.items() if key != "signature_b64"}
    return crypto.canonical_json(data)


def encrypt_text_message(
    session: SecureSession,
    sender_signing_private_key: rsa.RSAPrivateKey,
    plaintext: str,
) -> dict:
    packet = {
        "message_id": str(uuid4()),
        "session_id": session.session_id,
        "sender": session.sender,
        "receiver": session.receiver,
        "seq": session.next_seq,
        "timestamp": _now(),
    }
    encrypted = crypto.aes_gcm_encrypt(session.session_key, plaintext.encode("utf-8"), _aad(packet))
    packet.update(
        {
            "nonce_b64": crypto.b64e(encrypted.nonce),
            "ciphertext_b64": crypto.b64e(encrypted.ciphertext),
            "tag_b64": crypto.b64e(encrypted.tag),
            "digest": crypto.sha256_label(encrypted.nonce + encrypted.ciphertext + encrypted.tag),
        }
    )
    packet["signature_b64"] = crypto.b64e(crypto.rsa_pss_sign(sender_signing_private_key, _message_signing_payload(packet)))
    session.next_seq += 1
    return packet


def decrypt_text_message(
    packet: dict,
    session: SecureSession,
    sender_signing_public_key: rsa.RSAPublicKey,
    replay_tracker: ReplayTracker,
) -> str:
    try:
        if packet["session_id"] != session.session_id:
            raise MessageSecurityError("wrong session")
        if packet["sender"] != session.sender or packet["receiver"] != session.receiver:
            raise MessageSecurityError("wrong peer metadata")
        crypto.rsa_pss_verify(sender_signing_public_key, _message_signing_payload(packet), crypto.b64d(packet["signature_b64"]))
        nonce = crypto.b64d(packet["nonce_b64"])
        ciphertext = crypto.b64d(packet["ciphertext_b64"])
        tag = crypto.b64d(packet["tag_b64"])
        if packet["digest"] != crypto.sha256_label(nonce + ciphertext + tag):
            raise MessageSecurityError("digest mismatch")
        plaintext = crypto.aes_gcm_decrypt(session.session_key, nonce, ciphertext, tag, _aad(packet))
        replay_tracker.check_and_mark(packet["session_id"], int(packet["seq"]))
        return plaintext.decode("utf-8")
    except MessageSecurityError:
        raise
    except Exception as exc:
        raise MessageSecurityError("message verification failed") from exc
