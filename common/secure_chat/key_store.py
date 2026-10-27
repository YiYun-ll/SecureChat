from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from . import crypto_utils as crypto


class KeyStoreError(Exception):
    """Raised when local key-store creation or unlock fails."""


@dataclass
class UnlockedKeyStore:
    owner: str
    signing_private_key: rsa.RSAPrivateKey
    signing_public_key: rsa.RSAPublicKey
    encryption_private_key: rsa.RSAPrivateKey
    encryption_public_key: rsa.RSAPublicKey
    path: Path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_key_store(owner: str, password: str, path: str | Path) -> UnlockedKeyStore:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    signing_private, signing_public = crypto.generate_rsa_keypair()
    encryption_private, encryption_public = crypto.generate_rsa_keypair()
    private_payload = {
        "signing_private_key_pem_b64": crypto.b64e(crypto.private_key_to_pem(signing_private)),
        "encryption_private_key_pem_b64": crypto.b64e(crypto.private_key_to_pem(encryption_private)),
    }
    kdf = crypto.default_kdf_params()
    salt = crypto.random_bytes(16)
    key = crypto.derive_storage_key(password, salt, kdf)
    encrypted = crypto.aes_gcm_encrypt(key, crypto.canonical_json(private_payload), owner.encode("utf-8"))
    document = {
        "version": 1,
        "owner": owner,
        "kdf": {**kdf, "salt_b64": crypto.b64e(salt)},
        "cipher": {
            "name": "AES-256-GCM",
            "nonce_b64": crypto.b64e(encrypted.nonce),
            "tag_b64": crypto.b64e(encrypted.tag),
            "ciphertext_b64": crypto.b64e(encrypted.ciphertext),
        },
        "public_keys": {
            "signing_public_key_pem": crypto.public_key_to_pem(signing_public),
            "encryption_public_key_pem": crypto.public_key_to_pem(encryption_public),
        },
        "public_fingerprints": {
            "signing_key": crypto.fingerprint_public_key(signing_public),
            "encryption_key": crypto.fingerprint_public_key(encryption_public),
        },
        "created_at": _now(),
    }
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    return UnlockedKeyStore(owner, signing_private, signing_public, encryption_private, encryption_public, path)


def unlock_key_store(path: str | Path, password: str) -> UnlockedKeyStore:
    path = Path(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    try:
        kdf = dict(document["kdf"])
        salt = crypto.b64d(kdf.pop("salt_b64"))
        key = crypto.derive_storage_key(password, salt, kdf)
        cipher = document["cipher"]
        plaintext = crypto.aes_gcm_decrypt(
            key,
            crypto.b64d(cipher["nonce_b64"]),
            crypto.b64d(cipher["ciphertext_b64"]),
            crypto.b64d(cipher["tag_b64"]),
            document["owner"].encode("utf-8"),
        )
        private_payload = json.loads(plaintext.decode("utf-8"))
        signing_private = crypto.load_private_key_pem(crypto.b64d(private_payload["signing_private_key_pem_b64"]))
        encryption_private = crypto.load_private_key_pem(
            crypto.b64d(private_payload["encryption_private_key_pem_b64"])
        )
        signing_public = crypto.load_public_key_pem(document["public_keys"]["signing_public_key_pem"])
        encryption_public = crypto.load_public_key_pem(document["public_keys"]["encryption_public_key_pem"])
        return UnlockedKeyStore(
            document["owner"],
            signing_private,
            signing_public,
            encryption_private,
            encryption_public,
            path,
        )
    except Exception as exc:
        raise KeyStoreError("cannot unlock local key store") from exc


def export_public_key_bundle(store: UnlockedKeyStore) -> dict[str, str | int]:
    return {
        "type": "secure-chat-public-key",
        "username": store.owner,
        "signing_public_key_pem": crypto.public_key_to_pem(store.signing_public_key),
        "encryption_public_key_pem": crypto.public_key_to_pem(store.encryption_public_key),
        "signing_fingerprint": crypto.fingerprint_public_key(store.signing_public_key),
        "encryption_fingerprint": crypto.fingerprint_public_key(store.encryption_public_key),
        "created_at": _now(),
        "key_version": 1,
    }
