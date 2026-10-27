from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class SecurityError(Exception):
    """Raised when a cryptographic verification or decryption check fails."""


@dataclass(frozen=True)
class AesGcmCiphertext:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def random_bytes(length: int) -> bytes:
    return os.urandom(length)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_private_key_pem(pem: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key_pem(pem: str | bytes) -> rsa.RSAPublicKey:
    raw = pem.encode("utf-8") if isinstance(pem, str) else pem
    return serialization.load_pem_public_key(raw)


def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    try:
        return public_key.encrypt(data, oaep_padding)
    except ValueError:
        content_key = random_bytes(32)
        encrypted = aes_gcm_encrypt(content_key, data, b"RSA-OAEP-HYBRID-SHA256")
        wrapped_key = public_key.encrypt(content_key, oaep_padding)
        envelope = {
            "version": 1,
            "wrapped_key_b64": b64e(wrapped_key),
            "nonce_b64": b64e(encrypted.nonce),
            "ciphertext_b64": b64e(encrypted.ciphertext),
            "tag_b64": b64e(encrypted.tag),
        }
        return b"HYBRID1." + canonical_json(envelope)


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    if ciphertext.startswith(b"HYBRID1."):
        try:
            envelope = json.loads(ciphertext[len(b"HYBRID1.") :].decode("utf-8"))
            content_key = private_key.decrypt(
                b64d(envelope["wrapped_key_b64"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return aes_gcm_decrypt(
                content_key,
                b64d(envelope["nonce_b64"]),
                b64d(envelope["ciphertext_b64"]),
                b64d(envelope["tag_b64"]),
                b"RSA-OAEP-HYBRID-SHA256",
            )
        except Exception as exc:
            raise SecurityError("hybrid RSA-OAEP decryption failed") from exc
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise SecurityError("RSA-OAEP decryption failed") from exc


def rsa_pss_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> None:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SecurityError("signature verification failed") from exc


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> AesGcmCiphertext:
    nonce = random_bytes(12)
    encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
    return AesGcmCiphertext(nonce=nonce, ciphertext=encrypted[:-16], tag=encrypted[-16:])


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except Exception as exc:
        raise SecurityError("AES-GCM authentication failed") from exc


def sha256_bytes(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def sha256_hex(data: bytes) -> str:
    return sha256_bytes(data).hex()


def sha256_label(data: bytes) -> str:
    return "SHA256:" + sha256_hex(data)


def fingerprint_public_key(public_key: rsa.RSAPublicKey) -> str:
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_label(public_der)


def derive_storage_key(password: str, salt: bytes, params: dict[str, Any]) -> bytes:
    name = params.get("name", "scrypt")
    if name == "argon2id":
        try:
            from argon2.low_level import Type, hash_secret_raw

            return hash_secret_raw(
                password.encode("utf-8"),
                salt,
                time_cost=int(params.get("time_cost", 3)),
                memory_cost=int(params.get("memory_cost", 65536)),
                parallelism=int(params.get("parallelism", 2)),
                hash_len=32,
                type=Type.ID,
            )
        except ModuleNotFoundError:
            pass

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=int(params.get("n", 2**14)),
        r=int(params.get("r", 8)),
        p=int(params.get("p", 1)),
    )
    return kdf.derive(password.encode("utf-8"))


def default_kdf_params() -> dict[str, Any]:
    try:
        import argon2  # noqa: F401

        return {"name": "argon2id", "memory_cost": 65536, "time_cost": 3, "parallelism": 2}
    except ModuleNotFoundError:
        return {"name": "scrypt", "n": 2**14, "r": 8, "p": 1}
