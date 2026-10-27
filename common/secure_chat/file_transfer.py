from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import rsa

from . import crypto_utils as crypto
from . import file_scanner
from .messages import SecureSession


class FileTransferError(Exception):
    """Raised when a file package cannot be verified, decrypted, or scanned."""


def _manifest_payload(package: dict) -> bytes:
    manifest = dict(package["manifest"])
    manifest.pop("signature_b64", None)
    return crypto.canonical_json(manifest)


def encrypt_file_for_session(
    path: str | Path,
    session: SecureSession,
    sender_signing_private_key: rsa.RSAPrivateKey,
) -> dict:
    path = Path(path)
    scan = file_scanner.scan_file(path)
    if scan.status != "passed":
        raise FileTransferError("file scan blocked transfer")

    plaintext = path.read_bytes()
    file_key = crypto.random_bytes(32)
    encrypted_file_key = crypto.aes_gcm_encrypt(session.session_key, file_key, session.session_id.encode("utf-8"))
    encrypted_payload = crypto.aes_gcm_encrypt(file_key, plaintext, session.session_id.encode("utf-8"))
    manifest = {
        "file_id": str(uuid4()),
        "session_id": session.session_id,
        "sender": session.sender,
        "receiver": session.receiver,
        "original_filename": path.name,
        "safe_filename": scan.safe_filename,
        "size": scan.size,
        "plain_sha256": scan.sha256,
        "cipher_sha256": crypto.sha256_hex(encrypted_payload.ciphertext),
        "encryption": "AES-256-GCM",
        "wrapped_file_key": {
            "nonce_b64": crypto.b64e(encrypted_file_key.nonce),
            "ciphertext_b64": crypto.b64e(encrypted_file_key.ciphertext),
            "tag_b64": crypto.b64e(encrypted_file_key.tag),
        },
        "payload_nonce_b64": crypto.b64e(encrypted_payload.nonce),
        "payload_tag_b64": crypto.b64e(encrypted_payload.tag),
        "scan_result": {"status": scan.status, "rules": scan.rules},
    }
    package = {"manifest": manifest, "ciphertext_b64": crypto.b64e(encrypted_payload.ciphertext)}
    package["manifest"]["signature_b64"] = crypto.b64e(
        crypto.rsa_pss_sign(sender_signing_private_key, _manifest_payload(package))
    )
    return package


def decrypt_file_from_package(
    package: dict,
    session: SecureSession,
    sender_signing_public_key: rsa.RSAPublicKey,
    output_path: str | Path,
) -> None:
    try:
        manifest = package["manifest"]
        crypto.rsa_pss_verify(sender_signing_public_key, _manifest_payload(package), crypto.b64d(manifest["signature_b64"]))
        ciphertext = crypto.b64d(package["ciphertext_b64"])
        if crypto.sha256_hex(ciphertext) != manifest["cipher_sha256"]:
            raise FileTransferError("ciphertext hash mismatch")
        wrapped = manifest["wrapped_file_key"]
        file_key = crypto.aes_gcm_decrypt(
            session.session_key,
            crypto.b64d(wrapped["nonce_b64"]),
            crypto.b64d(wrapped["ciphertext_b64"]),
            crypto.b64d(wrapped["tag_b64"]),
            session.session_id.encode("utf-8"),
        )
        plaintext = crypto.aes_gcm_decrypt(
            file_key,
            crypto.b64d(manifest["payload_nonce_b64"]),
            ciphertext,
            crypto.b64d(manifest["payload_tag_b64"]),
            session.session_id.encode("utf-8"),
        )
        if crypto.sha256_hex(plaintext) != manifest["plain_sha256"]:
            raise FileTransferError("plaintext hash mismatch")
        output_path = Path(output_path)
        output_path.write_bytes(plaintext)
        report = file_scanner.scan_file(output_path)
        if report.status != "passed":
            output_path.unlink(missing_ok=True)
            raise FileTransferError("download scan blocked file")
    except FileTransferError:
        raise
    except Exception as exc:
        raise FileTransferError("file package verification failed") from exc
