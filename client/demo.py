from __future__ import annotations

import tempfile
from pathlib import Path

from common.secure_chat import file_scanner, file_transfer, key_store, messages


def run_demo() -> None:
    with tempfile.TemporaryDirectory(prefix="secure-chat-demo-") as tmp:
        root = Path(tmp)
        alice = key_store.create_key_store("alice", "alice-password", root / "alice_key_store.json")
        bob = key_store.create_key_store("bob", "bob-password", root / "bob_key_store.json")

        session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
        bob_session = messages.accept_session(session, alice.signing_public_key, bob.encryption_private_key)
        packet = messages.encrypt_text_message(session, alice.signing_private_key, "你好 Bob，这是一条端到端加密消息。")
        plaintext = messages.decrypt_text_message(packet, bob_session, alice.signing_public_key, messages.ReplayTracker())

        tampered = dict(packet)
        tampered["ciphertext_b64"] = tampered["ciphertext_b64"][:-2] + "AA"
        try:
            messages.decrypt_text_message(tampered, bob_session, alice.signing_public_key, messages.ReplayTracker())
            tamper_result = "unexpected-pass"
        except messages.MessageSecurityError:
            tamper_result = "blocked"

        safe_file = root / "report.txt"
        safe_file.write_text("安全文件传输演示内容", encoding="utf-8")
        package = file_transfer.encrypt_file_for_session(safe_file, session, alice.signing_private_key)
        downloaded = root / "downloaded-report.txt"
        file_transfer.decrypt_file_from_package(package, bob_session, alice.signing_public_key, downloaded)

        eicar = root / "eicar.txt"
        eicar.write_text(file_scanner.EICAR_TEST_STRING, encoding="utf-8")
        eicar_report = file_scanner.scan_file(eicar)

        print("Secure Chat demo")
        print(f"- Alice -> Bob plaintext after verification: {plaintext}")
        print(f"- Tampered message result: {tamper_result}")
        print(f"- Encrypted file restored: {downloaded.read_text(encoding='utf-8')}")
        print(f"- EICAR scan status: {eicar_report.status}, rules={','.join(eicar_report.rules)}")
        print(f"- Alice signing fingerprint: {key_store.export_public_key_bundle(alice)['signing_fingerprint']}")
        print(f"- Bob encryption fingerprint: {key_store.export_public_key_bundle(bob)['encryption_fingerprint']}")


if __name__ == "__main__":
    run_demo()
