from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import crypto_utils as crypto


EICAR_TEST_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

DANGEROUS_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".scr", ".vbs", ".msi", ".elf"}
DANGEROUS_TEXT_PATTERNS = [
    re.compile(r"Invoke-WebRequest", re.IGNORECASE),
    re.compile(r"curl\s+.+\|\s*(sh|bash|powershell)", re.IGNORECASE),
    re.compile(r"password\s*steal", re.IGNORECASE),
    re.compile(r"base64\s+-d\s*\|", re.IGNORECASE),
]


@dataclass(frozen=True)
class ScanReport:
    status: str
    rules: list[str]
    sha256: str
    size: int
    safe_filename: str


def safe_filename(filename: str) -> str:
    name = Path(filename).name.replace("\x00", "")
    return name or "unnamed"


def scan_file(path: str | Path, max_size: int = 50 * 1024 * 1024, blacklist: set[str] | None = None) -> ScanReport:
    path = Path(path)
    content = path.read_bytes()
    rules: list[str] = []
    blocked = False
    digest = crypto.sha256_hex(content)
    blacklist = blacklist or set()

    if len(content) > max_size:
        blocked = True
        rules.append("size_limit")
    if path.suffix.lower() in DANGEROUS_EXTENSIONS:
        blocked = True
        rules.append("dangerous_extension")
    if digest in blacklist:
        blocked = True
        rules.append("sha256_blacklist")
    if EICAR_TEST_STRING.encode("utf-8") in content:
        blocked = True
        rules.append("eicar_signature")

    text = content[:8192].decode("utf-8", errors="ignore")
    if any(pattern.search(text) for pattern in DANGEROUS_TEXT_PATTERNS):
        blocked = True
        rules.append("dangerous_text_pattern")

    if not rules:
        rules.append("basic_rules")
    return ScanReport(
        status="blocked" if blocked else "passed",
        rules=rules,
        sha256=digest,
        size=len(content),
        safe_filename=safe_filename(path.name),
    )
