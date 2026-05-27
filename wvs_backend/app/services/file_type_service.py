from __future__ import annotations

import hashlib
from pathlib import Path


MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "pe"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"{\\rtf", "rtf"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "ole"),
]


def sha256_for_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_file_type(path: str | Path, fallback_extension: str | None = None) -> str:
    with open(path, "rb") as handle:
        header = handle.read(16)

    for signature, detected in MAGIC_SIGNATURES:
        if header.startswith(signature):
            return detected

    extension = (fallback_extension or Path(path).suffix).lower()
    if extension in {".exe", ".dll", ".msi", ".scr"}:
        return "pe"
    if extension in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"}:
        return "office"
    if extension in {".js", ".vbs", ".ps1", ".bat", ".cmd"}:
        return "script"
    if extension == ".jar":
        return "jar"
    if extension == ".pdf":
        return "pdf"
    if extension == ".rtf":
        return "rtf"
    if extension == ".zip":
        return "zip"
    return "unknown"

