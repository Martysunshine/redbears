"""At-rest encryption for long-term memory content.

Memory *values* (the actual fact text) are encrypted with Fernet (AES-128-CBC +
HMAC) before they ever reach SQLite. The key is generated on first use and
persisted at ``config.MEMORY_KEY_FILE`` with owner-only permissions (0600), or
supplied out-of-band via ``OYSTER_MEMORY_ENCRYPTION_KEY``. Vector embeddings
computed FROM the plaintext are stored separately (see rag_service's memory
collection) and are not reversible to the original text.

This protects memory content on disk (e.g. from casual inspection of the SQLite
file or a backup) — it is not a substitute for OS-level access control, and
whoever can read the key file or the running process can decrypt.
"""

from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken

import config

_fernet: Fernet | None = None


def _load_or_create_key() -> bytes:
    if config.MEMORY_ENCRYPTION_KEY:
        return config.MEMORY_ENCRYPTION_KEY.encode("utf-8")

    key_file = config.MEMORY_KEY_FILE
    if key_file.exists():
        return key_file.read_bytes().strip()

    key = Fernet.generate_key()
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX perms
    return key


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt(plaintext: str) -> str:
    token = _get_fernet().encrypt(plaintext.encode("utf-8"))
    return base64.urlsafe_b64encode(token).decode("ascii")


def decrypt(ciphertext: str) -> str:
    try:
        token = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
        return _get_fernet().decrypt(token).decode("utf-8")
    except (InvalidToken, ValueError):
        return "[unreadable — encryption key mismatch]"
