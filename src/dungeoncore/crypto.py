"""AES-256-GCM Verschlüsselung für Dungeoncore.

Verwendet die `cryptography`-Bibliothek (bereits in requirements.txt).
Format der verschlüsselten Datei: salt(16) + nonce(12) + ciphertext+tag(variable)
"""

from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Leitet einen 256-bit AES-Key aus Passphrase + Salt ab."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(data: dict, passphrase: str) -> bytes:
    """Verschlüsselt ein dict mit AES-256-GCM.

    Returns: salt + nonce + ciphertext (mit eingebettetem GCM-Tag)
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt(data: bytes, passphrase: str) -> dict:
    """Entschlüsselt Dungeoncore-Daten.

    Raises:
        ValueError: Bei falscher Passphrase oder beschädigten Daten.
    """
    if len(data) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Datei zu klein — beschädigt oder kein Dungeoncore.")
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE :]
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Falsche Passphrase oder beschädigte Datei.")
    return json.loads(plaintext.decode("utf-8"))
