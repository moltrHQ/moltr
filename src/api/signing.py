# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>

"""SafeSkills Signing Service

Manages the Ed25519 keypair used to sign and verify skill certificates.

Key loading priority:
  1. SAFESKILLS_PRIVATE_KEY env var (base64url-encoded raw 32-byte private key)
  2. data/safeskills-keypair.json  (auto-generated on first run)

The public key is served openly at GET /api/v1/registry/pubkey so anyone
can verify certificates independently without calling our API.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("moltr.api.signing")


class SigningService:
    """Ed25519 signing service for SafeSkills certificates."""

    def __init__(self, data_dir: Path):
        self._private_key: Ed25519PrivateKey = self._load_or_generate(data_dir)
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        pub_raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._pub_b64 = base64.urlsafe_b64encode(pub_raw).decode()
        logger.info("[Signing] Ready — public key: %s", self._pub_b64[:16] + "...")

    def _load_or_generate(self, data_dir: Path) -> Ed25519PrivateKey:
        # Priority 1: env var
        env_key = os.environ.get("SAFESKILLS_PRIVATE_KEY", "")
        if env_key:
            raw = base64.urlsafe_b64decode(env_key + "==")
            logger.info("[Signing] Loaded private key from SAFESKILLS_PRIVATE_KEY env")
            return Ed25519PrivateKey.from_private_bytes(raw)

        # Priority 2: data/safeskills-keypair.json
        keypair_file = data_dir / "safeskills-keypair.json"
        if keypair_file.exists():
            kp = json.loads(keypair_file.read_text(encoding="utf-8"))
            raw = base64.urlsafe_b64decode(kp["private_key"] + "==")
            logger.info("[Signing] Loaded private key from %s", keypair_file)
            return Ed25519PrivateKey.from_private_bytes(raw)

        # Generate new keypair and persist
        private_key = Ed25519PrivateKey.generate()
        priv_raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_raw  = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        kp = {
            "private_key": base64.urlsafe_b64encode(priv_raw).decode().rstrip("="),
            "public_key":  base64.urlsafe_b64encode(pub_raw).decode().rstrip("="),
            "note": "Auto-generated. Set SAFESKILLS_PRIVATE_KEY env var for production.",
        }
        data_dir.mkdir(parents=True, exist_ok=True)
        keypair_file.write_text(json.dumps(kp, indent=2), encoding="utf-8")
        logger.warning(
            "[Signing] Generated new keypair and saved to %s — "
            "set SAFESKILLS_PRIVATE_KEY in .env for persistence across deploys",
            keypair_file,
        )
        return private_key

    @property
    def public_key_b64(self) -> str:
        return self._pub_b64

    def sign(self, payload: dict) -> str:
        """Sign a dict payload. Returns base64url-encoded signature.
        Payload is canonicalized (sorted keys, no whitespace) before signing.
        """
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        sig = self._private_key.sign(canonical)
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")

    def verify(self, payload: dict, signature: str) -> bool:
        """Verify a signature over a payload dict. Returns True if valid."""
        try:
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            sig_bytes = base64.urlsafe_b64decode(signature + "==")
            self._public_key.verify(sig_bytes, canonical)
            return True
        except InvalidSignature:
            return False
        except Exception as exc:
            logger.warning("[Signing] verify error: %s", exc)
            return False
