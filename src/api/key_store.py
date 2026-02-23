# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>

"""SafeSkills API Key Store

Manages API keys with tier assignments. Keys are stored as SHA-256 hashes —
plaintext keys are shown only at creation time and never stored.

Key format: ss_<tier_prefix>_<random_32_chars>
  ss_free_...  | ss_ver_...  | ss_pro_...  | ss_ent_...

Storage: data/api-keys.json (JSON file, loaded on startup).
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.api.tiers import Tier

logger = logging.getLogger("moltr.api.keystore")

_TIER_PREFIX = {
    Tier.FREE:       "free",
    Tier.VERIFIED:   "ver",
    Tier.PRO:        "pro",
    Tier.ENTERPRISE: "ent",
}


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_key(tier: Tier) -> str:
    prefix = _TIER_PREFIX.get(tier, "free")
    random_part = secrets.token_urlsafe(24)
    return f"ss_{prefix}_{random_part}"


@dataclass
class APIKey:
    key_hash: str
    key_prefix: str        # first 12 chars of plaintext key — for display/identification
    tier: str              # Tier value string
    owner: str
    created_at: str
    last_used: Optional[str] = None
    is_active: bool = True

    @property
    def tier_enum(self) -> Tier:
        try:
            return Tier(self.tier)
        except ValueError:
            return Tier.FREE

    def to_public_dict(self) -> dict:
        """Safe dict for API responses — never includes key_hash."""
        return {
            "key_prefix": self.key_prefix,
            "tier": self.tier,
            "owner": self.owner,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "is_active": self.is_active,
        }


class KeyStore:
    """Persistent API key store backed by a JSON file."""

    def __init__(self, data_dir: Path):
        self._path = data_dir / "api-keys.json"
        self._keys: dict[str, APIKey] = {}  # key_hash → APIKey
        self._load()
        logger.info("[KeyStore] Ready — %d keys loaded", len(self._keys))

    def _load(self):
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in raw.get("keys", []):
                k = APIKey(**entry)
                self._keys[k.key_hash] = k
        except Exception as exc:
            logger.warning("[KeyStore] Failed to load %s: %s", self._path, exc)

    def _save(self):
        try:
            data = {"keys": [asdict(k) for k in self._keys.values()]}
            self._path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("[KeyStore] Failed to save: %s", exc)

    def create(self, tier: Tier, owner: str) -> tuple[str, APIKey]:
        """Generate a new key. Returns (plaintext_key, APIKey). Store only the hash."""
        plaintext = generate_key(tier)
        key_hash  = _hash_key(plaintext)
        key_prefix = plaintext[:12]
        entry = APIKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            tier=tier.value,
            owner=owner,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._keys[key_hash] = entry
        self._save()
        logger.info("[KeyStore] Created %s key for %r (prefix: %s)", tier.value, owner, key_prefix)
        return plaintext, entry

    def lookup(self, plaintext_key: str) -> Optional[APIKey]:
        """Look up a key by plaintext. Returns None if not found or inactive."""
        key_hash = _hash_key(plaintext_key)
        entry = self._keys.get(key_hash)
        if entry and entry.is_active:
            # Update last_used
            entry.last_used = datetime.now(timezone.utc).isoformat()
            self._save()
            return entry
        return None

    def revoke(self, key_prefix: str) -> bool:
        """Revoke a key by its prefix. Returns True if found and revoked."""
        for entry in self._keys.values():
            if entry.key_prefix == key_prefix:
                entry.is_active = False
                self._save()
                logger.info("[KeyStore] Revoked key with prefix %s", key_prefix)
                return True
        return False

    def list_keys(self) -> list[APIKey]:
        return list(self._keys.values())

    def get_by_prefix(self, key_prefix: str) -> Optional[APIKey]:
        for entry in self._keys.values():
            if entry.key_prefix == key_prefix:
                return entry
        return None

    def update_tier(self, key_prefix: str, new_tier_str: str) -> bool:
        """Update Tier eines Keys per Prefix. Returns True wenn gefunden."""
        for entry in self._keys.values():
            if entry.key_prefix == key_prefix:
                entry.tier = new_tier_str
                self._save()
                logger.info("[KeyStore] Tier updated for prefix %s → %s", key_prefix, new_tier_str)
                return True
        return False

    @property
    def count(self) -> int:
        return len(self._keys)
