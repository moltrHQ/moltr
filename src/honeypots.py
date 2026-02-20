# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Moltr honeypot generator.

Generates randomized honeypot files at runtime.
Each installation gets unique, non-reproducible fake credentials.
Files are registered in .moltr-honeypots.json manifest for scanner allowlisting.
"""

from __future__ import annotations

import json
import random
import secrets
import string
from pathlib import Path


# ---------------------------------------------------------------------------
# Fake credential templates
# ---------------------------------------------------------------------------

_DB_NAMES = ["prod", "staging", "analytics", "billing", "archive", "replica"]
_SERVICES = ["redis", "mongodb", "rabbitmq", "elasticsearch", "memcached"]
_CI_TOOLS = ["jenkins", "gitlab_runner", "github_actions", "circleci", "drone"]
_MONITOR = ["grafana", "prometheus", "datadog", "newrelic", "sentry"]
_ADJECTIVES = ["secure", "internal", "private", "system", "service", "deploy"]


def _rand_pass(length: int = 20) -> str:
    """Generate a realistic-looking fake password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


def _rand_token(prefix: str = "", length: int = 32) -> str:
    """Generate a fake API token."""
    hex_part = secrets.token_hex(length // 2)
    return f"{prefix}{hex_part}" if prefix else hex_part


def _rand_user(prefix: str = "svc") -> str:
    adj = random.choice(_ADJECTIVES)
    return f"{prefix}_{adj}_{secrets.token_hex(3)}"


def _generate_passwords_txt() -> str:
    db_name = random.choice(_DB_NAMES)
    db2_name = random.choice([n for n in _DB_NAMES if n != db_name])
    svc = random.choice(_SERVICES)
    ci = random.choice(_CI_TOOLS)
    mon = random.choice(_MONITOR)

    return f"""## ================================================================
## HONEYPOT FILE — FAKE CREDENTIALS FOR INTRUSION DETECTION
## ================================================================
## This file contains DELIBERATELY PLACED fake credentials.
## They are monitored by Moltr Security to detect unauthorized access.
## NONE of these credentials are real or functional.
## If you found this file, it was placed here intentionally.
## See: https://github.com/moltrHQ/moltr (Honeypot Documentation)
## ================================================================

## Internal Service Credentials - DO NOT SHARE
## Last rotated: {_rand_date()}

# Production Database (PostgreSQL)
db_{db_name}_user: {_rand_user()}
db_{db_name}_pass: {_rand_pass(18)}

# Staging Database
db_{db2_name}_user: {_rand_user()}
db_{db2_name}_pass: {_rand_pass(18)}

# {svc.title()} Cache
{svc}_auth: {_rand_token('r3d1s_', 20)}

# Admin Panel
admin_user: {_rand_user('admin')}
admin_pass: {_rand_pass(22)}

# {ci.replace('_', ' ').title()} CI
{ci}_user: {_rand_user('deploy')}
{ci}_token: {_rand_token('ci_', 32)}

# {mon.title()} Monitoring
{mon}_admin: {_rand_user('mon')}
{mon}_pass: {_rand_pass(20)}
"""


def _generate_backup_keys_txt() -> str:
    return f"""## ================================================================
## HONEYPOT FILE — FAKE BACKUP KEYS FOR INTRUSION DETECTION
## ================================================================
## NONE of these keys are real. Monitoring is active.
## ================================================================

# AWS Backup Access
aws_access_key_id: AKIA{secrets.token_hex(8).upper()[:16]}
aws_secret_access_key: {_rand_token('', 40)}
aws_region: eu-central-1

# GCP Service Account
gcp_project_id: {_rand_user('proj')}
gcp_key_file: /etc/secrets/gcp-sa-{secrets.token_hex(4)}.json

# Backup Encryption Key
backup_enc_key: {_rand_token('bkp_', 48)}
backup_hmac_secret: {_rand_token('hmac_', 32)}

# SSH Backup User
ssh_backup_host: backup-{secrets.token_hex(3)}.internal
ssh_backup_user: {_rand_user('bkp')}
ssh_backup_key_fingerprint: SHA256:{_rand_token('', 20)}
"""


def _generate_wallet_seed_txt() -> str:
    # BIP39-style fake seed (random words, clearly fake)
    fake_words = [
        secrets.token_hex(3) for _ in range(24)
    ]
    seed = " ".join(fake_words)
    return f"""## ================================================================
## HONEYPOT FILE — FAKE WALLET SEED FOR INTRUSION DETECTION
## ================================================================
## NONE of these values are real. Monitoring is active.
## ================================================================

# Ethereum Wallet (FAKE)
eth_address: 0x{secrets.token_hex(20)}
eth_private_key: 0x{secrets.token_hex(32)}
eth_mnemonic: {seed}

# Bitcoin Wallet (FAKE)
btc_address: bc1q{secrets.token_hex(16)}
btc_wif: {_rand_token('K', 50)}

# Internal Token Reserve (FAKE)
reserve_wallet: {_rand_token('moltr_', 32)}
reserve_pass: {_rand_pass(24)}
"""


def _rand_date() -> str:
    year = random.randint(2024, 2025)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year}-{month:02d}-{day:02d}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

HONEYPOT_FILES = {
    "passwords.txt": _generate_passwords_txt,
    "backup_keys.txt": _generate_backup_keys_txt,
    "wallet_seed.txt": _generate_wallet_seed_txt,
}

MANIFEST_FILE = ".moltr-honeypots.json"


def generate_honeypots(honeypot_dir: Path) -> list[Path]:
    """Generate randomized honeypot files in honeypot_dir.

    Creates the directory if needed. Overwrites existing files so each
    restart gets fresh, unique content. Also writes the scanner manifest.

    Returns list of generated file paths.
    """
    honeypot_dir = Path(honeypot_dir)
    honeypot_dir.mkdir(parents=True, exist_ok=True)

    generated: list[Path] = []

    for filename, generator in HONEYPOT_FILES.items():
        path = honeypot_dir / filename
        path.write_text(generator(), encoding="utf-8")
        generated.append(path)

    # Write scanner manifest
    manifest = {
        "version": "1",
        "description": "Moltr Security honeypot file registry. These files contain FAKE credentials for intrusion detection. Do NOT flag as real credential leaks.",
        "honeypots": [str(p.resolve()) for p in generated],
        "relative_paths": [f.name for f in generated],
        "reference": "https://github.com/moltrHQ/moltr",
    }
    manifest_path = honeypot_dir / MANIFEST_FILE
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return generated
