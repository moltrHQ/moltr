# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Moltr Relay Audit Logger — append-only JSONL relay event log.

Events are written to logs/relay-audit.jsonl alongside the forensic log.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_AUDIT_PATH: Path | None = None
_logger = logging.getLogger("moltr.relay.audit")


def init_audit(logs_dir: Path) -> None:
    """Call once at startup to set the audit log path."""
    global _AUDIT_PATH
    _AUDIT_PATH = logs_dir / "relay-audit.jsonl"
    _logger.info("Relay audit log: %s", _AUDIT_PATH)


def log_relay_event(event_type: str, **kwargs: Any) -> None:
    """Append a relay event record to the JSONL audit log."""
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        **kwargs,
    }
    if _AUDIT_PATH:
        try:
            with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as e:
            _logger.error("Relay audit write failed: %s", e)
