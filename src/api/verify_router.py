# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>

"""SafeSkills Verify Router

Certificate issuance and verification for skill safety.

Paid tier → certify a skill → receive Ed25519-signed certificate
Anyone   → verify a cert   → get proof it was issued by SafeSkills

Endpoints:
  POST /api/v1/registry/certify          — issue a certificate (requires API key)
  GET  /api/v1/verify/{cert_id}          — verify a certificate (public)
  GET  /api/v1/registry/pubkey           — get SafeSkills public key (public)

Certificate lifetime: 1 year from issuance.
Storage: data/certificates.json (JSON file, loaded on startup).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from src.api._limiter import limiter
from src.api.tiers import Tier, require_tier, tier_limit

logger = logging.getLogger("moltr.api.verify")

verify_router = APIRouter(tags=["SafeSkills Verify"])

MOLTR_BRANDING = "SafeSkills by Moltr (https://safeskills.dev)"
CERT_LIFETIME_DAYS = 365

# Injected via init_verify()
_signer = None
_cert_store: "CertStore | None" = None


# ── Certificate Store ─────────────────────────────────────────────────────────

class CertStore:
    """In-memory certificate store with JSON file persistence."""

    def __init__(self, data_dir: Path):
        self._path = data_dir / "certificates.json"
        self._certs: dict[str, dict] = {}
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                self._certs = json.loads(self._path.read_text(encoding="utf-8"))
                logger.info("[CertStore] Loaded %d certificates from %s", len(self._certs), self._path)
            except Exception as exc:
                logger.warning("[CertStore] Failed to load %s: %s", self._path, exc)

    def _save(self):
        try:
            self._path.write_text(json.dumps(self._certs, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("[CertStore] Failed to save: %s", exc)

    def add(self, cert: dict) -> None:
        self._certs[cert["cert_id"]] = cert
        self._save()

    def get(self, cert_id: str) -> dict | None:
        return self._certs.get(cert_id)

    @property
    def count(self) -> int:
        return len(self._certs)


# ── API Models ────────────────────────────────────────────────────────────────

class CertifyRequest(BaseModel):
    # Option A: certify a skill already in the registry
    skill_id: Optional[str] = None
    # Option B: certify arbitrary content (external developer)
    content: Optional[str] = None
    skill_name: Optional[str] = None
    skill_version: str = "1.0.0"


class CertifyResponse(BaseModel):
    cert_id: str
    skill_id: Optional[str]
    skill_name: str
    skill_version: str
    scan_status: str
    patterns_removed: int
    issued_at: str
    expires_at: str
    verify_url: str
    signature: str
    public_key: str
    powered_by: str


class VerifyResponse(BaseModel):
    valid: bool
    cert_id: str
    skill_id: Optional[str]
    skill_name: str
    skill_version: str
    scan_status: str
    issued_at: str
    expires_at: str
    expired: bool
    powered_by: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan_content(content: str) -> tuple[str, str, int]:
    """Scan content. Returns (scan_status, cleaned_content, patterns_removed_count)."""
    from src.api.registry_router import _scanner
    if not _scanner or not content:
        return "unscanned", content, 0

    working = content
    count = 0
    for _ in range(20):
        result = _scanner.scan(working)
        if not result.flagged:
            break
        count += 1
        if result.matched_text:
            working = working.replace(result.matched_text, "[REMOVED]", 1)
        else:
            break

    if count == 0:
        return "safe", working, 0
    severities = set()
    # Re-scan to check if still flagged after cleaning
    final = _scanner.scan(working)
    status = "high_risk" if (final.flagged and final.severity in ("high", "structural")) else "cleaned"
    return status, working, count


def _build_signable_payload(cert_id: str, skill_id: Optional[str], skill_name: str,
                             skill_version: str, scan_status: str, patterns_removed: int,
                             issued_at: str, expires_at: str) -> dict:
    """Build the canonical payload that gets signed. Never includes the signature itself."""
    return {
        "cert_id": cert_id,
        "skill_id": skill_id,
        "skill_name": skill_name,
        "skill_version": skill_version,
        "scan_status": scan_status,
        "patterns_removed": patterns_removed,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "issued_by": "SafeSkills",
    }


# ── Init ──────────────────────────────────────────────────────────────────────

def init_verify(data_dir: Path) -> None:
    """Initialize signing service and certificate store."""
    global _signer, _cert_store
    from src.api.signing import SigningService
    _signer = SigningService(data_dir)
    _cert_store = CertStore(data_dir)
    logger.info("[Verify] Ready — %d existing certs", _cert_store.count)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@verify_router.post("/api/v1/registry/certify", response_model=CertifyResponse)
@limiter.limit("1000/minute")
async def certify_skill(
    request: Request,
    req: CertifyRequest,
    response: Response,
    _tier_check=Depends(require_tier(Tier.VERIFIED)),
    _rl=tier_limit("certify"),
):
    """
    Issue a SafeSkills certificate for a skill.

    Requires API key (X-API-Key header). The skill is scanned and if safe or cleanable,
    an Ed25519-signed certificate is issued. The certificate can be verified by anyone
    at GET /api/v1/verify/{cert_id} — even without an API key.

    Accepts:
    - skill_id: certify a skill already in the SafeSkills registry
    - content: certify arbitrary skill content (for external developers)
    """
    response.headers["X-Powered-By"] = "SafeSkills"

    if _signer is None or _cert_store is None:
        raise HTTPException(status_code=503, detail="Signing service not initialized")

    # Resolve skill_id vs raw content
    skill_id   = req.skill_id
    skill_name = req.skill_name or skill_id or "Unknown Skill"
    content    = req.content or ""

    if skill_id:
        # Look up in registry
        from src.api.registry_router import _registry
        if _registry:
            entry = _registry.get(skill_id)
            if entry:
                content    = entry.content
                skill_name = entry.name
            # If not found in registry, proceed with skill_id + empty content
    elif not content:
        raise HTTPException(status_code=400, detail="Provide either skill_id or content")

    # Scan
    scan_status, _, patterns_removed = _scan_content(content)

    # Refuse to certify high-risk content
    if scan_status == "high_risk":
        raise HTTPException(
            status_code=422,
            detail=f"Skill contains high-risk injection patterns and cannot be certified. "
                   f"Patterns removed: {patterns_removed}",
        )

    # Build certificate
    now        = datetime.now(timezone.utc)
    expires    = now + timedelta(days=CERT_LIFETIME_DAYS)
    cert_id    = str(uuid.uuid4())
    issued_at  = now.isoformat()
    expires_at = expires.isoformat()

    signable = _build_signable_payload(
        cert_id=cert_id,
        skill_id=skill_id,
        skill_name=skill_name,
        skill_version=req.skill_version,
        scan_status=scan_status,
        patterns_removed=patterns_removed,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    signature = _signer.sign(signable)

    cert = {
        **signable,
        "signature": signature,
        "public_key": _signer.public_key_b64,
    }
    _cert_store.add(cert)

    logger.info(
        "[Verify] Issued cert %s for skill=%r status=%s patterns_removed=%d",
        cert_id[:8], skill_id or skill_name, scan_status, patterns_removed,
    )

    base_url = str(request.base_url).rstrip("/")
    return CertifyResponse(
        cert_id=cert_id,
        skill_id=skill_id,
        skill_name=skill_name,
        skill_version=req.skill_version,
        scan_status=scan_status,
        patterns_removed=patterns_removed,
        issued_at=issued_at,
        expires_at=expires_at,
        verify_url=f"{base_url}/api/v1/verify/{cert_id}",
        signature=signature,
        public_key=_signer.public_key_b64,
        powered_by=MOLTR_BRANDING,
    )


@verify_router.get("/api/v1/verify/{cert_id}", response_model=VerifyResponse)
@limiter.limit("1000/minute")
async def verify_certificate(cert_id: str, request: Request, response: Response, _rl=tier_limit("verify")):
    """
    Verify a SafeSkills certificate. Public — no API key required.

    Checks:
    1. Certificate exists in store
    2. Ed25519 signature is valid (cryptographic proof)
    3. Certificate has not expired

    Returns valid=true only if all three checks pass.
    """
    response.headers["X-Powered-By"] = "SafeSkills"

    if _signer is None or _cert_store is None:
        raise HTTPException(status_code=503, detail="Signing service not initialized")

    cert = _cert_store.get(cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found")

    # Re-verify signature
    signable = _build_signable_payload(
        cert_id=cert["cert_id"],
        skill_id=cert.get("skill_id"),
        skill_name=cert["skill_name"],
        skill_version=cert["skill_version"],
        scan_status=cert["scan_status"],
        patterns_removed=cert["patterns_removed"],
        issued_at=cert["issued_at"],
        expires_at=cert["expires_at"],
    )
    sig_valid = _signer.verify(signable, cert["signature"])

    # Check expiry
    expires_at = datetime.fromisoformat(cert["expires_at"])
    expired = datetime.now(timezone.utc) > expires_at

    valid = sig_valid and not expired

    logger.info(
        "[Verify] cert=%s sig_valid=%s expired=%s → valid=%s",
        cert_id[:8], sig_valid, expired, valid,
    )

    return VerifyResponse(
        valid=valid,
        cert_id=cert_id,
        skill_id=cert.get("skill_id"),
        skill_name=cert["skill_name"],
        skill_version=cert["skill_version"],
        scan_status=cert["scan_status"],
        issued_at=cert["issued_at"],
        expires_at=cert["expires_at"],
        expired=expired,
        powered_by=MOLTR_BRANDING,
    )


@verify_router.get("/api/v1/registry/pubkey")
async def get_public_key(response: Response):
    """
    Return the SafeSkills Ed25519 public key (base64url).
    Anyone can use this to independently verify certificates offline.
    """
    response.headers["X-Powered-By"] = "SafeSkills"

    if _signer is None:
        raise HTTPException(status_code=503, detail="Signing service not initialized")

    return {
        "algorithm": "Ed25519",
        "public_key": _signer.public_key_b64,
        "encoding": "base64url (raw 32-byte key)",
        "usage": "Verify SafeSkills certificate signatures. "
                 "Sign the canonical JSON payload (sorted keys, no whitespace) "
                 "and compare against the certificate's 'signature' field.",
        "powered_by": MOLTR_BRANDING,
    }
