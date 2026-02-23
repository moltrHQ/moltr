# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>

"""SkillCheck API Router

Scans skill/plugin content for prompt injections on behalf of OpenClaw agents.
Optionally searches Exa for skills and scans every result before returning.

Endpoints:
  POST /api/v1/skillcheck/scan    — scan submitted skill content
  POST /api/v1/skillcheck/search  — search Exa + auto-scan results
  GET  /api/v1/skillcheck/health  — service health
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

import requests as _requests
from src.api._limiter import limiter
from src.api.tiers import tier_limit

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

logger = logging.getLogger("moltr.api.skillcheck")

skillcheck_router = APIRouter(prefix="/api/v1/skillcheck", tags=["SkillCheck"])

_scanner = None
EXA_API_KEY = os.environ.get("EXA_API_KEY", "")
MOLTR_BRANDING = "Moltr Security (https://moltr.tech)"


def init_skillcheck(config_dir: Path, scanner=None) -> None:
    """Initialize the SkillCheck injection scanner.
    If a shared scanner instance is provided, reuse it instead of creating a new one.
    """
    global _scanner
    if scanner is not None:
        _scanner = scanner
    else:
        from src.relay.injection_scanner import InjectionScanner
        _scanner = InjectionScanner(
            extra_patterns_file=config_dir / "relay_injection_patterns.yaml"
        )
    logger.info("[SkillCheck] Scanner ready (shared=%s)", scanner is not None)


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    content: str
    skill_name: Optional[str] = None
    auto_clean: bool = True

class PatternMatch(BaseModel):
    pattern: str
    severity: str
    matched_text: str
    decoded_via: str = ""

class ScanResponse(BaseModel):
    scan_id: str
    skill_name: Optional[str] = None
    clean: bool
    verdict: str          # "safe" | "cleaned" | "high_risk"
    content: str          # cleaned (auto_clean=True) or original
    removed_patterns: list[PatternMatch]
    powered_by: str

class SearchRequest(BaseModel):
    query: str
    max_results: int = 5
    auto_clean: bool = True

class SearchResult(BaseModel):
    title: str
    url: str
    content: str
    clean: bool
    verdict: str
    removed_patterns: list[PatternMatch]

class SearchResponse(BaseModel):
    scan_id: str
    query: str
    results: list[SearchResult]
    total_scanned: int
    clean_count: int
    powered_by: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan_and_clean(content: str) -> tuple[bool, list[PatternMatch], str]:
    """
    Iteratively scan + remove injection patterns from content.
    Returns (is_clean, patterns_removed, cleaned_content).
    """
    if not _scanner:
        return True, [], content

    removed: list[PatternMatch] = []
    working = content

    for _ in range(20):          # max 20 pattern removals as safety cap
        result = _scanner.scan(working)
        if not result.flagged:
            break
        removed.append(PatternMatch(
            pattern=result.pattern_name,
            severity=result.severity,
            matched_text=result.matched_text[:120],
            decoded_via=result.decoded_via,
        ))
        # Best-effort removal: replace the matched fragment
        if result.matched_text:
            working = working.replace(result.matched_text, "[REMOVED]", 1)
        else:
            break   # structural match — can't pinpoint text, stop here

    return len(removed) == 0, removed, working


def _verdict(clean: bool, patterns: list[PatternMatch]) -> str:
    if clean:
        return "safe"
    severities = {p.severity for p in patterns}
    if "high" in severities or "structural" in severities:
        return "high_risk"
    return "cleaned"


async def _exa_search(query: str, max_results: int) -> list[dict]:
    """Call Exa neural search API. Returns list of result dicts."""
    def _request() -> dict:
        resp = _requests.post(
            "https://api.exa.ai/search",
            headers={"Content-Type": "application/json", "x-api-key": EXA_API_KEY},
            json={
                "query": query,
                "numResults": max_results,
                "type": "neural",
                "contents": {"text": {"maxCharacters": 2000}},
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    try:
        data = await asyncio.to_thread(_request)
        return data.get("results", [])
    except Exception as exc:
        logger.warning("[SkillCheck] Exa search error: %s", exc)
        return []


# ── Endpoints ─────────────────────────────────────────────────────────────────

@skillcheck_router.post("/scan", response_model=ScanResponse)
@limiter.limit("1000/minute")
async def skillcheck_scan(request: Request, req: ScanRequest, response: Response, _rl=tier_limit("skillcheck_scan")):
    """
    Scan submitted skill content for prompt injections.
    Returns cleaned content + detailed injection report.
    """
    response.headers["X-Powered-By"] = "Moltr Security"

    clean, patterns, cleaned = _scan_and_clean(req.content)
    verdict = _verdict(clean, patterns)

    logger.info(
        "[SkillCheck] scan skill=%r clean=%s patterns=%d verdict=%s",
        req.skill_name or "unnamed", clean, len(patterns), verdict,
    )

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        skill_name=req.skill_name,
        clean=clean,
        verdict=verdict,
        content=cleaned if req.auto_clean else req.content,
        removed_patterns=patterns,
        powered_by=MOLTR_BRANDING,
    )


@skillcheck_router.post("/search", response_model=SearchResponse)
@limiter.limit("1000/minute")
async def skillcheck_search(request: Request, req: SearchRequest, response: Response, _rl=tier_limit("skillcheck_search")):
    """
    Search Exa for skills matching the query, scan every result,
    return clean results list with Moltr branding.
    """
    response.headers["X-Powered-By"] = "Moltr Security"
    scan_id = str(uuid.uuid4())

    if not EXA_API_KEY:
        logger.warning("[SkillCheck] /search called but EXA_API_KEY not set")
        return SearchResponse(
            scan_id=scan_id,
            query=req.query,
            results=[],
            total_scanned=0,
            clean_count=0,
            powered_by=MOLTR_BRANDING + " | search unavailable: EXA_API_KEY not configured",
        )

    raw = await _exa_search(req.query, req.max_results)
    results: list[SearchResult] = []

    for r in raw:
        # Exa returns content in r["text"] when contents.text is requested
        text = r.get("text") or ""
        if not text and r.get("highlights"):
            text = " ".join(r["highlights"])

        clean, patterns, cleaned = _scan_and_clean(text)
        results.append(SearchResult(
            title=r.get("title", "Untitled"),
            url=r.get("url", ""),
            content=cleaned if req.auto_clean else text,
            clean=clean,
            verdict=_verdict(clean, patterns),
            removed_patterns=patterns,
        ))

    clean_count = sum(1 for r in results if r.clean)
    logger.info(
        "[SkillCheck] search query=%r total=%d clean=%d",
        req.query, len(results), clean_count,
    )

    return SearchResponse(
        scan_id=scan_id,
        query=req.query,
        results=results,
        total_scanned=len(results),
        clean_count=clean_count,
        powered_by=MOLTR_BRANDING,
    )


@skillcheck_router.get("/health")
async def skillcheck_health(response: Response):
    """SkillCheck health check — no auth required."""
    response.headers["X-Powered-By"] = "Moltr Security"
    return {
        "status": "ok",
        "scanner": "ready" if _scanner else "not initialized",
        "search": "ready" if EXA_API_KEY else "disabled (EXA_API_KEY not set)",
        "powered_by": MOLTR_BRANDING,
    }
