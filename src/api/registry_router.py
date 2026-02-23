# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>

"""SafeSkills Registry Router

Public skill discovery API. Agents search for skills here instead of the raw web.
SafeSkills acts as a security proxy: every result is scanned before being returned.

Endpoints (all public — no API key required):
  GET  /api/v1/registry/skills              — list / filter own registry
  GET  /api/v1/registry/skills/{skill_id}   — full skill detail + manifest
  GET  /api/v1/registry/skills/{skill_id}/manifest — raw manifest JSON (agent install)
  POST /api/v1/registry/search              — smart search: registry first, Exa fallback
  GET  /api/v1/registry/health              — health + stats

Note: Skills are loaded from config/skills/*.yaml on startup.
Hot-reload is not supported — add new YAML files and restart the service.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

import requests as _requests
import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from src.api._limiter import limiter
from src.api.tiers import Tier, require_tier, tier_limit

logger = logging.getLogger("moltr.api.registry")

registry_router = APIRouter(prefix="/api/v1/registry", tags=["SafeSkills Registry"])

EXA_API_KEY = os.environ.get("EXA_API_KEY", "")
MOLTR_BRANDING = "SafeSkills by Moltr (https://safeskills.dev)"

# Injected via init_registry()
_scanner = None
_registry: "SkillRegistry | None" = None


# ── Data Models ───────────────────────────────────────────────────────────────

class SkillEntry:
    """Internal representation of a skill loaded from YAML."""

    def __init__(self, data: dict, source_file: Path):
        self.id: str            = data.get("id", source_file.stem)
        self.name: str          = data.get("name", self.id)
        self.version: str       = data.get("version", "1.0.0")
        self.description: str   = data.get("description", "")
        self.category: str      = data.get("category", "general")
        self.tags: list[str]    = data.get("tags", [])
        self.author: str        = data.get("author", "unknown")
        self.license: str       = data.get("license", "unknown")
        self.scan_status: str   = data.get("scan_status", "unscanned")
        self.scan_date: str     = data.get("scan_date", "")
        self.compatibility: list[str] = data.get("compatibility", ["any"])
        self.manifest_type: str = data.get("manifest_type", "tool_definition")
        self.content: str       = data.get("content", "").strip()
        self._manifest_cache: dict | None = None  # parsed JSON cache

    def parse_manifest(self) -> dict | None:
        """Parse and cache manifest JSON content. Returns None on invalid JSON."""
        if self._manifest_cache is not None:
            return self._manifest_cache
        if not self.content:
            return None
        try:
            self._manifest_cache = json.loads(self.content)
            return self._manifest_cache
        except json.JSONDecodeError as exc:
            logger.warning("[Registry] Skill %r: invalid JSON manifest — %s", self.id, exc)
            return None

    def matches(self, q: str, tags: list[str], category: str) -> bool:
        """Match skill against query. Supports multi-word queries (all words must match)."""
        if category and self.category != category:
            return False
        if tags and not any(t in self.tags for t in tags):
            return False
        if q:
            searchable = f"{self.name} {self.description} {' '.join(self.tags)}".lower()
            # Every word in the query must appear somewhere in the searchable text
            if not all(word in searchable for word in q.lower().split()):
                return False
        return True

    def to_summary(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "tags": self.tags,
            "scan_status": self.scan_status,
            "source": "registry",
        }

    def to_detail(self) -> dict:
        return {
            **self.to_summary(),
            "author": self.author,
            "license": self.license,
            "scan_date": self.scan_date,
            "compatibility": self.compatibility,
            "manifest_type": self.manifest_type,
            "manifest_valid": self.parse_manifest() is not None,
            "content": self.content,
            "powered_by": MOLTR_BRANDING,
        }


class SkillRegistry:
    """In-memory registry backed by YAML files in config/skills/.

    Note: loaded once on startup. Hot-reload not supported — restart service to pick up changes.
    """

    def __init__(self):
        self._skills: dict[str, SkillEntry] = {}

    def load(self, skills_dir: Path, scanner=None) -> int:
        """Load all YAML skills from directory.
        If scanner is provided, each skill's content is scanned and scan_status is set accordingly.
        """
        count = 0
        for f in sorted(skills_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
                entry = SkillEntry(data, f)

                # Validate JSON manifest at load time — log warning if broken
                if entry.content and entry.parse_manifest() is None:
                    logger.warning("[Registry] Skill %r has invalid JSON manifest — still loaded", entry.id)

                # Scan content and override scan_status with actual result
                if scanner and entry.content:
                    entry.scan_status, entry.content = _rescan(entry.content, scanner)
                    logger.debug("[Registry] Scanned %r → %s", entry.id, entry.scan_status)
                    # Invalidate manifest cache after potential content modification
                    entry._manifest_cache = None

                self._skills[entry.id] = entry
                count += 1
            except Exception as exc:
                logger.warning("[Registry] Failed to load %s: %s", f.name, exc)
        logger.info("[Registry] Loaded %d skills from %s", count, skills_dir)
        return count

    def search(self, q: str = "", tags: list[str] = None, category: str = "") -> list[SkillEntry]:
        tags = tags or []
        return [s for s in self._skills.values() if s.matches(q, tags, category)]

    def get(self, skill_id: str) -> SkillEntry | None:
        return self._skills.get(skill_id)

    @property
    def count(self) -> int:
        return len(self._skills)

    @property
    def categories(self) -> list[str]:
        return sorted({s.category for s in self._skills.values()})


# ── API Models ────────────────────────────────────────────────────────────────

class RegistrySearchRequest(BaseModel):
    query: str
    tags: list[str] = []
    category: str = ""
    max_web_results: int = 5
    include_web: bool = True
    min_registry_threshold: int = 3  # below this count → trigger Exa fallback


class SkillListResponse(BaseModel):
    skills: list[dict]
    total: int
    powered_by: str


class SearchResponse(BaseModel):
    search_id: str
    query: str
    registry_results: list[dict]
    web_results: list[dict]
    total: int
    powered_by: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rescan(content: str, scanner) -> tuple[str, str]:
    """Scan content with injection scanner. Returns (scan_status, cleaned_content)."""
    if not content:
        return "safe", content
    working = content
    found_any = False
    for _ in range(10):
        result = scanner.scan(working)
        if not result.flagged:
            break
        found_any = True
        if result.matched_text:
            working = working.replace(result.matched_text, "[REMOVED]", 1)
        else:
            break
    if not found_any:
        return "safe", working
    # Check if high-severity patterns were found
    return "cleaned", working


async def _exa_search(query: str, max_results: int) -> list[dict]:
    """Search Exa and return raw results."""
    if not EXA_API_KEY:
        return []

    def _do_request() -> dict:
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
        data = await asyncio.to_thread(_do_request)
        return data.get("results", [])
    except Exception as exc:
        logger.warning("[Registry] Exa search error: %s", exc)
        return []


def _web_result_to_dict(raw: dict) -> dict:
    """Convert an Exa result to our standard format, including live scan."""
    text = raw.get("text") or " ".join(raw.get("highlights", []))
    if _scanner and text:
        scan_status, cleaned = _rescan(text, _scanner)
    else:
        scan_status, cleaned = "unscanned", text

    return {
        # No registry id for web results — use source field to distinguish
        "name": raw.get("title", "Untitled"),
        "url": raw.get("url", ""),
        "description": cleaned[:300] if cleaned else "",
        "scan_status": scan_status,
        "source": "web_scanned",
        "powered_by": MOLTR_BRANDING,
    }


# ── Init ──────────────────────────────────────────────────────────────────────

def init_registry(config_dir: Path, scanner=None) -> None:
    """Load skills from config/skills/ and initialize the injection scanner.
    If a shared scanner instance is provided, reuse it instead of creating a new one.
    """
    global _scanner, _registry
    if scanner is not None:
        _scanner = scanner
    else:
        from src.relay.injection_scanner import InjectionScanner
        _scanner = InjectionScanner(
            extra_patterns_file=config_dir / "relay_injection_patterns.yaml"
        )
    _registry = SkillRegistry()
    skills_dir = config_dir / "skills"
    if skills_dir.exists():
        _registry.load(skills_dir, scanner=_scanner)
    else:
        logger.warning("[Registry] skills dir not found: %s", skills_dir)
    logger.info("[Registry] Ready — %d skills, shared_scanner=%s, Exa=%s",
                _registry.count, scanner is not None, "enabled" if EXA_API_KEY else "disabled")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@registry_router.get("/health")
async def registry_health(response: Response):
    """Public health check — also returns registry stats."""
    response.headers["X-Powered-By"] = "SafeSkills"
    return {
        "status": "ok",
        "skills_loaded": _registry.count if _registry else 0,
        "categories": _registry.categories if _registry else [],
        "web_search": "enabled" if EXA_API_KEY else "disabled",
        "powered_by": MOLTR_BRANDING,
    }


@registry_router.get("/skills", response_model=SkillListResponse)
@limiter.limit("1000/minute")
async def list_skills(
    request: Request,
    response: Response,
    _rl=tier_limit("registry_list"),
    q: str = Query(default="", description="Search query — all words must match (name, description, tags)"),
    tags: str = Query(default="", description="Comma-separated tag filter"),
    category: str = Query(default="", description="Filter by category"),
):
    """List and search the SafeSkills registry. All results are pre-scanned."""
    response.headers["X-Powered-By"] = "SafeSkills"

    if _registry is None:
        raise HTTPException(status_code=503, detail="Registry not initialized")

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    results = _registry.search(q=q, tags=tag_list, category=category)

    return SkillListResponse(
        skills=[s.to_summary() for s in results],
        total=len(results),
        powered_by=MOLTR_BRANDING,
    )


@registry_router.get("/skills/{skill_id}")
@limiter.limit("1000/minute")
async def get_skill(skill_id: str, request: Request, response: Response, _rl=tier_limit("registry_list")):
    """Get full details + manifest for a specific skill."""
    response.headers["X-Powered-By"] = "SafeSkills"

    if _registry is None:
        raise HTTPException(status_code=503, detail="Registry not initialized")

    skill = _registry.get(skill_id)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Skill '{skill_id}' not found")

    return skill.to_detail()


@registry_router.get("/skills/{skill_id}/manifest")
@limiter.limit("1000/minute")
async def get_skill_manifest(skill_id: str, request: Request, response: Response, _rl=tier_limit("registry_list")):
    """Return the raw tool manifest for agent integration (JSON).
    Returns 422 if the skill's manifest content is not valid JSON.
    """
    response.headers["X-Powered-By"] = "SafeSkills"

    if _registry is None:
        raise HTTPException(status_code=503, detail="Registry not initialized")

    skill = _registry.get(skill_id)
    if not skill:
        raise HTTPException(status_code=404, detail=f"Skill '{skill_id}' not found")

    if not skill.content:
        raise HTTPException(status_code=404, detail="No manifest content for this skill")

    manifest = skill.parse_manifest()
    if manifest is None:
        raise HTTPException(
            status_code=422,
            detail=f"Skill '{skill_id}' has invalid JSON manifest — contact SafeSkills support"
        )

    return {
        "skill_id": skill.id,
        "skill_name": skill.name,
        "version": skill.version,
        "scan_status": skill.scan_status,
        "manifest_type": skill.manifest_type,
        "manifest": manifest,
        "powered_by": MOLTR_BRANDING,
    }


@registry_router.post("/search", response_model=SearchResponse)
@limiter.limit("1000/minute")
async def smart_search(request: Request, req: RegistrySearchRequest, response: Response, _rl=tier_limit("registry_search")):
    """
    Smart skill search for agents.

    1. Searches the SafeSkills registry first (pre-scanned, instant).
    2. If results < min_registry_threshold AND include_web=true AND Exa available:
       falls back to live web search — every result is scanned on-the-fly.

    Agents get clean, verified results without ever touching raw web content.
    Web results have no registry id (source='web_scanned'); registry results have source='registry'.
    """
    response.headers["X-Powered-By"] = "SafeSkills"
    search_id = str(uuid.uuid4())

    if _registry is None:
        raise HTTPException(status_code=503, detail="Registry not initialized")

    # Step 1: registry search (pre-scanned, instant)
    registry_hits = _registry.search(q=req.query, tags=req.tags, category=req.category)
    registry_results = [s.to_summary() for s in registry_hits]

    logger.info("[Registry] search q=%r registry_hits=%d", req.query, len(registry_hits))

    # Step 2: Exa fallback — only if registry results are below threshold
    web_results: list[dict] = []
    if req.include_web and len(registry_hits) < req.min_registry_threshold and EXA_API_KEY:
        raw_web = await _exa_search(req.query, req.max_web_results)
        web_results = [_web_result_to_dict(r) for r in raw_web]
        logger.info("[Registry] Exa fallback — %d web results scanned", len(web_results))

    return SearchResponse(
        search_id=search_id,
        query=req.query,
        registry_results=registry_results,
        web_results=web_results,
        total=len(registry_results) + len(web_results),
        powered_by=MOLTR_BRANDING,
    )
