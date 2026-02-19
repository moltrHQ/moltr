# Moltr Interop Manifest (MIM) — Specification v1.0

**Status:** Draft
**Authors:** Moltr Security (moltr.tech)
**License:** CC0 1.0 Universal (public domain)
**Repository:** https://github.com/moltrHQ/moltr

---

## Abstract

The Moltr Interop Manifest (MIM) is an open, lightweight specification that allows
security tools, AI agents, and scanners to declare their intentional traps, honeypots,
and decoy resources. Consuming tools can use this information to avoid false positives
when operating alongside other security systems.

**The problem this solves:** Security tool A places a honeypot file to detect unauthorized
access. Security tool B scans the filesystem and alerts on the same file, interpreting it
as a leaked credential. Both tools are correct — but they conflict. MIM eliminates this
by establishing a machine-readable contract between security tools.

---

## 1. Discovery

A MIM-compliant system MUST expose its manifest at the following well-known URL:

```
GET /.well-known/moltr-manifest.json
```

The endpoint MUST:
- Return `Content-Type: application/json`
- Return HTTP `200 OK` when the manifest is available
- Be accessible without authentication (read-only, no sensitive data)
- Return HTTP `404` if the system has no honeypots or traps to declare

Consuming tools SHOULD attempt discovery before performing scans and cache the
result for a reasonable period (recommended: 1 hour).

---

## 2. Manifest Format

```json
{
  "mim": "1.0",
  "vendor": "moltr",
  "generated": "2026-02-19T18:00:00Z",
  "honeypots": {
    "files": [
      "honeypots/passwords.txt",
      "honeypots/backup_keys.txt",
      "honeypots/wallet_seed.txt",
      "honeypots/.env.backup"
    ],
    "endpoints": [
      "/api/admin/debug",
      "/api/v1/keys/export",
      "/api/internal/secrets",
      "/admin/config/dump"
    ],
    "directories": [
      "honeypots/"
    ]
  },
  "traps": {
    "description": "Accessing any declared resource constitutes a security event and will be logged and alerted.",
    "contact": "security@example.com"
  },
  "scanner_hints": {
    "ignore_patterns": [
      "honeypots/**",
      "**/.env.backup"
    ],
    "false_positive_notice": "Credentials and keys in declared honeypot paths are intentionally fake. Do not alert on them."
  }
}
```

---

## 3. Field Reference

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mim` | string | **YES** | Spec version. Currently `"1.0"`. |
| `vendor` | string | **YES** | Tool or vendor name declaring this manifest. |
| `generated` | string (ISO 8601) | NO | Timestamp when the manifest was generated. |
| `honeypots` | object | NO | Declared honeypot resources. |
| `traps` | object | NO | Human-readable trap metadata. |
| `scanner_hints` | object | NO | Machine-readable hints for consuming scanners. |

### `honeypots` Object

| Field | Type | Description |
|-------|------|-------------|
| `files` | string[] | Relative file paths that are intentional honeypot files. |
| `endpoints` | string[] | HTTP endpoint paths that are decoy API routes. |
| `directories` | string[] | Entire directories containing only honeypot content. Glob patterns supported. |

### `traps` Object

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | Human-readable description of the trap intent. |
| `contact` | string | Security contact for questions about the manifest. |

### `scanner_hints` Object

| Field | Type | Description |
|-------|------|-------------|
| `ignore_patterns` | string[] | Glob patterns consuming tools SHOULD exclude from alerts. |
| `false_positive_notice` | string | Human-readable notice explaining the false positive risk. |

---

## 4. Consuming Tool Behavior

Tools that consume MIM manifests SHOULD implement the following behavior:

### 4.1 Discovery Phase
```
Before scan:
  1. Attempt GET /.well-known/moltr-manifest.json
  2. If 200: parse manifest, cache for 1h
  3. If 404/error: proceed without manifest (no false positive suppression)
```

### 4.2 Scan Phase
```
During scan:
  For each finding:
    If finding.path matches any manifest.honeypots.files → suppress alert, log as "known honeypot"
    If finding.path matches any manifest.honeypots.directories → suppress alert
    If finding.endpoint matches any manifest.honeypots.endpoints → suppress alert
    If finding.path matches any manifest.scanner_hints.ignore_patterns → suppress alert
    Else → alert normally
```

### 4.3 Logging
Consuming tools SHOULD log suppressed findings separately with a note indicating
the suppression reason (`mim-manifest`). This ensures the honeypot is still
recorded as "triggered" for the declaring tool's audit log.

---

## 5. Declaring Tool Behavior (e.g. Moltr)

Tools that declare a MIM manifest SHOULD:

1. Expose `GET /.well-known/moltr-manifest.json` automatically when honeypots are configured
2. Keep the manifest up to date when honeypots are added or removed
3. Include only paths/endpoints that are **intentionally fake** — never real sensitive resources
4. Serve the manifest without authentication (it contains no secrets)
5. Log all accesses to `/.well-known/moltr-manifest.json` for audit purposes

---

## 6. Security Considerations

### What MIM is NOT
- MIM does not whitelist tools from security enforcement
- MIM does not grant access to any resources
- MIM does not contain real credentials or secrets
- MIM is not a bypass mechanism — honeypots still trigger alerts in the declaring tool

### Manifest Spoofing
If an attacker can modify the manifest to declare real sensitive files as honeypots,
consuming tools would suppress alerts on those files. Therefore:
- Consuming tools SHOULD only suppress alerts for paths that match honeypot
  patterns (fake credentials, dummy keys, decoy configs)
- Consuming tools SHOULD NOT suppress alerts for paths with real operational data
  even if declared in a manifest
- The declaring server MUST protect write access to `/.well-known/moltr-manifest.json`

### HTTPS Requirement
In production deployments, the manifest MUST be served over HTTPS to prevent
tampering in transit.

---

## 7. Versioning

The `mim` field declares the spec version. Version changes:

| Version | Breaking | Notes |
|---------|----------|-------|
| `1.0` | — | Initial release |

Future versions will increment the minor version for additive changes and the
major version for breaking changes. Consuming tools SHOULD check the `mim` field
and warn if they encounter an unsupported version.

---

## 8. Minimal Valid Manifest

The smallest valid MIM manifest:

```json
{
  "mim": "1.0",
  "vendor": "my-tool"
}
```

An empty manifest with no declared honeypots is valid and signals to consuming
tools that MIM discovery is supported but no traps are currently active.

---

## 9. Example: Moltr Security Implementation

```
GET /.well-known/moltr-manifest.json HTTP/1.1
Host: moltr.example.com

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600

{
  "mim": "1.0",
  "vendor": "moltr-security",
  "generated": "2026-02-19T18:00:00Z",
  "honeypots": {
    "files": [
      "honeypots/passwords.txt",
      "honeypots/backup_keys.txt",
      "honeypots/wallet_seed.txt"
    ],
    "endpoints": [
      "/api/admin/debug",
      "/api/v1/keys/export"
    ],
    "directories": ["honeypots/"]
  },
  "scanner_hints": {
    "ignore_patterns": ["honeypots/**"],
    "false_positive_notice": "All files under honeypots/ are intentionally fake credentials used as intrusion detection traps."
  }
}
```

---

## 10. Compatibility Test Matrix

The following agent/scanner combinations have been tested for MIM compliance:

| Tool | Version | MIM Aware | False Positive Without MIM | False Positive With MIM |
|------|---------|-----------|---------------------------|------------------------|
| Moltr Security | v1.0.0 | Declarant | — | — |
| OpenClaw | 2026.2.x | Planned | YES | TBD |
| NanoClaw | latest | Planned | TBD | TBD |
| PicoClaw | latest | Planned | TBD | TBD |

*Results will be updated after compatibility lab testing on Linux infrastructure.*

---

## 11. Contributing

MIM is an open standard. Contributions, implementations, and feedback are welcome:

- **Issues:** https://github.com/moltrHQ/moltr/issues
- **Pull Requests:** Spec improvements, additional field proposals
- **Implementations:** Link your MIM-aware tool in the README

To declare MIM compatibility for your tool, open a PR adding it to Section 10.

---

*Moltr Interop Manifest — Made in Vienna*
*CC0 1.0 — No rights reserved. Use freely.*
