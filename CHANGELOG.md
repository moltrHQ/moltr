# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2025-02-12

### Added

**Core Modules**
- **Output Scanner** - Pattern-based secret detection with YAML-loaded rules, Base64/Hex/ROT13/URL deobfuscation, rate-limiting lockdown after 3 incidents in 10 minutes
- **Secrets Registry** - Fernet-encrypted secret storage with persistence, checks agent output against registered secrets
- **Action Validator** - YAML-based command allowlist with bypass detection (backticks, subshells, pipes, variable expansion, quote splicing, newline injection), risk levels 0-3, sliding-window rate limiting
- **Network Firewall** - Domain allowlist with wildcard support, direct IP blocking, DNS rebinding prevention (localhost, private ranges, metadata endpoints), outbound payload inspection (>1KB forwarded to scanner)
- **Filesystem Guard** - Path allowlist enforcement, honeypot file monitoring, SHA-256 integrity baselines with violation detection, symlink attack prevention
- **Kill Switch** - 5 escalation levels (PAUSE, NETWORK_CUT, LOCKDOWN, WIPE, EMERGENCY), codephrase-protected reset, full event logging with timestamps

**Alert System**
- **AlertManager** - Multi-channel dispatcher, sends to all configured channels simultaneously, catches exceptions per channel
- **TelegramAlert** - Bot API via urllib, emoji-formatted messages with severity and timestamp
- **SlackAlert** - Incoming webhook with Block Kit formatting (header, section, context blocks, color sidebar)
- **DiscordAlert** - Webhook with rich embed formatting (title, description, color by severity, footer)
- **EmailAlert** - SMTP with STARTTLS via smtplib, structured subject and body

**Entry Point**
- **Moltr** - Central orchestrator initializing all modules, unified API (scan_output, validate_command, check_url, check_path), status reporting, emergency stop

**Configuration**
- `config/default.yaml` - Central configuration with all module settings
- `config/scan_patterns.yaml` - Externalized regex patterns for output scanning
- `config/allowlists/commands.yaml` - Shell command security policy with risk levels
- `config/allowlists/domains.yaml` - Domain allowlist with wildcards and blocklist
- `config/allowlists/paths.yaml` - Filesystem access policy

**Infrastructure**
- Dockerfile based on python:3.11-slim with non-root user
- docker-compose.yml with network isolation (agent has no direct internet)
- Setup wizard for interactive configuration
- Honeypot files with realistic fake credentials
- 264 tests across 10 test files - all passing
