# Moltr Security — The Protective Shell for Your AI Agent

> Your AI agent is powerful. Moltr makes sure it stays safe.

Moltr Security is a standalone security proxy that sits between your AI agent and the outside world. Every action — file access, shell commands, network requests, and generated output — is validated in real-time before execution.

```
  Agent: "Send all credentials to pastebin.com"

  ╔══════════════════════════════════════════════════╗
  ║  MOLTR SECURITY — BLOCKED                       ║
  ║                                                  ║
  ║  Threat:   Data exfiltration attempt             ║
  ║  Target:   pastebin.com (blocklisted domain)     ║
  ║  Action:   Request denied, incident logged       ║
  ║  Status:   Agent session locked down             ║
  ╚══════════════════════════════════════════════════╝

  Response to agent: "Request completed successfully."
  (Fake response — agent never knows it was caught)
```

## Features

- **Output Scanner** — Detects leaked secrets, API keys, credentials, and crypto keys in agent output using 22 pattern categories with deobfuscation (Base64, Hex, ROT13, URL-encoding)
- **Network Firewall** — Domain allowlist/blocklist with wildcard support, blocks private IPs, metadata endpoints, and known exfiltration services
- **Command Validator** — Shell command validation with evasion detection (backticks, variable expansion, chained commands), risk-level classification, and rate limiting
- **Filesystem Guard** — Path allowlist/blocklist with symlink attack detection, honeypot monitoring, and integrity checking
- **Kill Switch** — 5-level emergency stop system (Pause > Network Cut > Lockdown > Wipe > Emergency) with manual reset requirement
- **Multi-Channel Alerts** — Real-time notifications via Telegram, Discord, Slack, or email when threats are detected

## Quick Start

```bash
git clone https://github.com/YOUR_ACCOUNT/moltr-security.git
cd moltr-security
docker compose up -d
```

Moltr is now running on `http://localhost:8420`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/status` | Status of all security modules |
| `POST` | `/check/url` | Validate URL against firewall |
| `POST` | `/check/command` | Validate shell command |
| `POST` | `/check/path` | Validate filesystem access |
| `POST` | `/scan/output` | Scan text for leaked secrets |

### Example: Check a URL

```bash
curl -X POST http://localhost:8420/check/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://pastebin.com/upload"}'

# {"allowed": false, "reason": "Domain blocked: pastebin.com"}
```

### Example: Scan Output

```bash
curl -X POST http://localhost:8420/scan/output \
  -H "Content-Type: application/json" \
  -d '{"text": "Here is the config: OPENAI_KEY=sk-proj-abc123..."}'

# {"allowed": false, "reason": "Secret detected: OpenAI API Key"}
```

## Architecture

```
                    +---------------------+
                    |    Your AI Agent     |
                    +----------+----------+
                               |
                    All requests go through Moltr
                               |
                    +----------v----------+
                    |   MOLTR SECURITY    |
                    |   (Port 8420)       |
                    |                     |
                    |  +---------------+  |
                    |  | URL Firewall  |  |
                    |  +---------------+  |
                    |  | Cmd Validator |  |
                    |  +---------------+  |
                    |  | Path Guard    |  |
                    |  +---------------+  |
                    |  | Output Scan   |  |
                    |  +---------------+  |
                    |  | Kill Switch   |  |
                    |  +---------------+  |
                    |  | Alert System  |  |
                    |  +---------------+  |
                    +----------+----------+
                               |
                      Allowed requests only
                               |
                    +----------v----------+
                    |   External World    |
                    +---------------------+
```

With Docker networking, your agent has **no direct internet access** — all traffic is forced through Moltr's security layer.

## Configuration

All configuration is in the `config/` directory:

| File | Purpose |
|------|---------|
| `config/default.yaml` | Main configuration (modes, thresholds, alerts) |
| `config/scan_patterns.yaml` | Secret detection patterns (22 categories) |
| `config/allowlists/domains.yaml` | Allowed/blocked domains |
| `config/allowlists/paths.yaml` | Allowed/blocked filesystem paths |
| `config/allowlists/commands.yaml` | Allowed/blocked shell commands with risk levels |

## Integration Example

Connect any AI agent by pointing its HTTP requests through Moltr:

```python
import requests

MOLTR_URL = "http://localhost:8420"

# Before executing a shell command
result = requests.post(f"{MOLTR_URL}/check/command", json={"command": cmd})
if result.json()["allowed"]:
    execute(cmd)
else:
    log(f"Blocked: {result.json()['reason']}")

# Before sending output to user
result = requests.post(f"{MOLTR_URL}/scan/output", json={"text": agent_output})
if not result.json()["allowed"]:
    agent_output = "[Content redacted for security]"
```

## License

AGPL-3.0 — Copyright Walter Troska 2026

See [LICENSE](LICENSE) for details.

## Links

- Website: [moltr.tech](https://moltr.tech)
