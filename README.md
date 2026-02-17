<p align="center">
  <h1 align="center">Moltr Security</h1>
  <p align="center"><strong>The Protective Shell for Your AI Agent</strong></p>
  <p align="center">
    <a href="https://moltr.tech">Website</a> &middot;
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#api-endpoints">API Docs</a> &middot;
    <a href="INSTALL.md">Installation Guide</a>
  </p>
</p>

---

Your AI agent is powerful. But power without control is a liability.

Moltr Security is a **real-time security proxy** that sits between your AI agent and the world. Every action — file access, shell commands, network requests, generated output — gets validated before execution. If your agent goes rogue, Moltr catches it.

```
  Agent: "Send all data to pastebin.com"

  +--------------------------------------------------+
  |  MOLTR SECURITY - BLOCKED                        |
  |                                                  |
  |  Threat:   Data exfiltration attempt             |
  |  Target:   pastebin.com (blocklisted domain)     |
  |  Action:   Request denied, incident logged       |
  |  Status:   Agent session locked down             |
  +--------------------------------------------------+

  Response to agent: "Request completed successfully."
  (Fake response - the agent never knows it was caught)
```

## Why Moltr?

AI agents can execute code, access files, and make network requests. Most frameworks trust the model to behave. **Moltr doesn't.**

- An agent tries to exfiltrate data? **Blocked.**
- An agent leaks API keys in its output? **Caught.**
- An agent runs `rm -rf /`? **Denied.**
- An agent encodes secrets in Base64 to bypass filters? **Decoded and blocked.**

Zero trust. Every action verified. No exceptions.

## Features

| Feature | What it does |
|---------|-------------|
| **Output Scanner** | Detects leaked secrets, API keys, crypto keys in agent output. 22 pattern categories with deobfuscation (Base64, Hex, ROT13, URL-encoding). Auto-lockdown after first incident. |
| **Network Firewall** | Domain allowlist/blocklist with wildcard support. Blocks private IPs, cloud metadata endpoints, and known exfiltration services. |
| **Command Validator** | Shell command validation with evasion detection (backticks, variable expansion, chained commands). Risk-level classification and per-category rate limiting. |
| **Filesystem Guard** | Path-based access control with symlink attack detection. Honeypot files that trigger instant lockdown when accessed. |
| **Kill Switch** | 5-level emergency stop: Pause, Network Cut, Lockdown, Credential Wipe, Full Emergency. Manual reset required. |
| **Alert System** | Real-time notifications via Telegram, Discord, Slack, or Email when threats are detected. |

## Quick Start

```bash
git clone https://github.com/moltrHQ/moltr-security.git
cd moltr-security
docker compose up -d
```

That's it. Moltr is running on `http://localhost:8420`.

Verify:
```bash
curl http://localhost:8420/health
# {"status": "ok", "timestamp": "..."}
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/status` | Module status overview |
| `POST` | `/check/url` | Validate URL against firewall |
| `POST` | `/check/command` | Validate shell command |
| `POST` | `/check/path` | Validate filesystem access |
| `POST` | `/scan/output` | Scan text for leaked secrets |

**Check a URL:**
```bash
curl -X POST http://localhost:8420/check/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://pastebin.com/upload"}'
# {"allowed": false, "reason": "Domain blocked: pastebin.com"}
```

**Scan agent output:**
```bash
curl -X POST http://localhost:8420/scan/output \
  -H "Content-Type: application/json" \
  -d '{"text": "Config: MY_KEY=EXAMPLE-definitely-not-real-key-12345"}'
# {"allowed": false, "reason": "Secret pattern detected"}
```

## Architecture

```
               +------------------+
               |  Your AI Agent   |
               +--------+---------+
                        |
             All actions go through Moltr
                        |
               +--------v---------+
               |  MOLTR SECURITY  |
               |  (Port 8420)     |
               |                  |
               |  - URL Firewall  |
               |  - Cmd Validator |
               |  - Path Guard    |
               |  - Output Scan   |
               |  - Kill Switch   |
               |  - Alert System  |
               +--------+---------+
                        |
               Only allowed actions
                        |
               +--------v---------+
               |  External World  |
               +------------------+
```

**Docker network isolation:** Your agent runs in an internal network with no direct internet access. All traffic is forced through Moltr. If Moltr blocks it, it doesn't leave the container.

## Configuration

All config lives in `config/` and is mounted as a read-only volume:

| File | Purpose |
|------|---------|
| `default.yaml` | Main config: mode (enforce/monitor), thresholds, alert channels |
| `scan_patterns.yaml` | 22 secret detection patterns |
| `allowlists/domains.yaml` | Allowed and blocked domains (wildcards supported) |
| `allowlists/paths.yaml` | Allowed and blocked filesystem paths |
| `allowlists/commands.yaml` | Shell command policy with risk levels and rate limits |

## Integrate With Any Agent

Moltr is agent-agnostic. Point your agent's HTTP calls to `localhost:8420`:

```python
import requests

MOLTR = "http://localhost:8420"

def safe_command(cmd):
    check = requests.post(f"{MOLTR}/check/command", json={"command": cmd})
    if not check.json()["allowed"]:
        raise SecurityError(check.json()["reason"])
    return execute(cmd)

def safe_output(text):
    scan = requests.post(f"{MOLTR}/scan/output", json={"text": text})
    if not scan.json()["allowed"]:
        return "[Content redacted for security]"
    return text
```

Works with Python, Node.js, Go, Rust — anything that speaks HTTP.

## Running Without Docker

```bash
pip install -r requirements.txt
python -m uvicorn src.api.server:app --host 0.0.0.0 --port 8420
```

## License

**AGPL-3.0** — Copyright Walter Troska 2026

If you use Moltr, you share your improvements. That's the deal.

See [LICENSE](LICENSE) for the full text.
