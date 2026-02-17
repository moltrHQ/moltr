# Moltr Security — Installation Guide

## 3 Steps: Clone, Configure, Run

### Step 1: Clone

```bash
git clone https://github.com/moltrHQ/moltr-security.git
cd moltr-security
```

### Step 2: Configure

Edit the allowlists in `config/allowlists/` for your agent's needs:

```bash
# Which domains your agent may access
nano config/allowlists/domains.yaml

# Which filesystem paths are allowed
nano config/allowlists/paths.yaml

# Which shell commands are permitted
nano config/allowlists/commands.yaml
```

Optional: Enable Telegram alerts in `docker-compose.yml`:
```yaml
environment:
  - MOLTR_TELEGRAM_BOT_TOKEN=your_bot_token
  - MOLTR_TELEGRAM_CHAT_ID=your_chat_id
```

### Step 3: Run

```bash
docker compose up -d
```

Verify it's running:
```bash
curl http://localhost:8420/health
# {"status": "ok", "timestamp": "2026-02-17T..."}
```

---

## Integration Examples

### Python Agent

```python
import requests

MOLTR = "http://localhost:8420"

# Check before executing
def safe_execute(command):
    check = requests.post(f"{MOLTR}/check/command", json={"command": command})
    if check.json()["allowed"]:
        return execute(command)
    raise SecurityError(check.json()["reason"])

# Scan before sending output
def safe_output(text):
    scan = requests.post(f"{MOLTR}/scan/output", json={"text": text})
    if scan.json()["allowed"]:
        return text
    return "[Redacted]"
```

### Node.js / TypeScript Agent

```typescript
const MOLTR = "http://localhost:8420";

async function checkCommand(cmd: string): Promise<boolean> {
  const res = await fetch(`${MOLTR}/check/command`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command: cmd }),
  });
  const { allowed, reason } = await res.json();
  if (!allowed) console.warn(`Blocked: ${reason}`);
  return allowed;
}
```

### Docker Networking (recommended)

For maximum isolation, run your agent in the same Docker network:

```yaml
# docker-compose.yml
services:
  moltr-security:
    build: .
    ports: ["8420:8420"]
    networks: [moltr-internal, moltr-external]

  my-agent:
    image: my-agent:latest
    environment:
      - MOLTR_URL=http://moltr-security:8420
    networks:
      - moltr-internal    # NO direct internet access
    depends_on:
      - moltr-security

networks:
  moltr-internal:
    internal: true        # Isolated — no internet
  moltr-external:
    driver: bridge        # Only Moltr has internet
```

Your agent can only reach the internet through Moltr. Every request is validated.

---

## Running Without Docker

```bash
pip install -r requirements.txt
python -m uvicorn src.api.server:app --host 0.0.0.0 --port 8420 --log-level info
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 8420 already in use | Change port in `docker-compose.yml` and Dockerfile |
| Agent can't reach Moltr | Ensure both are on `moltr-internal` network |
| Too many false positives | Adjust allowlists in `config/allowlists/` |
| Lockdown triggered | Check `logs/moltr-forensic.log`, restart container |
