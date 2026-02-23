import urllib.request, json, time, os

token = os.environ.get('TALON_BOT_TOKEN', '')
if not token:
    raise RuntimeError('TALON_BOT_TOKEN env var not set')
chat_id = '-5272352642'

msgs = [
    (
        "*Dungeoncore einrichten — Step by Step*\n\n"
        "Oeffne eine CMD oder PowerShell auf dem Server und fuehre folgende Befehle aus:\n\n"
        "*Schritt 1: Zum Verzeichnis navigieren*\n"
        "```\n"
        "cd \"C:\\Users\\Administrator\\Desktop\\MoltrHQ Codebase\\moltr-security\"\n"
        "```"
    ),
    (
        "*Schritt 2: Key-Inventar anzeigen (optional)*\n\n"
        "Zeigt dir alle kritischen Keys aus deinen .env Dateien:\n"
        "```\n"
        "python dc-inventory.py\n"
        "```\n\n"
        "Du siehst welche 21 Keys in den Dungeoncore gehoeren.\n"
        "Tipp: Lass das Fenster offen — du brauchst die Keys gleich."
    ),
    (
        "*Schritt 3: Dungeoncore initialisieren*\n"
        "```\n"
        "python dungeoncore.py init\n"
        "```\n\n"
        "Der Wizard fragt dich:\n\n"
        "1. *Name* — Enter druecken fuer Default `Dungeoncore`\n"
        "   (oder eigenen Namen tippen, z.B. `Rezepte`)\n\n"
        "2. *Passphrase* — mind. 12 Zeichen\n"
        "   Schreib sie JETZT offline auf!\n\n"
        "3. *Keys eingeben* — Format: `KEY_NAME=wert`\n"
        "   Zum Beenden: leere Zeile + Enter"
    ),
    (
        "*Schritt 4: Welche Keys eingeben?*\n\n"
        "Kopiere diese Keys aus deinen .env Dateien:\n\n"
        "`ANTHROPIC_API_KEY=sk-ant-...`\n"
        "`GROQ_API_KEY=gsk_...`\n"
        "`OPENAI_API_KEY=sk-proj-...`\n"
        "`TELEGRAM_BOT_TOKEN=8561659389:...` (Talon)\n"
        "`SUPABASE_ANON_KEY=eyJhbG...`\n"
        "`MOLTR_API_KEY=tBC9py...`\n"
        "`ADA_RELAY_KEY=lS290P...`\n"
        "`TALON_RELAY_KEY=Jzkvm0...`\n\n"
        "Du kannst auch erstmal nur 2-3 Keys eingeben und spaeter mit `add` ergaenzen."
    ),
    (
        "*Schritt 5: Testen*\n\n"
        "Nach dem Init — Status pruefen:\n"
        "```\n"
        "python dungeoncore.py status\n"
        "```\n\n"
        "Dann in Telegram an @Talon_Terminal_Bot schreiben:\n"
        "`/dc-status`\n\n"
        "Antwort: *Dungeoncore — GESPERRT* (noch nicht entsperrt)\n\n"
        "Zum Entsperren schreib an @Talon_Terminal_Bot:\n"
        "`/unlock`\n"
        "Bot fragt nach Passphrase → eingeben → Session laeuft 8h"
    ),
    (
        "*Keys spaeter ergaenzen*\n\n"
        "Jederzeit mit:\n"
        "```\n"
        "python dungeoncore.py add ANTHROPIC_API_KEY\n"
        "```\n"
        "Oder alle Keys anzeigen (nur Namen, keine Werte):\n"
        "```\n"
        "python dungeoncore.py list\n"
        "```\n\n"
        "*Wichtig:* Die Passphrase liegt NUR offline bei dir.\n"
        "Kein Agent kennt sie. Ohne sie sind alle Keys verloren."
    ),
]

for text in msgs:
    data = json.dumps({'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}).encode('utf-8')
    req = urllib.request.Request(
        f'https://api.telegram.org/bot{token}/sendMessage',
        data=data,
        headers={'Content-Type': 'application/json; charset=utf-8'}
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        print('OK' if result.get('ok') else result.get('description'))
    time.sleep(0.5)
