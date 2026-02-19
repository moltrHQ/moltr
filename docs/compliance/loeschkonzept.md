# Löschkonzept – Moltr Security

**Rechtsgrundlage:** Art. 17 DSGVO (Recht auf Löschung), Art. 5 Abs. 1 lit. e DSGVO (Speicherbegrenzung)

---

## 1. Übersicht der Datenkategorien

| Kategorie | Beispiel | Rechtsgrundlage | Speicherfrist | Löschung |
|-----------|----------|-----------------|---------------|----------|
| **Session-Daten** | JWT-Tokens, Refresh-Sessions | Vertragserfüllung (Art. 6 Abs. 1 lit. b) | 30 Min Inaktivität | Automatisch nach Timeout |
| **Login-Protokolle** | Fehlgeschlagene Logins, IP-Logs | Berechtigtes Interesse (Art. 6 Abs. 1 lit. f) | 7 Tage | Automatisch |
| **Incident-Logs** | Blockierte Aktionen, Alerts | Rechtliche Verpflichtung (Art. 6 Abs. 1 lit. c) | 90 Tage | Automatisch |
| **Forensische Logs** | Detaillierte Incident-Reports | Berechtigtes Interesse | 30 Tage | Automatisch |
| **User-Credentials** | Passwort-Hashes (Dashboard) | Vertragserfüllung | Solange Account aktiv | Bei Account-Löschung |
| **API-Keys** | Externe API-Zugänge | Vertragserfüllung | Solange aktiv | Bei Widerruf |
| **Telegram-User-Daten** | Chat-Logs (falls gespeichert) | Einwilligung / Berechtigtes Interesse | 30 Tage oder user-definiert | Automatisch / Auf Anfrage |

---

## 2. Löschfristen nach Art. 17 DSGVO

### 2.1 Regellöschfristen

| Datenart | Frist | Begründung |
|----------|-------|------------|
| Login-Fehler | 7 Tage | Sicherheit, Missbrauchserkennung |
| Session-Tokens | 30 Min / 24h (Refresh) | Betrieb Notwendig |
| Incident-Logs | 90 Tage | Nachweispflicht, Behördenanfragen |
| Forensische Logs | 30 Tage | Sicherheitsanalyse |
| Audit-Trails | 1 Jahr | Compliance-Anforderungen |

### 2.2 Anlassbezogene Löschung

- **Benutzeranfrage (Art. 17):** Innerhalb von 30 Tagen
- **Widerruf der Einwilligung:** Sofortige Löschung der betroffenen Daten
- **Datenpannen:** Prüfung ob Löschung erforderlich (72h-Meldefrist)
- **Account-Löschung:** Vollständige Entfernung innerhalb von 30 Tagen

---

## 3. Backup-Löschung

### 3.1 Problem

Backups sind von der Löschpflicht nicht ausgenommen! Art. 17 gilt auch für Backups.

### 3.2 Lösung

| Backup-Typ | Strategie |
|------------|-----------|
| **Tägliche DB-Backups** | Retention: 7 Tage, dann überschreiben |
| **Wöchentliche Full-Backups** | Retention: 4 Wochen |
| **Monatliche Archives** | Retention: 12 Monate |
| **Verschlüsselte Backups** | Separate Löschung mit garantierter Zerstörung |

### 3.3 Umsetzung

```python
# Pseudocode für Backup-Cleanup
BACKUP_RETENTION = {
    "daily": 7,    # Tage
    "weekly": 28,  # Tage
    "monthly": 365 # Tage
}

def cleanup_old_backups():
    for backup in list_backups():
        age = days_since(backup.timestamp)
        if age > BACKUP_RETENTION[backup.type]:
            secure_delete(backup)  # Überschreiben vor Löschen
```

---

## 4. Automatisierte Löschung

### 4.1 Implementierung

- **Täglicher Cron-Job:** Prüft auf abgelaufene Datensätze
- **Session-Store:** `cleanup()` wird bei jedem Validate aufgerufen
- **Logs:** Automatische Rotation via logrotate

### 4.2 Cleanup-Funktionen

```python
# session_store.py
def cleanup(self) -> int:
    """Entferne abgelaufene und widerrufene Sessions."""
    now = time.time()
    removed = 0
    with self._lock:
        to_remove = [
            tid
            for tid, s in self._sessions.items()
            if s.revoked or now - s.last_activity > self._inactivity_timeout * 2
        ]
        for tid in to_remove:
            del self._sessions[tid]
            removed += 1
    return removed
```

---

## 5. Löschprotokoll

**Rechtsgrundlage:** Art. 30 Abs. 2 DSGVO (Verzeichnis der Verarbeitungstätigkeiten)

Jede Löschung wird protokolliert:

| Feld | Beispiel |
|------|----------|
| timestamp | 2026-02-19T17:30:00Z |
| data_category | incident_logs |
| reason | retention_expired |
| user_id | user_123 (falls relevant) |
| performed_by | system (automated) |

---

## 6. Löschvalidierung

### 6.1 Tests

- [ ] Nach 30 Min Inaktivität: Session gelöscht
- [ ] Nach 7 Tagen: Login-Fehler gelöscht
- [ ] Nach 90 Tagen: Incident-Logs gelöscht
- [ ] Nach Account-Löschung: Alle User-Daten entfernt

### 6.2 Monitoring

- Wöchentlicher Report: Anzahl gelöschter Datensätze
- Alert bei Fehlschlag der automatischen Löschung

---

## 7. Rechtliche Hinweise

⚠️ **Dieses Löschkonzept ist eine technische Orientierungshilfe und keine Rechtsberatung.** Konsultiere einen Datenschutzbeauftragten für die finale Freigabe.

**Änderungen:**
- 2026-02-19: Initiale Version für Moltr Security
