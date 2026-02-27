# Vertragsmanagement

Persoenliches Vertragsmanagement. Node.js + better-sqlite3 Backend, React 18 Frontend (kein Build-Step). Deutsche UI.

> **Datenpersistenz:** Die Datenbank liegt in einem Named Volume (`contracts-app-{env}-data`). Erst ein explizites `docker volume rm` loescht die Daten unwiderruflich!

---

## Uebersicht

| Umgebung  | Port | `NODE_ENV`  | Docker Tag | Branch | Volume |
|-----------|------|-------------|------------|--------|--------|
| PROD      | 4200 | production  | `:prod`    | main   | `contracts-app-prod-data` |
| TEST      | 4201 | test        | `:test`    | test   | `contracts-app-test-data` |
| DEV       | 4202 | development | `:dev`     | dev    | `contracts-app-dev-data` |
| LOCAL DEV | 4210 | development | lokaler Build | —  | `contracts-app-dev-local-data` |

Interner Container-Port ist immer `3000`.

---

## Features (v1.1)

- Vertragserfassung mit Name, Kategorie, Laufzeit, Kuendigungsfrist, Kosten
- Zahlungsintervall: Monatlich, Quartalsweise, Halbjaehrlich, Jaehrlich
- Automatische Berechnung der monatlichen Kosten aus Betrag und Intervall
- Kostenaufteilung: Vertraege mit mehreren Personen teilen
- Dashboard zeigt Gesamtkosten und eigenen Anteil separat an
- Cashback-Feld (Freitext) zur Erfassung von Cashback-Informationen
- Kuendigungswarnung pro Vertrag aktivierbar/deaktivierbar
- Multi-User mit Passwort-Authentifizierung und Session-Tokens
- Filter nach Kategorie, Status und Sortierung nach Name, Kosten, Kuendigungsdatum
- Suche nach Vertragsname oder Anbieter
- Kuendigungswarnung: Rot (<30 Tage), Gelb (<90 Tage), Gruen (>90 Tage)
- Kosten-Uebersicht pro Monat und Jahr, aufgeschluesselt nach Kategorie
- CSV- und JSON-Export/Import
- Responsive Design mit Dark/Light Mode

---

## 1. Lokale Entwicklung (Laptop)

### Starten

```bash
docker compose -p contracts-dev-local -f docker-compose.dev.local.yml up -d --build
```

Baut das Image lokal und mounted `server.js` + `public/` als Volumes. Aenderungen an diesen Dateien sind sofort sichtbar (Container-Neustart bei `server.js`-Aenderungen noetig).

### Logs & API-Key anzeigen

```bash
docker logs -f contracts-app-dev-local
```

### Stoppen

```bash
docker compose -p contracts-dev-local -f docker-compose.dev.local.yml down
```

### Komplett aufraeumen (inkl. Datenbank)

```bash
docker compose -p contracts-dev-local -f docker-compose.dev.local.yml down
docker volume rm contracts-app-dev-local-data
```

### App oeffnen

http://localhost:4210

---

## 2. Server einrichten (einmalig)

### Voraussetzungen

- Docker + Docker Compose auf dem Server
- GitHub Actions hat die Images bereits nach ghcr.io gepusht (`:prod`, `:test`, `:dev`)

### Schritt 1: Ordner + ghcr.io Login

```bash
# Auf dem Server:
mkdir -p ~/docker/contracts

# Bei ghcr.io einloggen (einmalig)
echo "<DEIN_GHCR_PAT>" | docker login ghcr.io -u <DEIN_GITHUB_USERNAME> --password-stdin
```

```bash
# Vom Laptop aus — Compose-Files auf den Server kopieren:
scp docker-compose.prod.yml \
    docker-compose.test.yml \
    docker-compose.dev.yml \
    user@server:~/docker/contracts/
```

### Schritt 2: `.env` Datei anlegen

```bash
cd ~/docker/contracts

# API-Key generieren
openssl rand -hex 32

# .env erstellen
cat > .env << 'EOF'
GHCR_USERNAME=dein-github-username
API_KEY=<hier-den-generierten-key-einfuegen>
EOF
```

### Ordnerstruktur auf dem Server

```
~/docker/contracts/
├── docker-compose.prod.yml     ← Port 4200, NODE_ENV=production
├── docker-compose.test.yml     ← Port 4201, NODE_ENV=test
├── docker-compose.dev.yml      ← Port 4202, NODE_ENV=development
└── .env                        ← GHCR_USERNAME + API_KEY
```

---

## 3. Umgebungen starten (Server)

### PROD starten (Port 4200)

```bash
docker compose --env-file .env -p contracts-prod -f docker-compose.prod.yml up -d --pull always
```

### TEST starten (Port 4201)

```bash
docker compose --env-file .env -p contracts-test -f docker-compose.test.yml up -d --pull always
```

### DEV starten (Port 4202)

```bash
docker compose --env-file .env -p contracts-dev -f docker-compose.dev.yml up -d --pull always
```

### Pruefen

```bash
docker ps -f name=contracts-app

curl http://localhost:4200/api/health   # PROD
curl http://localhost:4201/api/health   # TEST
curl http://localhost:4202/api/health   # DEV
```

---

## 4. Umgebungen stoppen (Server)

```bash
# PROD stoppen (Volume bleibt erhalten)
docker compose --env-file .env -p contracts-prod -f docker-compose.prod.yml down

# TEST stoppen
docker compose --env-file .env -p contracts-test -f docker-compose.test.yml down

# DEV stoppen
docker compose --env-file .env -p contracts-dev -f docker-compose.dev.yml down
```

> `down -v` loescht auch das Volume — **Datenbank wird unwiderruflich geloescht!**

---

## 5. Updates installieren (ohne Datenverlust)

1. Code auf den Branch pushen (`dev`, `test` oder `main`)
2. GitHub Actions baut automatisch das neue Docker Image
3. Auf dem Server den Befehl der jeweiligen Umgebung nochmal ausfuehren

```bash
# Beispiel: PROD updaten
docker compose --env-file .env -p contracts-prod -f docker-compose.prod.yml up -d --pull always
```

Docker Compose pullt das neueste Image, stoppt den alten Container und startet einen neuen. Das Named Volume bleibt erhalten — **die Datenbank bleibt erhalten**.

---

## 6. Git Workflow

```
dev  →  test  →  main
 ↓        ↓        ↓
:dev    :test    :prod
```

```bash
# Feature entwickeln
git checkout dev
# ... arbeiten + committen ...
git push origin dev

# Zum Testen
git checkout test && git merge dev && git push origin test

# Fuer Produktion
git checkout main && git merge test && git push origin main
```

GitHub Actions bauen automatisch das Docker Image pro Branch und pushen es nach ghcr.io.

---

## 7. CI/CD (GitHub Actions)

Die Workflow-Datei liegt unter `.github/workflows/docker.yml`.

### Authentifizierung

Der Workflow nutzt **`GITHUB_TOKEN`** (automatisch von GitHub bereitgestellt) — kein separater PAT noetig.

### Branch → Tag Mapping

| Branch | Docker Tag           |
|--------|----------------------|
| `main` | `:prod` + `:latest`  |
| `test` | `:test`              |
| `dev`  | `:dev`               |

### Features

- **Multi-Arch** Builds (`linux/amd64` + `linux/arm64`)
- **Docker Buildx** mit GitHub Actions Cache (`type=gha`)
- **OCI Labels** (`image.source`, `image.revision`, `image.created`)

---

## 8. API-Key Sicherheit

Alle Daten-Endpoints sind mit einem API-Key geschuetzt. Der Key wird bei jedem Request als `x-api-key` Header mitgeschickt.

**Offene Endpoints** (kein Key noetig): `/`, `/api/health`, `/api/version`, `/api/changelog`, `/api/categories`, `/api/billing-intervals`

| Verhalten | Details |
|-----------|---------|
| Key per Env-Variable | `API_KEY=...` in `.env` setzen |
| Kein Key gesetzt | Wird beim Start zufaellig generiert (in dev in den Logs sichtbar) |
| Frontend | Key wird automatisch vom Server ins HTML injiziert |
| POST/PUT/DELETE | Zusaetzlich Origin/Referer-Check |

---

## 9. Passwort zuruecksetzen

```bash
docker exec -it contracts-app-prod sh -c "
  sqlite3 /app/data/contracts.db \"UPDATE users SET password_hash = NULL, salt = NULL, session_token = NULL, session_expires = NULL WHERE name = 'BENUTZERNAME';\"
"
```

> Nach dem Reset wird die aktive Session ungueltig. Der Benutzer muss sich neu anmelden und ein neues Passwort vergeben.

---

## 10. Nuetzliche Befehle

```bash
# Container-Status aller Umgebungen
docker ps -f name=contracts-app

# Logs
docker logs -f contracts-app-prod
docker logs -f contracts-app-test
docker logs -f contracts-app-dev

# Datenbank-Backup (Prod)
docker cp contracts-app-prod:/app/data/contracts.db ~/backup-contracts-prod.db

# Volume-Details
docker volume inspect contracts-app-prod-data

# Alle Volumes auflisten
docker volume ls | grep contracts

# API Health Checks
curl http://localhost:4200/api/health
curl http://localhost:4200/api/version
curl http://localhost:4200/api/changelog
```
