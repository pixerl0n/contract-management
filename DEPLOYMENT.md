# Deployment — Vertragsmanagement

## Voraussetzungen

- Docker & Docker Compose auf dem Server
- GitHub Container Registry Zugang (GHCR)
- Zentraler Auth-Service laeuft im `auth-net` Docker-Netzwerk

## .env einrichten

Erstelle eine `.env` Datei auf dem Server (siehe `.env.example`):

```bash
# GitHub Container Registry Benutzername
GHCR_USERNAME=dein-github-username

# API-Key generieren (zufaellig, sicher)
API_KEY=$(openssl rand -hex 32)

# Cookie-Domain fuer SSO (mit Punkt-Prefix fuer Subdomain-Support)
COOKIE_DOMAIN=.deine-domain.de
```

API-Key generieren:
```bash
openssl rand -hex 32
```

## Docker-Netzwerk

Alle Apps teilen sich das `auth-net` Netzwerk fuer die Kommunikation mit dem zentralen Auth-Service. Falls es noch nicht existiert:

```bash
docker network create auth-net
```

## Server-Deployment

```bash
# Dev (Port 4202)
docker compose --env-file .env -p contracts-dev -f docker-compose.dev.yml up -d --pull always

# Test (Port 4201)
docker compose --env-file .env -p contracts-test -f docker-compose.test.yml up -d --pull always

# Prod (Port 4200)
docker compose --env-file .env -p contracts-prod -f docker-compose.prod.yml up -d --pull always
```

## Lokale Entwicklung

```bash
# Starten (Port 4210, live reload via bind mounts)
docker compose -p contracts-dev-local -f docker-compose.dev.local.yml up -d --build

# Logs
docker logs -f contracts-app-dev-local

# Stoppen
docker compose -p contracts-dev-local -f docker-compose.dev.local.yml down
```

## Umgebungen

| Umgebung    | Port | NODE_ENV    | Image-Tag |
|-------------|------|-------------|-----------|
| PROD        | 4200 | production  | prod      |
| TEST        | 4201 | test        | test      |
| DEV (remote)| 4202 | development | dev       |
| LOCAL DEV   | 4210 | development | lokal     |

## CI/CD

GitHub Actions (`.github/workflows/docker.yml`) baut bei Push auf `dev`/`test`/`main` automatisch Multi-Arch Docker Images (amd64/arm64) und pusht sie in die GitHub Container Registry:

```
ghcr.io/<owner>/contracts-app:{dev,test,prod,latest}
```

## SSO / Auth-Service

Die App verbindet sich ueber das `auth-net` Docker-Netzwerk mit dem zentralen Auth-Service (`AUTH_SERVICE_URL=http://auth:3000`). Der Auth-Service verwaltet Benutzer und Sessions zentral fuer alle Apps.

`COOKIE_DOMAIN` (z.B. `.example.com`) ermoeglicht Cookie-Sharing ueber Subdomains hinweg, sodass ein Login fuer alle Apps gilt.

Ohne `AUTH_SERVICE_URL` laeuft die App im Standalone-Modus mit eigener Benutzerverwaltung.
