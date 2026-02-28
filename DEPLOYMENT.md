# Deployment

## Git Workflow

```
dev → test → main
```

Jeder Push triggert GitHub Actions: Docker-Image Build + Push zu GHCR.

## Befehle

### 1. DEV pushen

```bash
git add -A && git commit -m "v1.1.7" && git push origin dev
```

### 2. DEV → TEST mergen und pushen

```bash
git checkout test && git merge dev && git push origin test && git checkout dev
```

### 3. TEST → PROD mergen und pushen

```bash
git checkout main && git merge test && git push origin main && git checkout dev
```

### Komplett-Deployment (DEV → TEST → PROD)

```bash
git checkout test && git merge dev && git push origin test && git checkout main && git merge test && git push origin main && git checkout dev
```

## Server: Docker Container aktualisieren

```bash
# DEV
docker compose --env-file .env -p contracts-dev -f docker-compose.dev.yml up -d --pull always

# TEST
docker compose --env-file .env -p contracts-test -f docker-compose.test.yml up -d --pull always

# PROD
docker compose --env-file .env -p contracts-prod -f docker-compose.prod.yml up -d --pull always
```
