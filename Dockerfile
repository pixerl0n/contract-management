FROM node:24.13.1-alpine3.22

# Build-Tools für better-sqlite3 (native Kompilierung)
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Dependencies zuerst (Layer-Caching: nur neu bauen wenn package*.json geändert)
COPY package*.json ./
RUN npm ci --omit=dev

# Anwendungsdateien
COPY server.js changelog.json ./
COPY public ./public

# Datenbank-Verzeichnis mit korrekten Rechten
RUN mkdir -p /app/data && chown -R node:node /app/data

# Security: Non-root user
USER node

EXPOSE 3000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "server.js"]
