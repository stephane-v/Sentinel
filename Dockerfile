# === Stage 1: Téléchargement des outils binaires ===
FROM python:3.12-alpine AS downloader

RUN apk add --no-cache curl

# osv-scanner (Google — multi-écosystème, base OSV)
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
      x86_64) ARCH="amd64" ;; \
      aarch64) ARCH="arm64" ;; \
    esac && \
    curl -sSfL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${ARCH} \
      -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# grype (Anchore — scanner de vulnérabilités)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# === Stage 2: Dépendances Python ===
FROM python:3.12-alpine AS python-deps

RUN pip install --no-cache-dir --break-system-packages pip-audit pyyaml

# === Stage 3: Image finale minimale ===
FROM python:3.12-alpine AS final

# System tools (curl needed for IOC feed updates)
RUN apk add --no-cache \
    bash jq grep findutils coreutils curl \
    nodejs npm \
    openssl

# Copier les binaires depuis le stage downloader
COPY --from=downloader /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=downloader /usr/local/bin/grype /usr/local/bin/grype

# Copier pip-audit depuis le stage python-deps
COPY --from=python-deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=python-deps /usr/local/bin/pip-audit /usr/local/bin/pip-audit

# Utilisateur non-root
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

# Créer les répertoires de travail avec les bonnes permissions
RUN mkdir -p /reports /data /projects && \
    chown sentinel:sentinel /reports /data

# --- Structure ---
WORKDIR /sentinel
COPY scanner/ /sentinel/
RUN chmod +x /sentinel/*.sh

USER sentinel

ENTRYPOINT ["/sentinel/sentinel.sh"]
CMD ["scan", "/projects"]
