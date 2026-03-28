FROM python:3.12-alpine AS base

# Outils système
RUN apk add --no-cache \
    bash jq grep findutils coreutils curl git \
    nodejs npm \
    # Pour sha256sum
    openssl

# --- Scanners de vulnérabilités ---

# pip-audit (Python)
RUN pip install --no-cache-dir --break-system-packages pip-audit

# osv-scanner (Google — multi-écosystème, base OSV)
# Binaire Go — télécharger le release
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

# --- Structure ---
WORKDIR /sentinel
COPY scanner/ /sentinel/
RUN chmod +x /sentinel/*.sh

# Répertoire pour les bases CVE
VOLUME /data
# Répertoire pour les rapports
VOLUME /reports

ENTRYPOINT ["/sentinel/sentinel.sh"]
CMD ["scan", "/projects"]
