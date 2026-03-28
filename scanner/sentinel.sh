#!/bin/bash
set -uo pipefail

# === Configuration ===
# SECURITY: .env files are excluded from ALL scans by design.
# Their content (secrets, tokens, API keys) is never read, logged, or sent to external tools.
PROJECTS_DIR="${2:-/projects}"
REPORTS_DIR="/reports"
DATA_DIR="/data"
SCAN_DEPTH="${SCAN_DEPTH:-4}"
SEVERITY_MIN="${SEVERITY_MIN:-medium}"
EXCLUDE_DIRS="${EXCLUDE_DIRS:-sentinel}"
REPORT_FILE="$REPORTS_DIR/sentinel-$(date +%Y-%m-%d_%H%M%S).md"
EXIT_CODE=0

# Construire les options find/grep d'exclusion a partir de EXCLUDE_DIRS
FIND_PRUNE=""
GREP_EXCLUDE_DIRS=""
if [ -n "$EXCLUDE_DIRS" ]; then
  IFS=',' read -ra _EXCLUDE_ARRAY <<< "$EXCLUDE_DIRS"
  for _dir in "${_EXCLUDE_ARRAY[@]}"; do
    _dir=$(echo "$_dir" | xargs)  # trim
    [ -z "$_dir" ] && continue
    FIND_PRUNE="$FIND_PRUNE -path */$_dir -o"
    GREP_EXCLUDE_DIRS="$GREP_EXCLUDE_DIRS --exclude-dir=$_dir"
  done
fi

# Couleurs
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# === Fonctions utilitaires ===
log_critical() { echo -e "${RED}[CRITIQUE]${NC} $*" >&2; EXIT_CODE=2; }
log_warning()  { echo -e "${YELLOW}[ALERTE]${NC} $*" >&2; [ "$EXIT_CODE" -lt 1 ] && EXIT_CODE=1; }
log_ok()       { echo -e "${GREEN}[OK]${NC} $*"; }

# === Commandes ===
case "${1:-scan}" in
  update)
    echo "=== Mise à jour des bases de vulnérabilités ==="

    # Mise à jour base grype
    echo "-- Grype --"
    GRYPE_DB_CACHE_DIR="$DATA_DIR/grype" grype db update 2>&1

    # Mise à jour base osv-scanner (se fait automatiquement au scan)
    echo "-- OSV Scanner --"
    osv-scanner --experimental-local-db --experimental-download-offline-databases 2>&1 || true

    # Mise à jour des listes IOC custom
    echo "-- IOCs custom --"
    echo "Les fichiers IOC doivent être mis à jour manuellement ou via un script dédié."
    echo "Dernière mise à jour IOCs : $(stat -c '%y' /sentinel/iocs/compromised_npm.txt 2>/dev/null || echo 'inconnue')"

    echo "=== Bases mises à jour ==="
    exit 0
    ;;

  scan)
    echo "============================================"
    echo "  SENTINEL — Supply Chain Security Scanner"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Cible : $PROJECTS_DIR"
    echo "============================================"
    echo ""

    # Vérifier la présence des bases de vulnérabilités
    GRYPE_DB="$DATA_DIR/grype"
    if [ ! -d "$GRYPE_DB" ] || [ -z "$(ls -A "$GRYPE_DB" 2>/dev/null)" ]; then
      echo -e "${YELLOW}[ALERTE]${NC} Base Grype absente. Lancez d'abord :"
      echo "  docker compose run --rm sentinel update"
      echo ""
    else
      GRYPE_DATE=$(find "$GRYPE_DB" -type f -name "*.db" -printf '%TY-%Tm-%Td %TH:%TM\n' 2>/dev/null | head -1 || true)
      [ -z "$GRYPE_DATE" ] && GRYPE_DATE=$(stat -c '%y' "$GRYPE_DB" 2>/dev/null | cut -d'.' -f1 || echo "?")
      echo "  Base Grype : $GRYPE_DATE"
    fi

    # Vérifier que le répertoire est monté
    if [ ! -d "$PROJECTS_DIR" ]; then
      echo "ERREUR: $PROJECTS_DIR n'existe pas. As-tu monté le volume ?"
      exit 1
    fi

    # Vérifier que le répertoire de rapports est accessible en écriture
    mkdir -p "$REPORTS_DIR" 2>/dev/null || true
    if [ ! -w "$REPORTS_DIR" ]; then
      echo "ERREUR: $REPORTS_DIR n'est pas accessible en écriture."
      echo "Vérifiez les permissions du répertoire ./reports sur l'hôte :"
      echo "  mkdir -p reports && chmod 777 reports"
      echo "  # ou lancez avec : UID=\$(id -u) GID=\$(id -g) docker compose run --rm sentinel"
      exit 1
    fi

    # Initialiser le rapport
    cat > "$REPORT_FILE" <<EOF
# Rapport Sentinel — Audit Supply Chain
**Date** : $(date '+%Y-%m-%d %H:%M:%S')
**Cible** : $PROJECTS_DIR
**Seuil minimum** : $SEVERITY_MIN
**Base Grype** : ${GRYPE_DATE:-non installee}

---

EOF

    # === Phase 1 : Découverte des projets ===
    echo "=== Phase 1 : Découverte des projets ==="

    PYTHON_PROJECTS=()
    NODE_PROJECTS=()

    # Fonction utilitaire find avec exclusions
    _find_excluded() {
      local args=("$@")
      if [ -n "$FIND_PRUNE" ]; then
        # shellcheck disable=SC2086
        find "${args[@]}" \( -path "*/.git" $FIND_PRUNE -false \) -prune -o -type f -print 2>/dev/null
      else
        find "${args[@]}" -not -path "*/.git/*" -type f -print 2>/dev/null
      fi
    }

    while IFS= read -r f; do
      [ -z "$f" ] && continue
      PYTHON_PROJECTS+=("$(dirname "$f")")
    done < <(find "$PROJECTS_DIR" -maxdepth "$SCAN_DEPTH" \
      \( -name "requirements.txt" -o -name "requirements-*.txt" -o -name "pyproject.toml" \) \
      -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/node_modules/*" -not -path "*/.git/*" \
      $(for _d in $(echo "$EXCLUDE_DIRS" | tr ',' ' '); do echo "-not -path */$_d/*"; done) \
      2>/dev/null | sort -u)

    while IFS= read -r f; do
      [ -z "$f" ] && continue
      NODE_PROJECTS+=("$(dirname "$f")")
    done < <(find "$PROJECTS_DIR" -maxdepth "$SCAN_DEPTH" -name "package-lock.json" \
      -not -path "*/node_modules/*" -not -path "*/.git/*" \
      $(for _d in $(echo "$EXCLUDE_DIRS" | tr ',' ' '); do echo "-not -path */$_d/*"; done) \
      2>/dev/null | sort -u)

    echo "Projets Python trouvés : ${#PYTHON_PROJECTS[@]}"
    echo "Projets Node.js trouvés : ${#NODE_PROJECTS[@]}"

    echo "## Projets découverts" >> "$REPORT_FILE"
    echo "- **Python** : ${#PYTHON_PROJECTS[@]}" >> "$REPORT_FILE"
    echo "- **Node.js** : ${#NODE_PROJECTS[@]}" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # === Phase 2 : Scan IOCs (fichiers/patterns malveillants) ===
    echo ""
    echo "=== Phase 2 : Recherche IOCs ==="
    source /sentinel/scan_iocs.sh "$PROJECTS_DIR" "$REPORT_FILE"

    # === Phase 3 : Scan Python ===
    echo ""
    echo "=== Phase 3 : Scan projets Python ==="
    for proj in "${PYTHON_PROJECTS[@]}"; do
      source /sentinel/scan_python.sh "$proj" "$REPORT_FILE"
    done

    # === Phase 4 : Scan Node.js ===
    echo ""
    echo "=== Phase 4 : Scan projets Node.js ==="
    for proj in "${NODE_PROJECTS[@]}"; do
      source /sentinel/scan_node.sh "$proj" "$REPORT_FILE"
    done

    # === Phase 5 : Scan Dockerfiles et docker-compose ===
    echo ""
    echo "=== Phase 5 : Analyse sécurité Docker ==="
    source /sentinel/scan_docker.sh "$PROJECTS_DIR" "$REPORT_FILE"

    # === Résumé final ===
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "## Résultat global" >> "$REPORT_FILE"
    case $EXIT_CODE in
      0) echo "**✅ CLEAN** — Aucune vulnérabilité critique ni IOC détecté." >> "$REPORT_FILE" ;;
      1) echo "**⚠️ ALERTES** — Des vulnérabilités ou mauvaises pratiques ont été détectées." >> "$REPORT_FILE" ;;
      2) echo "**❌ CRITIQUE** — Des IOCs ou paquets compromis ont été détectés. Action immédiate requise." >> "$REPORT_FILE" ;;
    esac

    echo ""
    echo "============================================"
    echo "  Rapport : $REPORT_FILE"
    echo "  Code retour : $EXIT_CODE"
    echo "============================================"

    exit $EXIT_CODE
    ;;

  *)
    echo "Usage: sentinel.sh [scan|update] [répertoire]"
    exit 1
    ;;
esac
