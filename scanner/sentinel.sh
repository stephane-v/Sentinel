#!/bin/bash
set -euo pipefail

# === Configuration ===
PROJECTS_DIR="${2:-/projects}"
REPORTS_DIR="/reports"
DATA_DIR="/data"
SCAN_DEPTH="${SCAN_DEPTH:-4}"
SEVERITY_MIN="${SEVERITY_MIN:-medium}"
REPORT_FILE="$REPORTS_DIR/sentinel-$(date +%Y-%m-%d_%H%M%S).md"
EXIT_CODE=0

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
    grype db update --cache-dir "$DATA_DIR/grype" 2>&1

    # Mise à jour base osv-scanner (se fait automatiquement mais on force)
    echo "-- OSV Scanner --"
    osv-scanner --experimental-offline --experimental-download-offline-databases 2>&1 || true

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

    # Vérifier que le répertoire est monté
    if [ ! -d "$PROJECTS_DIR" ]; then
      echo "ERREUR: $PROJECTS_DIR n'existe pas. As-tu monté le volume ?"
      exit 1
    fi

    # Créer le répertoire de rapports
    mkdir -p "$REPORTS_DIR"

    # Initialiser le rapport
    cat > "$REPORT_FILE" <<EOF
# Rapport Sentinel — Audit Supply Chain
**Date** : $(date '+%Y-%m-%d %H:%M:%S')
**Cible** : $PROJECTS_DIR
**Seuil minimum** : $SEVERITY_MIN

---

EOF

    # === Phase 1 : Découverte des projets ===
    echo "=== Phase 1 : Découverte des projets ==="

    PYTHON_PROJECTS=()
    NODE_PROJECTS=()

    while IFS= read -r f; do
      [ -z "$f" ] && continue
      PYTHON_PROJECTS+=("$(dirname "$f")")
    done < <(find "$PROJECTS_DIR" -maxdepth "$SCAN_DEPTH" \
      \( -name "requirements.txt" -o -name "requirements-*.txt" -o -name "pyproject.toml" \) \
      -not -path "*/venv/*" -not -path "*/.venv/*" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | sort -u)

    while IFS= read -r f; do
      [ -z "$f" ] && continue
      NODE_PROJECTS+=("$(dirname "$f")")
    done < <(find "$PROJECTS_DIR" -maxdepth "$SCAN_DEPTH" -name "package-lock.json" \
      -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | sort -u)

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
