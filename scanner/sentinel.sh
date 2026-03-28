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

# Construire les options find/grep d'exclusion a partir de EXCLUDE_DIRS
FIND_PRUNE=""
GREP_EXCLUDE_DIRS=""
if [ -n "$EXCLUDE_DIRS" ]; then
  IFS=',' read -ra _EXCLUDE_ARRAY <<< "$EXCLUDE_DIRS"
  for _dir in "${_EXCLUDE_ARRAY[@]}"; do
    _dir=$(echo "$_dir" | xargs)
    [ -z "$_dir" ] && continue
    FIND_PRUNE="$FIND_PRUNE -path */$_dir -o"
    GREP_EXCLUDE_DIRS="$GREP_EXCLUDE_DIRS --exclude-dir=$_dir"
  done
fi

# === Verdict system (4 levels) ===
# CLEAN < INFO < ATTENTION < CRITIQUE
VERDICT="CLEAN"
set_verdict() {
  local new="$1"
  case "$VERDICT" in
    CRITIQUE) return ;;  # already max
    ATTENTION) [ "$new" = "CRITIQUE" ] && VERDICT="CRITIQUE" ;;
    INFO) case "$new" in ATTENTION|CRITIQUE) VERDICT="$new" ;; esac ;;
    CLEAN) VERDICT="$new" ;;
  esac
}

# === Counters for summary ===
COUNT_CRITIQUE=0
COUNT_ATTENTION=0
COUNT_INFO=0
COUNT_FILTERED=0

# Temp files for report assembly
REPORT_BODY=$(mktemp /tmp/sentinel-body.XXXXXX)
REPORT_FILTERED=$(mktemp /tmp/sentinel-filtered.XXXXXX)

# Summary counters (set by sub-scripts)
SUMMARY_IOC_CONFIRMED=0
SUMMARY_COMPROMISED_PKG=0
SUMMARY_HASH_MATCH=0
SUMMARY_UNICODE_SOURCE=0
SUMMARY_PATTERN_SUSPECT=0
SUMMARY_SECRETS_DOCKER=0
SUMMARY_VULN_PIP=0
SUMMARY_VULN_NPM=0
SUMMARY_UNPINNED=0
SUMMARY_NO_USER=0
SUMMARY_SINGLE_STAGE=0
SUMMARY_BUILD_ARGS_SECRET=0
SUMMARY_BUILD_ARGS_SAFE=0

# Couleurs
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
GRAY='\033[0;90m'
NC='\033[0m'

# === Fonctions utilitaires ===
log_critique() { echo -e "${RED}[CRITIQUE]${NC} $*" >&2; set_verdict CRITIQUE; }
log_attention() { echo -e "${YELLOW}[ATTENTION]${NC} $*" >&2; set_verdict ATTENTION; }
log_info()     { echo -e "${BLUE}[INFO]${NC} $*"; set_verdict INFO; }
log_ok()       { echo -e "${GREEN}[OK]${NC} $*"; }
log_filtered() { echo -e "${GRAY}[FILTRE]${NC} $*"; }

# === Commandes ===
case "${1:-scan}" in
  update)
    echo "=== Mise à jour des bases de vulnérabilités ==="

    # Mise à jour base grype
    echo "-- Grype --"
    GRYPE_DB_CACHE_DIR="$DATA_DIR/grype" grype db update 2>&1

    # Mise à jour base osv-scanner
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
      GRYPE_DATE="non installee"
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

    # === Phase 1 : Découverte des projets ===
    echo "=== Phase 1 : Découverte des projets ==="

    PYTHON_PROJECTS=()
    NODE_PROJECTS=()

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

    # === Phase 2 : Scan IOCs ===
    echo ""
    echo "=== Phase 2 : Recherche IOCs ==="
    source /sentinel/scan_iocs.sh "$PROJECTS_DIR" "$REPORT_BODY"

    # === Phase 3 : Scan Python ===
    echo ""
    echo "=== Phase 3 : Scan projets Python ==="
    for proj in "${PYTHON_PROJECTS[@]}"; do
      source /sentinel/scan_python.sh "$proj" "$REPORT_BODY"
    done

    # === Phase 4 : Scan Node.js ===
    echo ""
    echo "=== Phase 4 : Scan projets Node.js ==="
    for proj in "${NODE_PROJECTS[@]}"; do
      source /sentinel/scan_node.sh "$proj" "$REPORT_BODY"
    done

    # === Phase 5 : Scan Docker ===
    echo ""
    echo "=== Phase 5 : Analyse sécurité Docker ==="
    source /sentinel/scan_docker.sh "$PROJECTS_DIR" "$REPORT_BODY"

    # === Assembler le rapport final ===
    # Verdict label
    case "$VERDICT" in
      CRITIQUE)  VERDICT_LABEL="🚨 **CRITIQUE** — IOCs confirmés ou paquets compromis détectés. Action immédiate requise." ;;
      ATTENTION) VERDICT_LABEL="⚠️ **ATTENTION** — Éléments suspects nécessitant vérification manuelle." ;;
      INFO)      VERDICT_LABEL="💡 **INFO** — Points d'attention détectés, aucune menace confirmée." ;;
      CLEAN)     VERDICT_LABEL="✅ **CLEAN** — Aucun problème détecté." ;;
    esac

    # Write final report
    cat > "$REPORT_FILE" <<HEADER
# Rapport Sentinel — Audit Supply Chain
**Date** : $(date '+%Y-%m-%d %H:%M:%S')
**Cible** : $PROJECTS_DIR
**Base Grype** : ${GRYPE_DATE}
**Projets** : ${#PYTHON_PROJECTS[@]} Python, ${#NODE_PROJECTS[@]} Node.js

---

## Verdict : $VERDICT_LABEL

| Catégorie | Résultat |
|-----------|----------|
| IOCs confirmés (fichiers/hashes) | $([ "$SUMMARY_IOC_CONFIRMED" -gt 0 ] && echo "🚨 $SUMMARY_IOC_CONFIRMED trouvé(s)" || echo "✅ 0 trouvé") |
| Paquets compromis connus | $([ "$SUMMARY_COMPROMISED_PKG" -gt 0 ] && echo "🚨 $SUMMARY_COMPROMISED_PKG trouvé(s)" || echo "✅ 0 trouvé") |
| Hashes malveillants | $([ "$SUMMARY_HASH_MATCH" -gt 0 ] && echo "🚨 $SUMMARY_HASH_MATCH trouvé(s)" || echo "✅ 0 trouvé") |
| Vulnérabilités pip-audit | $([ "$SUMMARY_VULN_PIP" -gt 0 ] && echo "⚠️ $SUMMARY_VULN_PIP projet(s) affecté(s)" || echo "✅ 0 critique") |
| Vulnérabilités npm audit | $([ "$SUMMARY_VULN_NPM" -gt 0 ] && echo "⚠️ $SUMMARY_VULN_NPM projet(s) affecté(s)" || echo "✅ 0 critique") |
| Unicode suspects (code source) | $([ "$SUMMARY_UNICODE_SOURCE" -gt 0 ] && echo "⚠️ $SUMMARY_UNICODE_SOURCE fichier(s) à vérifier" || echo "✅ 0 trouvé") |
| Patterns suspects dans le code | $([ "$SUMMARY_PATTERN_SUSPECT" -gt 0 ] && echo "⚠️ $SUMMARY_PATTERN_SUSPECT pattern(s)" || echo "✅ 0 trouvé") |
| Secrets dans build.args | $([ "$SUMMARY_BUILD_ARGS_SECRET" -gt 0 ] && echo "⚠️ $SUMMARY_BUILD_ARGS_SECRET fichier(s)" || echo "✅ 0 trouvé") |
| Dépendances non pinnées | $([ "$SUMMARY_UNPINNED" -gt 0 ] && echo "💡 ~$SUMMARY_UNPINNED sur ${#PYTHON_PROJECTS[@]} projets" || echo "✅ toutes pinnées") |
| Dockerfiles sans USER | $([ "$SUMMARY_NO_USER" -gt 0 ] && echo "💡 $SUMMARY_NO_USER fichier(s)" || echo "✅ tous avec USER") |
| Single-stage builds | $([ "$SUMMARY_SINGLE_STAGE" -gt 0 ] && echo "💡 $SUMMARY_SINGLE_STAGE fichier(s)" || echo "✅ tous multi-stage") |
| Faux positifs filtrés | $([ "$COUNT_FILTERED" -gt 0 ] && echo "⚪ $COUNT_FILTERED fichier(s) (binaires/i18n/éditeur)" || echo "⚪ 0") |

---

HEADER

    # Append body (detailed findings)
    cat "$REPORT_BODY" >> "$REPORT_FILE"

    # Append filtered false positives section
    if [ "$COUNT_FILTERED" -gt 0 ]; then
      cat >> "$REPORT_FILE" <<'FILTERED_HEADER'

---

## Faux positifs filtrés

Ces fichiers ont déclenché une règle de détection mais ont été identifiés comme
des faux positifs par les filtres Sentinel. Listés ici pour transparence.

<details>
<summary>Voir les fichiers filtrés</summary>

| Fichier | Règle | Raison du filtrage |
|---------|-------|--------------------|
FILTERED_HEADER
      cat "$REPORT_FILTERED" >> "$REPORT_FILE"
      echo "" >> "$REPORT_FILE"
      echo "</details>" >> "$REPORT_FILE"
    fi

    # Cleanup temp files
    rm -f "$REPORT_BODY" "$REPORT_FILTERED"

    # Exit code mapping
    case "$VERDICT" in
      CLEAN)     EXIT_CODE=0 ;;
      INFO)      EXIT_CODE=0 ;;
      ATTENTION) EXIT_CODE=1 ;;
      CRITIQUE)  EXIT_CODE=2 ;;
    esac

    echo ""
    echo "============================================"
    echo "  Verdict : $VERDICT"
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
