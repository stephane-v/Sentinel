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
IOC_AUTO_UPDATE="${IOC_AUTO_UPDATE:-true}"
REPORT_FILE="$REPORTS_DIR/sentinel-$(date +%Y-%m-%d_%H%M%S).md"

# === IOC directory: bind-mounted from host for persistence ===
IOC_DIR="/sentinel/iocs"
export IOC_DIR

# === Load i18n ===
REPORT_LANG="${REPORT_LANG:-en}"
I18N_FILE="$(dirname "$0")/i18n/${REPORT_LANG}.sh"
if [ -f "$I18N_FILE" ]; then
  source "$I18N_FILE"
else
  echo "Warning: language '$REPORT_LANG' not found, falling back to English"
  source "$(dirname "$0")/i18n/en.sh"
fi

# Build find/grep exclusion options from EXCLUDE_DIRS
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
VERDICT="CLEAN"
set_verdict() {
  local new="$1"
  case "$VERDICT" in
    CRITIQUE) return ;;
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
SUMMARY_VULN_GRYPE=0

# Grype availability
GRYPE_AVAILABLE=0
if command -v grype >/dev/null 2>&1; then
  GRYPE_AVAILABLE=1
fi

# Severity level mapping for filtering
_severity_rank() {
  case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
    critical) echo 4 ;;
    high) echo 3 ;;
    medium) echo 2 ;;
    low) echo 1 ;;
    *) echo 0 ;;
  esac
}
SEVERITY_MIN_RANK=$(_severity_rank "$SEVERITY_MIN")

# Colors (CLI output only — not in reports)
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
GRAY='\033[0;90m'
NC='\033[0m'

# === Utility functions ===
log_critique() { echo -e "${RED}[CRITICAL]${NC} $*" >&2; set_verdict CRITIQUE; }
log_attention() { echo -e "${YELLOW}[ATTENTION]${NC} $*" >&2; set_verdict ATTENTION; }
log_info()     { echo -e "${BLUE}[INFO]${NC} $*"; set_verdict INFO; }
log_ok()       { echo -e "${GREEN}[OK]${NC} $*"; }
log_filtered() { echo -e "${GRAY}[FILTERED]${NC} $*"; }

# === Commands ===
case "${1:-scan}" in
  update)
    echo "=== Updating vulnerability databases ==="

    echo "-- Grype --"
    GRYPE_DB_CACHE_DIR="$DATA_DIR/grype" grype db update 2>&1

    echo "-- OSV Scanner --"
    osv-scanner --experimental-local-db --experimental-download-offline-databases 2>&1 || true

    echo "-- IOC feeds --"
    if [ "$IOC_AUTO_UPDATE" = "true" ]; then
      bash "$(dirname "$0")/update_iocs.sh"
    else
      echo "IOC auto-update disabled (IOC_AUTO_UPDATE=false)"
      echo "IOC files can be updated manually in $IOC_DIR/"
    fi
    echo "Last IOC update: $(stat -c '%y' "$IOC_DIR/compromised_npm.txt" 2>/dev/null || echo 'unknown')"

    echo "=== Databases updated ==="
    exit 0
    ;;

  scan)
    echo "============================================"
    echo "  SENTINEL — Supply Chain Security Scanner"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Target: $PROJECTS_DIR"
    echo "============================================"
    echo ""

    # Check vulnerability databases
    GRYPE_DB="$DATA_DIR/grype"
    if [ ! -d "$GRYPE_DB" ] || [ -z "$(ls -A "$GRYPE_DB" 2>/dev/null)" ]; then
      echo -e "${YELLOW}[WARNING]${NC} Grype DB missing. Run first:"
      echo "  docker compose run --rm sentinel update"
      echo ""
      GRYPE_DATE="not installed"
    else
      GRYPE_DATE=$(find "$GRYPE_DB" -type f -name "*.db" -printf '%TY-%Tm-%Td %TH:%TM\n' 2>/dev/null | head -1 || true)
      [ -z "$GRYPE_DATE" ] && GRYPE_DATE=$(stat -c '%y' "$GRYPE_DB" 2>/dev/null | cut -d'.' -f1 || echo "?")
      echo "  Grype DB: $GRYPE_DATE"
    fi

    # Check project directory
    if [ ! -d "$PROJECTS_DIR" ]; then
      echo "ERROR: $PROJECTS_DIR does not exist. Did you mount the volume?"
      exit 1
    fi

    # Check reports directory is writable
    mkdir -p "$REPORTS_DIR" 2>/dev/null || true
    if [ ! -w "$REPORTS_DIR" ]; then
      echo "ERROR: $REPORTS_DIR is not writable."
      echo "Fix permissions on the host:"
      echo "  mkdir -p reports && chmod 777 reports"
      echo "  # or run with: UID=\$(id -u) GID=\$(id -g) docker compose run --rm sentinel"
      exit 1
    fi

    # === Phase 1: Project discovery ===
    echo "=== Phase 1: Project discovery ==="

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

    echo "Python projects found: ${#PYTHON_PROJECTS[@]}"
    echo "Node.js projects found: ${#NODE_PROJECTS[@]}"

    # === Phase 2: IOC scan ===
    echo ""
    echo "=== Phase 2: IOC search ==="
    source /sentinel/scan_iocs.sh "$PROJECTS_DIR" "$REPORT_BODY"

    # === Phase 3: Python scan ===
    echo ""
    echo "=== Phase 3: Python projects ==="
    for proj in "${PYTHON_PROJECTS[@]}"; do
      source /sentinel/scan_python.sh "$proj" "$REPORT_BODY"
    done

    # === Phase 4: Node.js scan ===
    echo ""
    echo "=== Phase 4: Node.js projects ==="
    for proj in "${NODE_PROJECTS[@]}"; do
      source /sentinel/scan_node.sh "$proj" "$REPORT_BODY"
    done

    # === Phase 5: Docker scan ===
    echo ""
    echo "=== Phase 5: Docker security ==="
    source /sentinel/scan_docker.sh "$PROJECTS_DIR" "$REPORT_BODY"

    # === Assemble final report ===
    case "$VERDICT" in
      CRITIQUE)  VERDICT_LABEL="🚨 **$L_VERDICT_CRITICAL**" ;;
      ATTENTION) VERDICT_LABEL="⚠️ **$L_VERDICT_ATTENTION**" ;;
      INFO)      VERDICT_LABEL="💡 **$L_VERDICT_INFO**" ;;
      CLEAN)     VERDICT_LABEL="✅ **$L_VERDICT_CLEAN**" ;;
    esac

    cat > "$REPORT_FILE" <<HEADER
# $L_REPORT_TITLE
**$L_DATE** : $(date '+%Y-%m-%d %H:%M:%S')
**$L_TARGET** : $PROJECTS_DIR
**$L_GRYPE_DB** : ${GRYPE_DATE}
**$L_PROJECTS** : ${#PYTHON_PROJECTS[@]} $L_PYTHON, ${#NODE_PROJECTS[@]} $L_NODEJS

---

## $L_VERDICT : $VERDICT_LABEL

| $L_CATEGORY | $L_RESULT |
|-----------|----------|
| $L_CONFIRMED_IOCS | $([ "$SUMMARY_IOC_CONFIRMED" -gt 0 ] && echo "🚨 $SUMMARY_IOC_CONFIRMED $L_FOUND" || echo "✅ 0 $L_FOUND") |
| $L_KNOWN_COMPROMISED | $([ "$SUMMARY_COMPROMISED_PKG" -gt 0 ] && echo "🚨 $SUMMARY_COMPROMISED_PKG $L_FOUND" || echo "✅ 0 $L_FOUND") |
| $L_MALICIOUS_HASHES | $([ "$SUMMARY_HASH_MATCH" -gt 0 ] && echo "🚨 $SUMMARY_HASH_MATCH $L_FOUND" || echo "✅ 0 $L_FOUND") |
| $L_PIP_AUDIT_VULNS | $([ "$SUMMARY_VULN_PIP" -gt 0 ] && echo "⚠️ $SUMMARY_VULN_PIP $L_PROJECTS_AFFECTED" || echo "✅ 0 $L_CRITICAL") |
| $L_NPM_AUDIT_VULNS | $([ "$SUMMARY_VULN_NPM" -gt 0 ] && echo "⚠️ $SUMMARY_VULN_NPM $L_PROJECTS_AFFECTED" || echo "✅ 0 $L_CRITICAL") |
| $L_GRYPE_VULNS | $([ "$SUMMARY_VULN_GRYPE" -gt 0 ] && echo "⚠️ $SUMMARY_VULN_GRYPE $L_PROJECTS_AFFECTED" || echo "✅ 0 $L_FOUND") |
| $L_UNICODE_SUSPECT | $([ "$SUMMARY_UNICODE_SOURCE" -gt 0 ] && echo "⚠️ $SUMMARY_UNICODE_SOURCE $L_FILES_TO_VERIFY" || echo "✅ 0 $L_FOUND") |
| $L_PATTERNS_SUSPECT | $([ "$SUMMARY_PATTERN_SUSPECT" -gt 0 ] && echo "⚠️ $SUMMARY_PATTERN_SUSPECT $L_PATTERN_S" || echo "✅ 0 $L_FOUND") |
| $L_SECRETS_BUILD | $([ "$SUMMARY_BUILD_ARGS_SECRET" -gt 0 ] && echo "⚠️ $SUMMARY_BUILD_ARGS_SECRET $L_FILES" || echo "✅ 0 $L_FOUND") |
| $L_UNPINNED_DEPS | $([ "$SUMMARY_UNPINNED" -gt 0 ] && echo "💡 ~$SUMMARY_UNPINNED $L_ACROSS ${#PYTHON_PROJECTS[@]} $L_PROJECTS" || echo "✅ $L_ALL_PINNED") |
| $L_NO_USER | $([ "$SUMMARY_NO_USER" -gt 0 ] && echo "💡 $SUMMARY_NO_USER $L_FILES" || echo "✅ $L_ALL_WITH_USER") |
| $L_SINGLE_STAGE | $([ "$SUMMARY_SINGLE_STAGE" -gt 0 ] && echo "💡 $SUMMARY_SINGLE_STAGE $L_FILES" || echo "✅ $L_ALL_MULTISTAGE") |
| $L_FALSE_POSITIVES | $([ "$COUNT_FILTERED" -gt 0 ] && echo "⚪ $COUNT_FILTERED $L_FILES (binary/i18n/IDE)" || echo "⚪ 0") |

---

HEADER

    # Append body
    cat "$REPORT_BODY" >> "$REPORT_FILE"

    # Append filtered false positives
    if [ "$COUNT_FILTERED" -gt 0 ]; then
      cat >> "$REPORT_FILE" <<FILTERED_HEADER

---

## $L_FP_SECTION

$L_FP_INTRO

<details>
<summary>$L_FP_SHOW</summary>

| $L_FP_FILE | $L_FP_RULE | $L_FP_REASON |
|---------|-------|--------------------|
FILTERED_HEADER
      cat "$REPORT_FILTERED" >> "$REPORT_FILE"
      echo "" >> "$REPORT_FILE"
      echo "</details>" >> "$REPORT_FILE"
    fi

    # Cleanup
    rm -f "$REPORT_BODY" "$REPORT_FILTERED"

    # Exit code
    case "$VERDICT" in
      CLEAN)     EXIT_CODE=0 ;;
      INFO)      EXIT_CODE=0 ;;
      ATTENTION) EXIT_CODE=1 ;;
      CRITIQUE)  EXIT_CODE=2 ;;
    esac

    echo ""
    echo "============================================"
    echo "  Verdict: $VERDICT"
    echo "  Report: $REPORT_FILE"
    echo "  Exit code: $EXIT_CODE"
    echo "============================================"

    exit $EXIT_CODE
    ;;

  *)
    echo "Usage: sentinel.sh [scan|update] [directory]"
    exit 1
    ;;
esac
