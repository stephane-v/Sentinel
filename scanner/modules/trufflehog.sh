#!/bin/bash
# TruffleHog secrets scanner module for Sentinel
# Arguments when sourced: $1=PROJECT_PATH $2=REPORT_BODY
# Standalone: bash scanner/modules/trufflehog.sh /path/to/project
# NOTE: Variables inherited from sentinel.sh (sourced): SUMMARY_*, L_*, COUNT_*,
#       set_verdict, log_* functions

# === Standalone mode support ===
if [ -z "${VERDICT:-}" ]; then
  # Running standalone — define minimal logging
  RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
  log_critique()  { echo -e "${RED}[CRITICAL]${NC} $*" >&2; }
  log_attention() { echo -e "${YELLOW}[ATTENTION]${NC} $*" >&2; }
  log_info()      { echo -e "${BLUE}[INFO]${NC} $*"; }
  log_ok()        { echo -e "${GREEN}[OK]${NC} $*"; }
  set_verdict()   { :; }
  SUMMARY_SECRETS_VERIFIED=0
  SUMMARY_SECRETS_UNVERIFIED=0
  _STANDALONE=1
fi

run_trufflehog_scan() {
  local PROJECT_PATH="$1"
  local REPORT="${2:-/dev/null}"

  if ! command -v trufflehog >/dev/null 2>&1; then
    log_attention "TruffleHog not found — skipping secrets scan"
    echo "### $L_SECRETS_SCAN" >> "$REPORT"
    echo "" >> "$REPORT"
    echo "> TruffleHog binary not available. Skipping secrets scan." >> "$REPORT"
    echo "" >> "$REPORT"
    return 0
  fi

  # === Build flags ===
  local TRUFFLEHOG_FLAGS="--json --no-update"

  if [ "${SECRETS_MODE:-verified}" != "full" ]; then
    TRUFFLEHOG_FLAGS="$TRUFFLEHOG_FLAGS --only-verified"
  fi

  # === Exclude paths ===
  local EXCLUDE_ARGS=""
  local GLOBAL_IGNORE="/sentinel/config/trufflehog-ignore.txt"
  if [ -f "$GLOBAL_IGNORE" ]; then
    EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude-paths=$GLOBAL_IGNORE"
  fi
  if [ -f "$PROJECT_PATH/.trufflehogignore" ]; then
    EXCLUDE_ARGS="$EXCLUDE_ARGS --exclude-paths=$PROJECT_PATH/.trufflehogignore"
  fi

  # === Determine scan command ===
  local SCAN_ARGS=""
  if [ -d "$PROJECT_PATH/.git" ]; then
    SCAN_ARGS="git file://$PROJECT_PATH"
    if [ -n "${SECRETS_MAX_DEPTH:-}" ]; then
      SCAN_ARGS="$SCAN_ARGS --max-depth=$SECRETS_MAX_DEPTH"
    fi
    if [ -n "${SECRETS_SINCE_COMMIT:-}" ]; then
      SCAN_ARGS="$SCAN_ARGS --since-commit=$SECRETS_SINCE_COMMIT"
    fi
  else
    SCAN_ARGS="filesystem $PROJECT_PATH"
  fi

  # === Run TruffleHog with timeout (default 5 min) ===
  local TIMEOUT="${SECRETS_TIMEOUT:-300}"
  local OUTPUT_FILE
  OUTPUT_FILE=$(mktemp /tmp/trufflehog-output.XXXXXX)

  # shellcheck disable=SC2086
  timeout "$TIMEOUT" trufflehog $SCAN_ARGS $TRUFFLEHOG_FLAGS $EXCLUDE_ARGS > "$OUTPUT_FILE" 2>/dev/null
  local TH_EXIT=$?

  if [ "$TH_EXIT" -eq 124 ]; then
    log_attention "TruffleHog scan timed out after ${TIMEOUT}s"
  fi

  # === Parse results ===
  local VERIFIED_COUNT=0
  local UNVERIFIED_COUNT=0
  local VERIFIED_FINDINGS=""
  local UNVERIFIED_FINDINGS=""

  if [ -s "$OUTPUT_FILE" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue

      local detector_name file_path line_num commit_hash verified

      detector_name=$(echo "$line" | jq -r '.DetectorName // .detector_name // "Unknown"' 2>/dev/null)
      verified=$(echo "$line" | jq -r '.Verified // .verified // false' 2>/dev/null)

      # Extract source metadata — handle both git and filesystem structures
      file_path=$(echo "$line" | jq -r '
        .SourceMetadata.Data.Git.file //
        .SourceMetadata.Data.Filesystem.file //
        .source_metadata.Data.Git.file //
        .source_metadata.Data.Filesystem.file //
        "unknown"' 2>/dev/null)

      line_num=$(echo "$line" | jq -r '
        .SourceMetadata.Data.Git.line //
        .SourceMetadata.Data.Filesystem.line //
        .source_metadata.Data.Git.line //
        .source_metadata.Data.Filesystem.line //
        "?"' 2>/dev/null)

      commit_hash=$(echo "$line" | jq -r '
        .SourceMetadata.Data.Git.commit //
        .source_metadata.Data.Git.commit //
        ""' 2>/dev/null)

      # Shorten commit hash for display
      if [ -n "$commit_hash" ] && [ "$commit_hash" != "null" ] && [ "$commit_hash" != "" ]; then
        commit_hash="${commit_hash:0:7}"
      else
        commit_hash="-"
      fi

      # Strip project path prefix for cleaner display
      file_path="${file_path#"$PROJECT_PATH/"}"

      if [ "$verified" = "true" ]; then
        VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
        VERIFIED_FINDINGS="${VERIFIED_FINDINGS}| ${detector_name} | \`${file_path}\` | ${line_num} | ${commit_hash} |\n"
      else
        UNVERIFIED_COUNT=$((UNVERIFIED_COUNT + 1))
        UNVERIFIED_FINDINGS="${UNVERIFIED_FINDINGS}| ${detector_name} | \`${file_path}\` | ${line_num} |\n"
      fi
    done < "$OUTPUT_FILE"
  fi

  rm -f "$OUTPUT_FILE"

  # === Update summary counters ===
  SUMMARY_SECRETS_VERIFIED=$((SUMMARY_SECRETS_VERIFIED + VERIFIED_COUNT))
  SUMMARY_SECRETS_UNVERIFIED=$((SUMMARY_SECRETS_UNVERIFIED + UNVERIFIED_COUNT))

  # === Write report section ===
  echo "## ${L_SECRETS_SCAN:-Secrets Scan (TruffleHog)}" >> "$REPORT"
  echo "" >> "$REPORT"

  if [ "$VERIFIED_COUNT" -eq 0 ] && [ "$UNVERIFIED_COUNT" -eq 0 ]; then
    log_ok "No leaked secrets detected"
    echo "✅ ${L_SECRETS_NONE:-No leaked secrets detected.}" >> "$REPORT"
    echo "" >> "$REPORT"
    return 0
  fi

  # Verified secrets — CRITICAL
  if [ "$VERIFIED_COUNT" -gt 0 ]; then
    log_critique "VERIFIED secrets found ($VERIFIED_COUNT) — immediate rotation required"
    set_verdict CRITIQUE
    echo "### 🚨 CRITICAL — ${L_SECRETS_VERIFIED:-Verified secrets (active)}" >> "$REPORT"
    echo "" >> "$REPORT"
    echo "| Type | File | Line | Commit |" >> "$REPORT"
    echo "|------|------|------|--------|" >> "$REPORT"
    echo -e "$VERIFIED_FINDINGS" >> "$REPORT"
  fi

  # Unverified secrets — HIGH
  if [ "$UNVERIFIED_COUNT" -gt 0 ]; then
    log_attention "Potential secrets detected ($UNVERIFIED_COUNT unverified)"
    set_verdict ATTENTION
    echo "### ⚠️ HIGH — ${L_SECRETS_UNVERIFIED:-Unverified secrets}" >> "$REPORT"
    echo "" >> "$REPORT"
    echo "| Type | File | Line |" >> "$REPORT"
    echo "|------|------|------|" >> "$REPORT"
    echo -e "$UNVERIFIED_FINDINGS" >> "$REPORT"
  fi

  # Recommended actions
  echo "### ${L_SECRETS_RECOMMENDED:-Recommended actions}" >> "$REPORT"
  echo "" >> "$REPORT"
  if [ "$VERIFIED_COUNT" -gt 0 ]; then
    echo "- [ ] ${L_SECRETS_ROTATE:-Rotate all CRITICAL secrets immediately}" >> "$REPORT"
  fi
  echo "- [ ] ${L_SECRETS_REVIEW:-Review HIGH findings for false positives}" >> "$REPORT"
  echo "- [ ] ${L_SECRETS_IGNORE:-Add confirmed false positives to .trufflehogignore}" >> "$REPORT"
  echo "" >> "$REPORT"

  # === Return exit code ===
  if [ "$VERIFIED_COUNT" -gt 0 ]; then
    return 2
  elif [ "$UNVERIFIED_COUNT" -gt 0 ]; then
    return 1
  fi
  return 0
}

# === Standalone execution ===
if [ "${_STANDALONE:-0}" = "1" ] && [ $# -ge 1 ]; then
  REPORT_TMP=$(mktemp /tmp/trufflehog-report.XXXXXX)
  run_trufflehog_scan "$1" "$REPORT_TMP"
  EXIT_CODE=$?
  echo ""
  echo "--- Report ---"
  cat "$REPORT_TMP"
  rm -f "$REPORT_TMP"
  exit $EXIT_CODE
fi
