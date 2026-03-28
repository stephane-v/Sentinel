#!/bin/bash
# Arguments: $1=PROJECTS_DIR $2=REPORT_BODY
# SECURITY: .env files are excluded from ALL scans by design.
# NOTE: Variables inherited from sentinel.sh (sourced): EXCLUDE_DIRS, GREP_EXCLUDE_DIRS,
#       REPORT_FILTERED, COUNT_FILTERED, SUMMARY_*, set_verdict, log_* functions
SCAN_DIR="$1"
REPORT="$2"
DEPTH="${SCAN_DEPTH:-4}"

# === Directories to always exclude (editor/IDE/build artifacts) ===
EDITOR_DIRS="config/data/User/History:.vscode:.idea:.cursor:__pycache__:.next:.nuxt:dist:build:.cache:coverage"

# === I18N patterns (Unicode false positives) ===
_is_i18n_file() {
  local f="$1"
  case "$f" in
    */locales/*|*/locale/*|*/i18n/*|*/l10n/*|*/translations/*) return 0 ;;
    *-locales.*|*-with-locales.*|*/moment/locales*|*/moment/*-with-locales*) return 0 ;;
  esac
  return 1
}

# === Check if path is in an editor/IDE directory ===
_is_editor_path() {
  local f="$1"
  local IFS=':'
  for pattern in $EDITOR_DIRS; do
    case "$f" in
      */$pattern/*) return 0 ;;
    esac
  done
  return 1
}

# === Build find exclusions ===
_build_find_excludes() {
  echo "-not -path */.git/*"
  echo "-not -path */node_modules/*"
  echo "-not -path */.venv/*"
  echo "-not -path */venv/*"
  if [ -n "${EXCLUDE_DIRS:-}" ]; then
    for _d in $(echo "$EXCLUDE_DIRS" | tr ',' ' '); do
      _d=$(echo "$_d" | xargs)
      [ -z "$_d" ] && continue
      echo "-not -path */$_d/*"
    done
  fi
}
FIND_EXCLUDES=$(_build_find_excludes)

# === File dates helper ===
_file_dates() {
  local f="$1"
  local mod cre
  mod=$(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1) || mod="?"
  cre=$(stat -c '%w' "$f" 2>/dev/null | cut -d'.' -f1) || cre="?"
  [ "$cre" = "-" ] && cre="n/a"
  echo "cree: $cre | modifie: $mod"
}

# === Phase 2 sections ===
# We write to REPORT (body) organized by severity

# Temp collectors
_CRITIQUE_SECTION=$(mktemp /tmp/sentinel-ioc-crit.XXXXXX)
_ATTENTION_SECTION=$(mktemp /tmp/sentinel-ioc-attn.XXXXXX)

# -------------------------------------------------------
# --- Fichiers malveillants connus ---
# -------------------------------------------------------
echo "-- Fichiers malveillants connus --"
while IFS= read -r pattern; do
  [ -z "$pattern" ] && continue
  [[ "$pattern" =~ ^# ]] && continue
  # shellcheck disable=SC2086
  results=$(find "$SCAN_DIR" -maxdepth "$DEPTH" -type f -name "$pattern" \
    $FIND_EXCLUDES \
    2>/dev/null || true)
  if [ -n "$results" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if _is_editor_path "$f"; then
        log_filtered "Fichier IOC dans répertoire éditeur: $f"
        echo "| \`$f\` | Fichier IOC \`$pattern\` | Répertoire éditeur |" >> "$REPORT_FILTERED"
        COUNT_FILTERED=$((COUNT_FILTERED + 1))
      else
        log_critique "Fichier IOC confirmé: $pattern → $f"
        echo "- 🚨 **Fichier IOC confirmé** : \`$pattern\` — \`$f\` — *$(_file_dates "$f")*" >> "$_CRITIQUE_SECTION"
        SUMMARY_IOC_CONFIRMED=$((SUMMARY_IOC_CONFIRMED + 1))
      fi
    done <<< "$results"
  fi
done < /sentinel/iocs/malicious_files.txt

# -------------------------------------------------------
# --- Patterns dans le code ---
# -------------------------------------------------------
echo "-- Patterns malveillants dans le code --"
while IFS= read -r pattern; do
  [ -z "$pattern" ] && continue
  [[ "$pattern" =~ ^# ]] && continue
  # shellcheck disable=SC2086
  results=$(grep -rl --binary-files=without-match \
    --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv \
    ${GREP_EXCLUDE_DIRS:-} \
    --exclude=".env" --exclude=".env.*" \
    --include="*.js" --include="*.ts" --include="*.py" \
    --include="*.json" --include="*.yml" --include="*.yaml" \
    --include="*.txt" --include="*.md" --include="*.sh" \
    "$pattern" "$SCAN_DIR" 2>/dev/null | head -20 || true)
  if [ -n "$results" ]; then
    while IFS= read -r f; do
      [ -z "$f" ] && continue

      # Classify by context
      if _is_editor_path "$f"; then
        log_filtered "Pattern '$pattern' dans répertoire éditeur: $f"
        echo "| \`$f\` | Pattern \`$pattern\` | Répertoire éditeur |" >> "$REPORT_FILTERED"
        COUNT_FILTERED=$((COUNT_FILTERED + 1))
        continue
      fi

      # Check file type: .md/.txt = documentation about the attack, not the attack
      case "$f" in
        *.md|*.txt)
          log_filtered "Pattern '$pattern' dans documentation: $f"
          echo "| \`$f\` | Pattern \`$pattern\` | Fichier documentation |" >> "$REPORT_FILTERED"
          COUNT_FILTERED=$((COUNT_FILTERED + 1))
          continue
          ;;
      esac

      # Exfiltration endpoints in code = CRITIQUE
      case "$pattern" in
        webhook.site|checkmarx.zone|models.litellm.cloud)
          log_critique "Endpoint d'exfiltration '$pattern' dans: $f"
          echo "- 🚨 **Endpoint d'exfiltration** : \`$pattern\` dans \`$f\` — *$(_file_dates "$f")*" >> "$_CRITIQUE_SECTION"
          SUMMARY_IOC_CONFIRMED=$((SUMMARY_IOC_CONFIRMED + 1))
          continue
          ;;
      esac

      # Other patterns in code files = ATTENTION
      log_attention "Pattern suspect '$pattern' dans: $f"
      echo "- ⚠️ **Pattern suspect** : \`$pattern\` dans \`$f\` — *$(_file_dates "$f")*" >> "$_ATTENTION_SECTION"
      SUMMARY_PATTERN_SUSPECT=$((SUMMARY_PATTERN_SUSPECT + 1))
    done <<< "$results"
  fi
done < /sentinel/iocs/malicious_patterns.txt

# -------------------------------------------------------
# --- Caractères Unicode invisibles ---
# -------------------------------------------------------
echo "-- Caractères Unicode invisibles --"
UNICODE_PATTERN='[\x{200B}-\x{200F}\x{2028}-\x{202F}\x{2060}-\x{206F}\x{FEFF}]'

# Pass 1: text source files
# shellcheck disable=SC2086
unicode_text=$(grep -rPl --binary-files=without-match \
  --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv \
  ${GREP_EXCLUDE_DIRS:-} \
  --exclude=".env" --exclude=".env.*" \
  --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
  --include="*.py" --include="*.sh" --include="*.bash" \
  --include="*.json" --include="*.yml" --include="*.yaml" \
  --include="*.toml" --include="*.cfg" --include="*.ini" \
  "$UNICODE_PATTERN" \
  "$SCAN_DIR" 2>/dev/null | head -30 || true)

if [ -n "$unicode_text" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue

    if _is_editor_path "$f"; then
      log_filtered "Unicode invisible dans répertoire éditeur: $f"
      echo "| \`$f\` | Unicode invisibles | Répertoire éditeur |" >> "$REPORT_FILTERED"
      COUNT_FILTERED=$((COUNT_FILTERED + 1))
    elif _is_i18n_file "$f"; then
      log_filtered "Unicode invisible dans fichier i18n: $f"
      echo "| \`$f\` | Unicode invisibles | Fichier i18n/locales |" >> "$REPORT_FILTERED"
      COUNT_FILTERED=$((COUNT_FILTERED + 1))
    else
      log_attention "Unicode invisible dans code source: $f"
      echo "- ⚠️ **Unicode invisible dans code source** : \`$f\` — *$(_file_dates "$f")*" >> "$_ATTENTION_SECTION"
      SUMMARY_UNICODE_SOURCE=$((SUMMARY_UNICODE_SOURCE + 1))
    fi
  done <<< "$unicode_text"
fi

# Pass 2: binary files (<5MB) — always filtered as false positive
# shellcheck disable=SC2086
unicode_binary=$(find "$SCAN_DIR" -maxdepth "$DEPTH" -type f \
  \( -name "*.png" -o -name "*.jpg" -o -name "*.gif" -o -name "*.svg" \
     -o -name "*.woff" -o -name "*.woff2" -o -name "*.ttf" -o -name "*.eot" \
     -o -name "*.bin" -o -name "*.dat" -o -name "*.so" -o -name "*.pdf" \) \
  $FIND_EXCLUDES \
  -size -5M \
  -exec grep -Pl "$UNICODE_PATTERN" {} + 2>/dev/null | head -20 || true)

if [ -n "$unicode_binary" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    log_filtered "Unicode invisible dans binaire: $f"
    echo "| \`$f\` | Unicode invisibles | Fichier binaire |" >> "$REPORT_FILTERED"
    COUNT_FILTERED=$((COUNT_FILTERED + 1))
  done <<< "$unicode_binary"
fi

# -------------------------------------------------------
# --- Hashes malveillants connus ---
# -------------------------------------------------------
echo "-- Vérification hashes malveillants --"
HASH_FILE=$(mktemp /tmp/sentinel-hashes.XXXXXX)
# shellcheck disable=SC2086
find "$SCAN_DIR" -maxdepth "$DEPTH" -type f \( -name "*.js" -o -name "*.py" \) \
  $FIND_EXCLUDES \
  -size -1M \
  -exec sha256sum {} + 2>/dev/null > "$HASH_FILE" || true

while IFS= read -r hash; do
  [ -z "$hash" ] && continue
  [[ "$hash" =~ ^# ]] && continue
  results=$(grep "^$hash" "$HASH_FILE" 2>/dev/null | head -5 || true)
  if [ -n "$results" ]; then
    log_critique "Hash malveillant trouvé: $hash"
    while IFS=' ' read -r _ fpath; do
      echo "- 🚨 **Hash malveillant confirmé** : \`$hash\` — \`$fpath\` — *$(_file_dates "$fpath")*" >> "$_CRITIQUE_SECTION"
      SUMMARY_HASH_MATCH=$((SUMMARY_HASH_MATCH + 1))
    done <<< "$results"
  fi
done < /sentinel/iocs/malicious_hashes.txt
rm -f "$HASH_FILE"

# -------------------------------------------------------
# --- Assemble IOC section into report body ---
# -------------------------------------------------------
echo "## Recherche IOCs (Indicators of Compromise)" >> "$REPORT"
echo "" >> "$REPORT"

_crit_content=$(cat "$_CRITIQUE_SECTION" 2>/dev/null)
_attn_content=$(cat "$_ATTENTION_SECTION" 2>/dev/null)

if [ -z "$_crit_content" ] && [ -z "$_attn_content" ]; then
  log_ok "Aucun IOC détecté"
  echo "✅ Aucun IOC ni pattern suspect détecté." >> "$REPORT"
else
  if [ -n "$_crit_content" ]; then
    echo "### 🚨 IOCs confirmés" >> "$REPORT"
    echo "" >> "$REPORT"
    echo "$_crit_content" >> "$REPORT"
    echo "" >> "$REPORT"
  fi
  if [ -n "$_attn_content" ]; then
    echo "### ⚠️ Éléments suspects (vérification manuelle requise)" >> "$REPORT"
    echo "" >> "$REPORT"
    echo "$_attn_content" >> "$REPORT"
    echo "" >> "$REPORT"
  fi
fi

echo "" >> "$REPORT"

# Cleanup temp files
rm -f "$_CRITIQUE_SECTION" "$_ATTENTION_SECTION"
