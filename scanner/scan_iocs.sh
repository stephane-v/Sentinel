#!/bin/bash
# Arguments: $1=PROJECTS_DIR $2=REPORT_FILE
# SECURITY: .env files are excluded from ALL scans by design — their content
# (secrets, tokens, API keys) must never be read, logged, or sent to external tools.
# NOTE: EXCLUDE_DIRS, GREP_EXCLUDE_DIRS are inherited from sentinel.sh (sourced)
SCAN_DIR="$1"
REPORT="$2"
DEPTH="${SCAN_DEPTH:-4}"

# Construire les exclusions find pour les repertoires utilisateur + standards
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

# Afficher les dates d'un fichier (creation/modification)
_file_dates() {
  local f="$1"
  local mod cre
  mod=$(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1) || mod="?"
  cre=$(stat -c '%w' "$f" 2>/dev/null | cut -d'.' -f1) || cre="?"
  [ "$cre" = "-" ] && cre="n/a"
  echo "cree: $cre | modifie: $mod"
}

echo "## Recherche IOCs (Indicators of Compromise)" >> "$REPORT"
echo "" >> "$REPORT"

IOC_COUNT=0

# --- Fichiers malveillants connus ---
echo "-- Fichiers malveillants connus --"
while IFS= read -r pattern; do
  [ -z "$pattern" ] && continue
  [[ "$pattern" =~ ^# ]] && continue
  # shellcheck disable=SC2086
  results=$(find "$SCAN_DIR" -maxdepth "$DEPTH" -type f -name "$pattern" \
    $FIND_EXCLUDES \
    2>/dev/null || true)
  if [ -n "$results" ]; then
    log_critical "Fichier suspect trouvé: $pattern"
    echo "$results" | while read -r f; do echo "  → $f ($(_file_dates "$f"))"; done
    echo "- ❌ **Fichier malveillant** : \`$pattern\` trouvé" >> "$REPORT"
    echo "$results" | while read -r f; do
      echo "  - \`$f\` — *$(_file_dates "$f")*" >> "$REPORT"
    done
    IOC_COUNT=$((IOC_COUNT + 1))
  fi
done < /sentinel/iocs/malicious_files.txt

# --- Patterns dans le code ---
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
    log_critical "Pattern suspect trouvé: $pattern"
    echo "- ❌ **Pattern malveillant** : \`$pattern\`" >> "$REPORT"
    echo "$results" | while read -r f; do
      echo "  - \`$f\` — *$(_file_dates "$f")*" >> "$REPORT"
    done
    IOC_COUNT=$((IOC_COUNT + 1))
  fi
done < /sentinel/iocs/malicious_patterns.txt

# --- Caractères Unicode invisibles (GlassWorm) ---
echo "-- Caractères Unicode invisibles --"
UNICODE_PATTERN='[\x{200B}-\x{200F}\x{2028}-\x{202F}\x{2060}-\x{206F}\x{FEFF}]'
UNICODE_GREP_BASE="--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv ${GREP_EXCLUDE_DIRS:-} --exclude=.env --exclude=.env.*"

# Pass 1 : fichiers source texte — CRITIQUE
# shellcheck disable=SC2086
unicode_text=$(grep -rPl --binary-files=without-match \
  $UNICODE_GREP_BASE \
  --include="*.js" --include="*.ts" --include="*.py" \
  --include="*.json" --include="*.yml" --include="*.yaml" \
  "$UNICODE_PATTERN" \
  "$SCAN_DIR" 2>/dev/null | head -20 || true)
if [ -n "$unicode_text" ]; then
  log_critical "Caractères Unicode invisibles détectés dans du code source (technique GlassWorm)"
  echo "- ❌ **Unicode invisibles dans du code source** (GlassWorm)" >> "$REPORT"
  echo "$unicode_text" | while read -r f; do
    echo "  - \`$f\` — *$(_file_dates "$f")*" >> "$REPORT"
  done
  IOC_COUNT=$((IOC_COUNT + 1))
fi

# Pass 2 : fichiers binaires courants (<10MB) — probable faux-positif mais signale
# On utilise find+grep par fichier au lieu de grep -r pour eviter de bloquer sur les gros fichiers
unicode_binary=""
# shellcheck disable=SC2086
while IFS= read -r bf; do
  if grep -Pq "$UNICODE_PATTERN" "$bf" 2>/dev/null; then
    unicode_binary="${unicode_binary}${bf}"$'\n'
  fi
done < <(find "$SCAN_DIR" -maxdepth "$DEPTH" -type f \
  \( -name "*.png" -o -name "*.jpg" -o -name "*.gif" -o -name "*.svg" \
     -o -name "*.woff" -o -name "*.woff2" -o -name "*.ttf" -o -name "*.eot" \
     -o -name "*.bin" -o -name "*.dat" -o -name "*.so" -o -name "*.dll" \
     -o -name "*.pdf" -o -name "*.zip" -o -name "*.tar" -o -name "*.gz" \) \
  $FIND_EXCLUDES \
  -size -10M \
  2>/dev/null || true)
unicode_binary=$(echo "$unicode_binary" | sed '/^$/d' | head -20)
if [ -n "$unicode_binary" ]; then
  log_warning "Caractères Unicode invisibles dans des fichiers binaires (probable faux-positif)"
  echo "- ⚠️ **Unicode invisibles dans des fichiers binaires** (probable faux-positif)" >> "$REPORT"
  echo "$unicode_binary" | while read -r f; do
    echo "  - \`$f\` — *$(_file_dates "$f")*" >> "$REPORT"
  done
fi

# --- Hashes connus ---
echo "-- Vérification hashes malveillants --"
# Pre-calculer les hashes des fichiers sources (hors node_modules/venv/.git/exclusions)
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
    log_critical "Hash malveillant trouvé: $hash"
    echo "- ❌ **Hash malveillant** : \`$hash\`" >> "$REPORT"
    echo "$results" | while IFS=' ' read -r _ fpath; do
      echo "  - \`$fpath\` — *$(_file_dates "$fpath")*" >> "$REPORT"
    done
    IOC_COUNT=$((IOC_COUNT + 1))
  fi
done < /sentinel/iocs/malicious_hashes.txt
rm -f "$HASH_FILE"

# --- Résultat ---
if [ $IOC_COUNT -eq 0 ]; then
  log_ok "Aucun IOC détecté"
  echo "✅ Aucun IOC détecté" >> "$REPORT"
fi
echo "" >> "$REPORT"
