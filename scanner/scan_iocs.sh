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
    echo "$results" | while read -r f; do echo "  → $f"; done
    echo "- ❌ **Fichier malveillant** : \`$pattern\` trouvé" >> "$REPORT"
    echo "$results" | while read -r f; do echo "  - \`$f\`" >> "$REPORT"; done
    IOC_COUNT=$((IOC_COUNT + 1))
  fi
done < /sentinel/iocs/malicious_files.txt

# --- Patterns dans le code ---
echo "-- Patterns malveillants dans le code --"
while IFS= read -r pattern; do
  [ -z "$pattern" ] && continue
  [[ "$pattern" =~ ^# ]] && continue
  # shellcheck disable=SC2086
  results=$(grep -rl \
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
    echo "$results" | while read -r f; do echo "  - \`$f\`" >> "$REPORT"; done
    IOC_COUNT=$((IOC_COUNT + 1))
  fi
done < /sentinel/iocs/malicious_patterns.txt

# --- Caractères Unicode invisibles (GlassWorm) ---
echo "-- Caractères Unicode invisibles --"
# Scan uniquement les fichiers source (pas les binaires/images/fonts)
# shellcheck disable=SC2086
unicode_results=$(grep -rPl \
  --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv \
  ${GREP_EXCLUDE_DIRS:-} \
  --exclude=".env" --exclude=".env.*" \
  --include="*.js" --include="*.ts" --include="*.py" \
  --include="*.json" --include="*.yml" --include="*.yaml" \
  '[\x{200B}-\x{200F}\x{2028}-\x{202F}\x{2060}-\x{206F}\x{FEFF}]' \
  "$SCAN_DIR" 2>/dev/null | head -20 || true)
if [ -n "$unicode_results" ]; then
  log_critical "Caractères Unicode invisibles détectés (technique GlassWorm)"
  echo "- ❌ **Unicode invisibles** (GlassWorm)" >> "$REPORT"
  echo "$unicode_results" | while read -r f; do echo "  - \`$f\`" >> "$REPORT"; done
  IOC_COUNT=$((IOC_COUNT + 1))
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
