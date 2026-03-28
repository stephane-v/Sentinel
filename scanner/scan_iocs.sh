#!/bin/bash
# Arguments: $1=PROJECTS_DIR $2=REPORT_FILE
# SECURITY: .env files are excluded from ALL scans by design — their content
# (secrets, tokens, API keys) must never be read, logged, or sent to external tools.
SCAN_DIR="$1"
REPORT="$2"

echo "## Recherche IOCs (Indicators of Compromise)" >> "$REPORT"
echo "" >> "$REPORT"

IOC_COUNT=0

# --- Fichiers malveillants connus ---
echo "-- Fichiers malveillants connus --"
while IFS= read -r pattern; do
  [ -z "$pattern" ] && continue
  [[ "$pattern" =~ ^# ]] && continue
  results=$(find "$SCAN_DIR" -type f -name "$pattern" -not -path "*/.git/*" -not -name ".env" -not -name ".env.*" -not -path "*/.env" -not -path "*/.env.*" 2>/dev/null)
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
  results=$(grep -rl "$pattern" --include="*.js" --include="*.ts" --include="*.py" \
    --include="*.json" --include="*.yml" --include="*.yaml" \
    --exclude=".env" --exclude=".env.*" \
    -r "$SCAN_DIR" 2>/dev/null | grep -v "/.git/" | head -20)
  if [ -n "$results" ]; then
    log_critical "Pattern suspect trouvé: $pattern"
    echo "- ❌ **Pattern malveillant** : \`$pattern\`" >> "$REPORT"
    echo "$results" | while read -r f; do echo "  - \`$f\`" >> "$REPORT"; done
    IOC_COUNT=$((IOC_COUNT + 1))
  fi
done < /sentinel/iocs/malicious_patterns.txt

# --- Caractères Unicode invisibles (GlassWorm) ---
echo "-- Caractères Unicode invisibles --"
unicode_results=$(grep -rPl '[\x{200B}-\x{200F}\x{2028}-\x{202F}\x{2060}-\x{206F}\x{FEFF}]' \
  --include="*.js" --include="*.ts" --include="*.py" \
  --exclude=".env" --exclude=".env.*" \
  "$SCAN_DIR" 2>/dev/null | grep -v "/.git/\|/node_modules/" | head -20)
if [ -n "$unicode_results" ]; then
  log_critical "Caractères Unicode invisibles détectés (technique GlassWorm)"
  echo "- ❌ **Unicode invisibles** (GlassWorm)" >> "$REPORT"
  echo "$unicode_results" | while read -r f; do echo "  - \`$f\`" >> "$REPORT"; done
  IOC_COUNT=$((IOC_COUNT + 1))
fi

# --- Hashes connus ---
echo "-- Vérification hashes malveillants --"
while IFS= read -r hash; do
  [ -z "$hash" ] && continue
  [[ "$hash" =~ ^# ]] && continue
  results=$(find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.py" \) -not -path "*/.git/*" \
    -not -name ".env" -not -name ".env.*" \
    -exec sha256sum {} \; 2>/dev/null | grep "^$hash" | head -5)
  if [ -n "$results" ]; then
    log_critical "Hash malveillant trouvé: $hash"
    echo "- ❌ **Hash malveillant** : \`$hash\`" >> "$REPORT"
    IOC_COUNT=$((IOC_COUNT + 1))
  fi
done < /sentinel/iocs/malicious_hashes.txt

# --- Résultat ---
if [ $IOC_COUNT -eq 0 ]; then
  log_ok "Aucun IOC détecté"
  echo "✅ Aucun IOC détecté" >> "$REPORT"
fi
echo "" >> "$REPORT"
