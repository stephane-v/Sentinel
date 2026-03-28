#!/bin/bash
# Arguments: $1=PROJECT_DIR $2=REPORT_BODY
# NOTE: Variables inherited from sentinel.sh (sourced): SUMMARY_*, set_verdict, log_* functions
PROJ="$1"
REPORT="$2"
PROJ_NAME=$(echo "$PROJ" | sed "s|^/projects/||")

echo "-- Scan Node.js: $PROJ_NAME --"
echo "### $PROJ_NAME (Node.js)" >> "$REPORT"

LOCKFILE="$PROJ/package-lock.json"
[ -f "$LOCKFILE" ] || return

# --- Paquets compromis connus ---
while IFS= read -r line; do
  [ -z "$line" ] && continue
  [[ "$line" =~ ^# ]] && continue
  pkg=$(echo "$line" | cut -d'@' -f1)
  ver=$(echo "$line" | cut -d'@' -f2)

  found=$(jq -r --arg pkg "$pkg" --arg ver "$ver" \
    '.packages | to_entries[] | select(.key | endswith($pkg)) | select(.value.version == $ver) | .key' \
    "$LOCKFILE" 2>/dev/null)

  if [ -n "$found" ]; then
    log_critique "[$PROJ_NAME] Paquet npm compromis: $pkg@$ver"
    echo "- 🚨 **Paquet compromis** : \`$pkg@$ver\`" >> "$REPORT"
    SUMMARY_COMPROMISED_PKG=$((SUMMARY_COMPROMISED_PKG + 1))
  fi
done < /sentinel/iocs/compromised_npm.txt

# --- Paquets avec install scripts ---
script_count=$(jq '[.packages | to_entries[] | select(.value.hasInstallScript == true)] | length' "$LOCKFILE" 2>/dev/null || echo "?")
echo "- Paquets avec install scripts : **$script_count**" >> "$REPORT"

# --- npm audit ---
if [ -f "$PROJ/package.json" ]; then
  echo "  npm audit..."
  cd "$PROJ"
  audit_output=$(npm audit --json 2>/dev/null || echo '{}')

  critical=$(echo "$audit_output" | jq '.metadata.vulnerabilities.critical // 0' 2>/dev/null | tail -1 || true)
  high=$(echo "$audit_output" | jq '.metadata.vulnerabilities.high // 0' 2>/dev/null | tail -1 || true)
  moderate=$(echo "$audit_output" | jq '.metadata.vulnerabilities.moderate // 0' 2>/dev/null | tail -1 || true)
  critical="${critical:-0}"; high="${high:-0}"; moderate="${moderate:-0}"

  if [ "$critical" -gt 0 ] 2>/dev/null || [ "$high" -gt 0 ] 2>/dev/null; then
    log_attention "[$PROJ_NAME] npm audit: $critical critiques, $high élevées, $moderate modérées"
    echo "- ⚠️ **npm audit** : $critical critiques, $high élevées, $moderate modérées" >> "$REPORT"
    SUMMARY_VULN_NPM=$((SUMMARY_VULN_NPM + 1))
  else
    echo "- ✅ npm audit clean ($moderate modérées)" >> "$REPORT"
  fi
  cd - > /dev/null
fi

# --- osv-scanner ---
echo "  osv-scanner..."
osv_output=$(osv-scanner --format json --lockfile "$LOCKFILE" 2>/dev/null || echo '{}')
osv_count=$(echo "$osv_output" | jq '.results | length' 2>/dev/null | tail -1 || true)
osv_count="${osv_count:-0}"
if [ "$osv_count" -gt 0 ] 2>/dev/null; then
  log_attention "[$PROJ_NAME] $osv_count résultats osv-scanner"
  echo "- ⚠️ **$osv_count vulnérabilités osv-scanner**" >> "$REPORT"
fi

echo "" >> "$REPORT"
