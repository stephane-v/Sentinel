#!/bin/bash
# Arguments: $1=PROJECT_DIR $2=REPORT_BODY
# NOTE: Variables inherited from sentinel.sh (sourced): SUMMARY_*, set_verdict, log_* functions
PROJ="$1"
REPORT="$2"
PROJ_NAME=$(echo "$PROJ" | sed "s|^/projects/||")

echo "-- Scan Python: $PROJ_NAME --"
echo "### $PROJ_NAME (Python)" >> "$REPORT"

# --- Paquets compromis connus ---
while IFS= read -r line; do
  [ -z "$line" ] && continue
  [[ "$line" =~ ^# ]] && continue
  pkg=$(echo "$line" | cut -d'@' -f1)
  ver=$(echo "$line" | cut -d'@' -f2)

  for req in "$PROJ"/requirements*.txt; do
    [ -f "$req" ] || continue
    if grep -qi "${pkg}.*${ver}" "$req" 2>/dev/null; then
      log_critique "[$PROJ_NAME] Paquet PyPI compromis: $pkg@$ver dans $(basename "$req")"
      echo "- 🚨 **Paquet compromis** : \`$pkg@$ver\` dans \`$(basename "$req")\`" >> "$REPORT"
      SUMMARY_COMPROMISED_PKG=$((SUMMARY_COMPROMISED_PKG + 1))
    fi
  done

  if [ -f "$PROJ/pyproject.toml" ]; then
    if grep -qi "${pkg}.*${ver}" "$PROJ/pyproject.toml" 2>/dev/null; then
      log_critique "[$PROJ_NAME] Paquet PyPI compromis: $pkg@$ver dans pyproject.toml"
      echo "- 🚨 **Paquet compromis** : \`$pkg@$ver\` dans \`pyproject.toml\`" >> "$REPORT"
      SUMMARY_COMPROMISED_PKG=$((SUMMARY_COMPROMISED_PKG + 1))
    fi
  fi
done < /sentinel/iocs/compromised_pypi.txt

# --- Versions non pinnées ---
for req in "$PROJ"/requirements*.txt; do
  [ -f "$req" ] || continue
  unpinned=$(grep -v -E "^#|^$|^-|==" "$req" 2>/dev/null | grep -c -E "[>=~]" 2>/dev/null || true)
  unpinned="${unpinned:-0}"
  unpinned=$(echo "$unpinned" | tail -1)
  if [ "$unpinned" -gt 0 ]; then
    log_info "[$PROJ_NAME] $unpinned dépendances non pinnées dans $(basename "$req")"
    echo "- 💡 **$unpinned dépendances non pinnées** dans \`$(basename "$req")\`" >> "$REPORT"
    echo "  - *Risque : un \`docker build\` futur pourrait tirer une version compromise*" >> "$REPORT"
    echo "  - *Action : \`pip freeze > requirements.txt\` dans le conteneur pour pinner*" >> "$REPORT"
    echo "  <details>" >> "$REPORT"
    echo "  <summary>Voir les dépendances non pinnées</summary>" >> "$REPORT"
    echo "" >> "$REPORT"
    grep -v -E "^#|^$|^-|==" "$req" 2>/dev/null | grep -E "[>=~]" 2>/dev/null | while read -r dep; do
      echo "  - \`$dep\`" >> "$REPORT"
    done || true
    echo "" >> "$REPORT"
    echo "  </details>" >> "$REPORT"
    SUMMARY_UNPINNED=$((SUMMARY_UNPINNED + unpinned))
  fi
done

# --- pip-audit (CVE connues) ---
for req in "$PROJ"/requirements*.txt; do
  [ -f "$req" ] || continue
  echo "  pip-audit sur $(basename "$req")..."
  audit_output=$(pip-audit -r "$req" --format json 2>/dev/null || echo '[]')

  vuln_count=$(echo "$audit_output" | jq 'if type == "array" then [.[] | select(.vulns | length > 0)] | length else 0 end' 2>/dev/null | tail -1 || true)
  vuln_count="${vuln_count:-0}"

  if [ "$vuln_count" -gt 0 ] 2>/dev/null; then
    log_attention "[$PROJ_NAME] $vuln_count vulnérabilités pip-audit"
    echo "- ⚠️ **$vuln_count vulnérabilités pip-audit** dans \`$(basename "$req")\`" >> "$REPORT"
    echo "$audit_output" | jq -r '.[] | select(.vulns | length > 0) |
      .name as $name | .version as $ver | .vulns[] |
      "  - \($name)@\($ver) — \(.id) (\(.fix_versions | join(", ")))"' 2>/dev/null >> "$REPORT"
    SUMMARY_VULN_PIP=$((SUMMARY_VULN_PIP + 1))
  else
    echo "- ✅ Aucune vulnérabilité pip-audit" >> "$REPORT"
  fi
done

# --- osv-scanner ---
if [ -f "$PROJ/requirements.txt" ] || [ -f "$PROJ/pyproject.toml" ]; then
  echo "  osv-scanner..."
  osv_output=$(osv-scanner --format json "$PROJ" 2>/dev/null || echo '{}')
  osv_count=$(echo "$osv_output" | jq '.results | length' 2>/dev/null | tail -1 || true)
  osv_count="${osv_count:-0}"
  if [ "$osv_count" -gt 0 ] 2>/dev/null; then
    log_attention "[$PROJ_NAME] $osv_count résultats osv-scanner"
    echo "- ⚠️ **$osv_count vulnérabilités osv-scanner**" >> "$REPORT"
  fi
fi

echo "" >> "$REPORT"
