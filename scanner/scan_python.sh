#!/bin/bash
# Arguments: $1=PROJECT_DIR $2=REPORT_FILE
PROJ="$1"
REPORT="$2"
PROJ_NAME=$(basename "$PROJ")

echo "-- Scan Python: $PROJ_NAME --"
echo "### $PROJ_NAME (Python)" >> "$REPORT"

# --- Paquets compromis connus ---
while IFS= read -r line; do
  [ -z "$line" ] && continue
  [[ "$line" =~ ^# ]] && continue
  pkg=$(echo "$line" | cut -d'@' -f1)
  ver=$(echo "$line" | cut -d'@' -f2)

  # Chercher dans requirements*.txt
  for req in "$PROJ"/requirements*.txt; do
    [ -f "$req" ] || continue
    if grep -qi "${pkg}.*${ver}" "$req" 2>/dev/null; then
      log_critical "[$PROJ_NAME] Paquet PyPI compromis: $pkg@$ver dans $(basename "$req")"
      echo "- ❌ **Paquet compromis** : \`$pkg@$ver\` dans \`$(basename "$req")\`" >> "$REPORT"
    fi
  done

  # Chercher dans pyproject.toml
  if [ -f "$PROJ/pyproject.toml" ]; then
    if grep -qi "${pkg}.*${ver}" "$PROJ/pyproject.toml" 2>/dev/null; then
      log_critical "[$PROJ_NAME] Paquet PyPI compromis: $pkg@$ver dans pyproject.toml"
      echo "- ❌ **Paquet compromis** : \`$pkg@$ver\` dans \`pyproject.toml\`" >> "$REPORT"
    fi
  fi
done < /sentinel/iocs/compromised_pypi.txt

# --- Versions non pinnées ---
for req in "$PROJ"/requirements*.txt; do
  [ -f "$req" ] || continue
  unpinned=$(grep -v "^#\|^$\|^-\|==" "$req" | grep -c "[>=~]" 2>/dev/null || echo 0)
  if [ "$unpinned" -gt 0 ]; then
    log_warning "[$PROJ_NAME] $unpinned dépendances non pinnées (>=, ~=) dans $(basename "$req")"
    echo "- ⚠️ **$unpinned dépendances non pinnées** dans \`$(basename "$req")\`" >> "$REPORT"
  fi
done

# --- pip-audit (CVE connues) ---
for req in "$PROJ"/requirements*.txt; do
  [ -f "$req" ] || continue
  echo "  pip-audit sur $(basename "$req")..."
  audit_output=$(pip-audit -r "$req" --format json 2>/dev/null || echo '[]')

  vuln_count=$(echo "$audit_output" | jq 'if type == "array" then [.[] | select(.vulns | length > 0)] | length else 0 end' 2>/dev/null || echo 0)

  if [ "$vuln_count" -gt 0 ]; then
    log_warning "[$PROJ_NAME] $vuln_count vulnérabilités trouvées par pip-audit"
    echo "- ⚠️ **$vuln_count vulnérabilités pip-audit** dans \`$(basename "$req")\`" >> "$REPORT"

    # Détailler les critiques et élevées
    echo "$audit_output" | jq -r '.[] | select(.vulns | length > 0) |
      .name as $name | .version as $ver | .vulns[] |
      "  - \($name)@\($ver) — \(.id) (\(.fix_versions | join(", ")))"' 2>/dev/null >> "$REPORT"
  else
    echo "- ✅ Aucune vulnérabilité pip-audit" >> "$REPORT"
  fi
done

# --- osv-scanner (base OSV, plus large que pip-audit) ---
if [ -f "$PROJ/requirements.txt" ] || [ -f "$PROJ/pyproject.toml" ]; then
  echo "  osv-scanner..."
  osv_output=$(osv-scanner --format json "$PROJ" 2>/dev/null || echo '{}')
  osv_count=$(echo "$osv_output" | jq '.results | length' 2>/dev/null || echo 0)
  if [ "$osv_count" -gt 0 ]; then
    log_warning "[$PROJ_NAME] $osv_count résultats osv-scanner"
    echo "- ⚠️ **$osv_count vulnérabilités osv-scanner**" >> "$REPORT"
  fi
fi

echo "" >> "$REPORT"
