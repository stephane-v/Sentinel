#!/bin/bash
# Arguments: $1=PROJECT_DIR $2=REPORT_BODY
# NOTE: Variables inherited from sentinel.sh (sourced): SUMMARY_*, L_*, set_verdict, log_* functions
PROJ="$1"
REPORT="$2"
PROJ_NAME=$(echo "$PROJ" | sed "s|^/projects/||")

echo "-- Scan Node.js: $PROJ_NAME --"
echo "### $PROJ_NAME ($L_NODEJS)" >> "$REPORT"

LOCKFILE="$PROJ/package-lock.json"
[ -f "$LOCKFILE" ] || return

# --- Known compromised packages ---
while IFS= read -r line; do
  [ -z "$line" ] && continue
  [[ "$line" =~ ^# ]] && continue
  pkg=$(echo "$line" | cut -d'@' -f1)
  ver=$(echo "$line" | cut -d'@' -f2)

  found=$(jq -r --arg pkg "$pkg" --arg ver "$ver" \
    '.packages | to_entries[] | select(.key | endswith($pkg)) | select(.value.version == $ver) | .key' \
    "$LOCKFILE" 2>/dev/null)

  if [ -n "$found" ]; then
    log_critique "[$PROJ_NAME] Compromised npm package: $pkg@$ver"
    echo "- 🚨 **$L_COMPROMISED_PKG** : \`$pkg@$ver\`" >> "$REPORT"
    SUMMARY_COMPROMISED_PKG=$((SUMMARY_COMPROMISED_PKG + 1))
  fi
done < /sentinel/iocs/compromised_npm.txt

# --- Packages with install scripts ---
script_count=$(jq '[.packages | to_entries[] | select(.value.hasInstallScript == true)] | length' "$LOCKFILE" 2>/dev/null || echo "?")
echo "- $L_INSTALL_SCRIPTS : **$script_count**" >> "$REPORT"

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
    log_attention "[$PROJ_NAME] npm audit: $critical critical, $high high, $moderate moderate"
    echo "- ⚠️ **npm audit** : $critical critical, $high high, $moderate moderate" >> "$REPORT"
    SUMMARY_VULN_NPM=$((SUMMARY_VULN_NPM + 1))
  else
    echo "- ✅ $L_NO_VULN_NPM ($moderate moderate)" >> "$REPORT"
  fi
  cd - > /dev/null
fi

# --- osv-scanner ---
echo "  osv-scanner..."
osv_output=$(osv-scanner --format json --lockfile "$LOCKFILE" 2>/dev/null || echo '{}')
osv_count=$(echo "$osv_output" | jq '.results | length' 2>/dev/null | tail -1 || true)
osv_count="${osv_count:-0}"
if [ "$osv_count" -gt 0 ] 2>/dev/null; then
  log_attention "[$PROJ_NAME] $osv_count osv-scanner results"
  echo "- ⚠️ **$osv_count osv-scanner vulnerabilities**" >> "$REPORT"
fi

# --- Grype (second opinion, Anchore database) ---
if [ "${GRYPE_AVAILABLE:-0}" -eq 1 ] && [ "${GRYPE_DATE:-not installed}" != "not installed" ]; then
  echo "  grype..."
  grype_output=$(GRYPE_DB_CACHE_DIR="${DATA_DIR:-/data}/grype" grype dir:"$PROJ" --only-fixed -o json -q 2>/dev/null || echo '{"matches":[]}')

  grype_filtered=$(echo "$grype_output" | jq --argjson min "${SEVERITY_MIN_RANK:-2}" '
    [.matches[] |
      (if .vulnerability.severity == "Critical" then 4
       elif .vulnerability.severity == "High" then 3
       elif .vulnerability.severity == "Medium" then 2
       elif .vulnerability.severity == "Low" then 1
       else 0 end) as $rank |
      select($rank >= $min)
    ]' 2>/dev/null || echo '[]')

  grype_count=$(echo "$grype_filtered" | jq 'length' 2>/dev/null | tail -1 || true)
  grype_count="${grype_count:-0}"

  if [ "$grype_count" -gt 0 ] 2>/dev/null; then
    grype_critical=$(echo "$grype_filtered" | jq '[.[] | select(.vulnerability.severity == "Critical")] | length' 2>/dev/null | tail -1 || true)
    grype_high=$(echo "$grype_filtered" | jq '[.[] | select(.vulnerability.severity == "High")] | length' 2>/dev/null | tail -1 || true)
    grype_critical="${grype_critical:-0}"; grype_high="${grype_high:-0}"

    log_attention "[$PROJ_NAME] Grype: $grype_count vulns ($grype_critical Critical, $grype_high High)"
    # shellcheck disable=SC2059
    printf -v _grype_label "$L_GRYPE_VULNS_DETAIL" "$grype_count"
    echo "- ⚠️ **$_grype_label** ($grype_critical Critical, $grype_high High) — *$L_SECOND_OPINION*" >> "$REPORT"

    echo "$grype_filtered" | jq -r '.[0:10][] |
      "  - `\(.artifact.name)` \(.artifact.version) → \(.vulnerability.id) (\(.vulnerability.severity)) — fix: \(.vulnerability.fix.versions // ["?"] | join(", "))"' 2>/dev/null >> "$REPORT" || true
    if [ "$grype_count" -gt 10 ] 2>/dev/null; then
      # shellcheck disable=SC2059
      printf -v _more "$L_AND_MORE" "$((grype_count - 10))"
      echo "  - *$_more*" >> "$REPORT"
    fi
    SUMMARY_VULN_GRYPE=$((SUMMARY_VULN_GRYPE + 1))
  else
    echo "- ✅ $L_NO_VULN_GRYPE" >> "$REPORT"
  fi
fi

echo "" >> "$REPORT"
