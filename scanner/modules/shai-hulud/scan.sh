#!/bin/bash
# Shai-Hulud detection module for Sentinel
# Detects Mini Shai-Hulud supply chain attack family (CVE-2026-45321)
# Waves: Sept 2025, Nov 2025, Apr 2026 (SAP/UiPath), May 2026 (TanStack)
#
# When sourced by sentinel.sh: inherits log_*, set_verdict, SUMMARY_*, VERDICT
# Standalone: bash scanner/modules/shai-hulud/scan.sh [path] [--max-depth N]
#
# Exit codes (standalone or returned by run_shai_hulud_scan):
#   0 — CLEAN
#   1 — LOW/MEDIUM: C2 domains not blocked in network defenses
#   2 — HIGH: runtime artifacts or persistence daemons found
#   3 — CRITICAL: compromised package present in a lockfile

# Apply strict mode only when running standalone — not when sourced by sentinel.sh,
# because sourcing propagates shell options into the caller's process.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
fi

_SHAI_HULUD_MODULE_VERSION="2026-05-13"
_SHAI_HULUD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# SHAI_HULUD_IOC_DIR env var allows overriding the IoC path (useful in tests)
_SHAI_HULUD_IOC_DIR="${SHAI_HULUD_IOC_DIR:-$_SHAI_HULUD_DIR/iocs}"

# === Standalone mode: define minimal stubs when not sourced by sentinel.sh ===
if [ -z "${VERDICT:-}" ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'; NC='\033[0m'
  log_critique()  { echo -e "${RED}[CRITICAL]${NC} $*" >&2; }
  log_attention() { echo -e "${YELLOW}[ATTENTION]${NC} $*" >&2; }
  log_info()      { echo -e "${BLUE}[INFO]${NC} $*"; }
  log_ok()        { echo -e "${GREEN}[OK]${NC} $*"; }
  set_verdict()   { :; }
  SUMMARY_SHAI_HULUD_PKGS=0
  SUMMARY_SHAI_HULUD_ARTIFACTS=0
  SUMMARY_SHAI_HULUD_DAEMONS=0
  SUMMARY_SHAI_HULUD_DOMAINS=0
  _SHAI_HULUD_STANDALONE=1
fi

# Global finding arrays — reset by run_shai_hulud_scan on each invocation
_SH_PKG_FINDINGS=()
_SH_ART_FINDINGS=()
_SH_DAEMON_FINDINGS=()
_SH_DOMAIN_FINDINGS=()

# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

_shai_hulud_check_deps() {
  local missing=0
  for cmd in jq find grep awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "ERROR: required dependency '$cmd' not found — install it and retry" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 127
  if ! command -v yq >/dev/null 2>&1; then
    log_info "yq not found — pnpm-lock.yaml and yarn.lock v2+ will be skipped"
  fi
}

# Look up the wave label for a given IoC line by scanning backwards in npm-packages.txt.
_shai_hulud_wave_for() {
  local target="$1"
  awk -v t="$target" '
    /^# Wave/ { wave = substr($0, 3) }
    $0 == t   { print wave; exit }
  ' "$_SHAI_HULUD_IOC_DIR/npm-packages.txt"
}

# ─────────────────────────────────────────────
# Detection 1 — Lockfile audit
# ─────────────────────────────────────────────

_shai_hulud_scan_package_lock() {
  local lockfile="$1"

  local lock_ver
  lock_ver=$(jq -r '.lockfileVersion // 1' "$lockfile" 2>/dev/null || echo "1")

  while IFS= read -r ioc_line; do
    [[ -z "$ioc_line" || "$ioc_line" == \#* ]] && continue
    # Extract version (after last @) and package name (before last @)
    local ver="${ioc_line##*@}"
    local pkg="${ioc_line%@*}"

    local found=""
    if [ "${lock_ver}" -ge 2 ] 2>/dev/null; then
      # lockfileVersion 2/3: packages object, keys are "node_modules/@scope/pkg"
      found=$(jq -r --arg p "$pkg" --arg v "$ver" \
        '.packages | to_entries[] |
         select(.key | endswith($p)) |
         select(.value.version == $v) |
         .key' "$lockfile" 2>/dev/null)
    else
      # lockfileVersion 1: dependencies object, keys are bare package names
      found=$(jq -r --arg p "$pkg" --arg v "$ver" \
        '.dependencies | to_entries[] |
         select(.key == $p) |
         select(.value.version == $v) |
         .key' "$lockfile" 2>/dev/null)
    fi

    if [ -n "$found" ]; then
      local wave
      wave=$(_shai_hulud_wave_for "$ioc_line")
      _SH_PKG_FINDINGS+=("${lockfile}|${pkg}@${ver}|${wave:-Unknown}")
    fi
  done < "$_SHAI_HULUD_IOC_DIR/npm-packages.txt"
}

_shai_hulud_scan_pnpm_lock() {
  local lockfile="$1"

  command -v yq >/dev/null 2>&1 || return 0

  while IFS= read -r ioc_line; do
    [[ -z "$ioc_line" || "$ioc_line" == \#* ]] && continue
    local ver="${ioc_line##*@}"
    local pkg="${ioc_line%@*}"

    # pnpm lockfile v6+: keys like "@scope/pkg@version" or "/@scope/pkg@version"
    # No need to escape "/" — it is not special in grep ERE
    local found
    found=$(yq -r '.packages | keys[]' "$lockfile" 2>/dev/null \
      | grep -E "^/?${pkg}@${ver}$" || true)

    if [ -n "$found" ]; then
      local wave
      wave=$(_shai_hulud_wave_for "$ioc_line")
      _SH_PKG_FINDINGS+=("${lockfile}|${pkg}@${ver}|${wave:-Unknown}")
    fi
  done < "$_SHAI_HULUD_IOC_DIR/npm-packages.txt"
}

_shai_hulud_scan_yarn_lock() {
  local lockfile="$1"

  # Detect yarn.lock format: v1 (text) vs v2+ (YAML, starts with __metadata)
  local is_v2=0
  head -5 "$lockfile" 2>/dev/null | grep -q "__metadata" && is_v2=1

  while IFS= read -r ioc_line; do
    [[ -z "$ioc_line" || "$ioc_line" == \#* ]] && continue
    local ver="${ioc_line##*@}"
    local pkg="${ioc_line%@*}"

    local found=""
    if [ "$is_v2" -eq 1 ]; then
      command -v yq >/dev/null 2>&1 || continue
      # yarn v2+ YAML: package entries have "version:" field
      found=$(yq -r ".[] | select(type == \"!!map\") | select(.version == \"$ver\") |
        to_entries[] | select(.key | test(\"^npm:${pkg//\//\\/}@\")) | .key" \
        "$lockfile" 2>/dev/null || true)
    else
      # yarn v1 classic text format:
      # "<pkg>@^x.y.z":
      #   version "x.y.z"
      found=$(awk -v search="${pkg}@" -v ver="$ver" '
        /^[^[:space:]]/ { in_block = ($0 ~ search) }
        in_block && /^  version / {
          gsub(/"/, "")
          if ($2 == ver) { print "found"; exit }
        }
      ' "$lockfile" 2>/dev/null || true)
    fi

    if [ -n "$found" ]; then
      local wave
      wave=$(_shai_hulud_wave_for "$ioc_line")
      _SH_PKG_FINDINGS+=("${lockfile}|${pkg}@${ver}|${wave:-Unknown}")
    fi
  done < "$_SHAI_HULUD_IOC_DIR/npm-packages.txt"
}

_shai_hulud_audit_lockfiles() {
  local scan_path="$1"
  local max_depth="$2"

  # Find all lockfiles up to max_depth, excluding node_modules and .git
  while IFS= read -r lf; do
    local base
    base=$(basename "$lf")
    case "$base" in
      package-lock.json) _shai_hulud_scan_package_lock "$lf" ;;
      pnpm-lock.yaml)    _shai_hulud_scan_pnpm_lock    "$lf" ;;
      yarn.lock)         _shai_hulud_scan_yarn_lock     "$lf" ;;
    esac
  done < <(find "$scan_path" \
    -maxdepth "$max_depth" \
    \( -name "package-lock.json" -o -name "pnpm-lock.yaml" -o -name "yarn.lock" \) \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    2>/dev/null | sort)
}

# ─────────────────────────────────────────────
# Detection 2 — Runtime artifacts
# ─────────────────────────────────────────────

_shai_hulud_scan_artifacts() {
  local scan_path="$1"
  local max_depth="$2"

  while IFS= read -r ioc_line; do
    [[ -z "$ioc_line" || "$ioc_line" == \#* ]] && continue

    local sig_required=0
    local fname="$ioc_line"
    if [[ "$ioc_line" == sig:* ]]; then
      sig_required=1
      fname="${ioc_line#sig:}"
    fi

    while IFS= read -r fpath; do
      if [ "$sig_required" -eq 1 ]; then
        # Only flag if file contains a Shai-Hulud marker string
        grep -qiE "shai.?hulud|gh-token-monitor|tanstack_runner" "$fpath" 2>/dev/null || continue
      fi
      _SH_ART_FINDINGS+=("${fpath}|file|${fname}")
    done < <(find "$scan_path" \
      -maxdepth "$max_depth" \
      -name "$fname" \
      -not -path "*/node_modules/*" \
      -not -path "*/.git/*" \
      -not -path "*/proc/*" \
      -not -path "*/sys/*" \
      -not -path "*/dev/*" \
      2>/dev/null)
  done < "$_SHAI_HULUD_IOC_DIR/files.txt"

  # Malicious GitHub Actions workflows
  while IFS= read -r wf_name; do
    [[ -z "$wf_name" || "$wf_name" == \#* ]] && continue
    while IFS= read -r wf_path; do
      _SH_ART_FINDINGS+=("${wf_path}|workflow|${wf_name}")
    done < <(find "$scan_path" \
      -maxdepth "$max_depth" \
      -path "*/.github/workflows/$wf_name" \
      2>/dev/null)
  done < "$_SHAI_HULUD_IOC_DIR/workflows.txt"
}

# ─────────────────────────────────────────────
# Detection 3 — Persistence daemons
# ─────────────────────────────────────────────

_shai_hulud_scan_daemons() {
  local -a search_dirs=()

  # macOS LaunchAgents
  if [ -d "${HOME:-/root}/Library/LaunchAgents" ]; then
    search_dirs+=("${HOME}/Library/LaunchAgents")
  fi
  [ -d "/Library/LaunchAgents" ] && search_dirs+=("/Library/LaunchAgents")

  # Linux systemd
  if [ -d "${HOME:-/root}/.config/systemd/user" ]; then
    search_dirs+=("${HOME}/.config/systemd/user")
  fi
  [ -d "/etc/systemd/system" ] && search_dirs+=("/etc/systemd/system")

  [ "${#search_dirs[@]}" -eq 0 ] && return 0

  while IFS= read -r daemon_name; do
    [[ -z "$daemon_name" || "$daemon_name" == \#* ]] && continue

    for dir in "${search_dirs[@]}"; do
      # Match by plist/service file name
      while IFS= read -r df; do
        _SH_DAEMON_FINDINGS+=("${df}|name-match|${daemon_name}")
      done < <(find "$dir" -maxdepth 2 \
        \( -name "${daemon_name}.plist" -o -name "${daemon_name}.service" \) \
        2>/dev/null)

      # Heuristic: any plist/unit whose command references gh-token
      while IFS= read -r df; do
        if grep -qiE "gh.?token|gh-token" "$df" 2>/dev/null; then
          _SH_DAEMON_FINDINGS+=("${df}|heuristic|gh-token keyword in ExecStart/ProgramArguments")
        fi
      done < <(find "$dir" -maxdepth 2 \
        \( -name "*.plist" -o -name "*.service" \) \
        2>/dev/null)
    done
  done < "$_SHAI_HULUD_IOC_DIR/daemons.txt"
}

# ─────────────────────────────────────────────
# Detection 4 — DNS/proxy blocking
# ─────────────────────────────────────────────

_shai_hulud_check_dns() {
  while IFS= read -r domain; do
    [[ -z "$domain" || "$domain" == \#* ]] && continue

    local blocked=0

    # /etc/hosts
    if grep -qE "^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]].*${domain}" /etc/hosts 2>/dev/null; then
      blocked=1
    fi

    # AdGuard Home
    if [ "$blocked" -eq 0 ] && command -v AdGuardHome >/dev/null 2>&1; then
      local ag_config
      ag_config=$(find /opt /etc /home -maxdepth 4 -name "AdGuardHome.yaml" 2>/dev/null | head -1)
      if [ -n "$ag_config" ] && grep -qF "$domain" "$ag_config" 2>/dev/null; then
        blocked=1
      fi
    fi

    # Pi-hole
    if [ "$blocked" -eq 0 ] && command -v pihole >/dev/null 2>&1; then
      if pihole -q "$domain" 2>/dev/null | grep -q "Match found"; then
        blocked=1
      fi
    fi

    # CrowdSec
    if [ "$blocked" -eq 0 ] && command -v cscli >/dev/null 2>&1; then
      if cscli decisions list --scope dns 2>/dev/null | grep -qF "$domain"; then
        blocked=1
      fi
    fi

    if [ "$blocked" -eq 0 ]; then
      _SH_DOMAIN_FINDINGS+=("$domain")
    fi
  done < "$_SHAI_HULUD_IOC_DIR/domains.txt"
}

# ─────────────────────────────────────────────
# Report writer
# ─────────────────────────────────────────────

_shai_hulud_write_report() {
  local report="$1"
  local scan_path="$2"

  local pkg_count="${#_SH_PKG_FINDINGS[@]}"
  local art_count="${#_SH_ART_FINDINGS[@]}"
  local daemon_count="${#_SH_DAEMON_FINDINGS[@]}"
  local domain_count="${#_SH_DOMAIN_FINDINGS[@]}"

  local global_severity="CLEAN"
  [ "$domain_count" -gt 0 ] && global_severity="MEDIUM"
  [ "$(( art_count + daemon_count ))" -gt 0 ] && global_severity="HIGH"
  [ "$pkg_count" -gt 0 ] && global_severity="CRITICAL"

  cat >> "$report" <<SECTION
## Shai-Hulud Scan (CVE-2026-45321)

**Date** : $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Host** : $(hostname 2>/dev/null || echo "unknown")
**Path scanned** : ${scan_path}
**Module version** : ${_SHAI_HULUD_MODULE_VERSION}

### Summary

- **Global severity** : ${global_severity}
- Compromised packages in lockfiles : ${pkg_count}
- Runtime artifacts : ${art_count}
- Persistence daemons : ${daemon_count}
- C2 domains not blocked : ${domain_count}

SECTION

  # 1. Compromised packages
  echo "### 1. Compromised packages in lockfiles" >> "$report"
  echo "" >> "$report"
  if [ "$pkg_count" -gt 0 ]; then
    echo "| Lockfile | Package | Wave |" >> "$report"
    echo "|----------|---------|------|" >> "$report"
    for entry in "${_SH_PKG_FINDINGS[@]}"; do
      IFS='|' read -r lf pkg wave <<< "$entry"
      echo "| \`${lf}\` | \`${pkg}\` | ${wave} |" >> "$report"
    done
  else
    echo "✅ No compromised packages found in lockfiles." >> "$report"
  fi
  echo "" >> "$report"

  # 2. Runtime artifacts
  echo "### 2. Runtime artifacts detected" >> "$report"
  echo "" >> "$report"
  if [ "$art_count" -gt 0 ]; then
    echo "| Path | Type | IoC matched |" >> "$report"
    echo "|------|------|-------------|" >> "$report"
    for entry in "${_SH_ART_FINDINGS[@]}"; do
      IFS='|' read -r fpath ftype ioc_name <<< "$entry"
      echo "| \`${fpath}\` | ${ftype} | ${ioc_name} |" >> "$report"
    done
  else
    echo "✅ No runtime artifacts detected." >> "$report"
  fi
  echo "" >> "$report"

  # 3. Persistence daemons
  echo "### 3. Persistence daemons" >> "$report"
  echo "" >> "$report"
  if [ "$daemon_count" -gt 0 ]; then
    echo "| Path | Type | Reason |" >> "$report"
    echo "|------|------|--------|" >> "$report"
    for entry in "${_SH_DAEMON_FINDINGS[@]}"; do
      IFS='|' read -r dpath dtype dreason <<< "$entry"
      echo "| \`${dpath}\` | ${dtype} | ${dreason} |" >> "$report"
    done
  else
    echo "✅ No persistence daemons detected." >> "$report"
  fi
  echo "" >> "$report"

  # 4. Unblocked C2 domains
  echo "### 4. C2 domains not blocked" >> "$report"
  echo "" >> "$report"
  if [ "$domain_count" -gt 0 ]; then
    echo "| Domain | Checked via |" >> "$report"
    echo "|--------|------------|" >> "$report"
    for domain in "${_SH_DOMAIN_FINDINGS[@]}"; do
      echo "| \`${domain}\` | /etc/hosts, AdGuard, Pi-hole, CrowdSec |" >> "$report"
    done
  else
    echo "✅ All known C2 domains are blocked." >> "$report"
  fi
  echo "" >> "$report"

  # Remediation
  if [ "$global_severity" != "CLEAN" ]; then
    cat >> "$report" <<'REMEDIATION'
### Remediation actions (ordered by priority)

1. - [ ] Rotate all **npm tokens** (`~/.npmrc`, CI secrets, Renovate/Dependabot credentials)
2. - [ ] Rotate **GitHub PATs** and audit OIDC trust policies (`pull_request_target` workflows)
3. - [ ] Rotate **AWS credentials** — both static keys and instance roles touched by the compromised runner
4. - [ ] Rotate **Vault tokens** scoped to the affected CI pipelines
5. - [ ] Rotate **Kubernetes service account tokens** used in CI
6. - [ ] Audit **GitHub Actions run logs** between wave timestamps (see README for dates)
7. - [ ] Run `npm audit` / `pnpm audit` after removing compromised packages
8. - [ ] Block C2 domains listed above in your DNS resolver or firewall

REMEDIATION
  fi

  # References
  cat >> "$report" <<'REFS'
### References

- [Socket — TanStack npm packages compromised (Mini Shai-Hulud Wave 4)](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)
- [Snyk — TanStack npm packages compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [StepSecurity — Mini Shai-Hulud is back](https://www.stepsecurity.io)
- [Wiz — Mini Shai-Hulud strikes again](https://wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [GitHub Advisory GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [TanStack postmortem — GitHub issue #7383](https://github.com/TanStack/router/issues/7383)

REFS
}

# ─────────────────────────────────────────────
# Main scan function
# ─────────────────────────────────────────────

run_shai_hulud_scan() {
  local SCAN_PATH="${1:-/projects}"
  local REPORT="${2:-/dev/null}"
  local MAX_DEPTH="${_SHAI_HULUD_MAX_DEPTH:-6}"

  _shai_hulud_check_deps

  # Reset finding arrays for this invocation
  _SH_PKG_FINDINGS=()
  _SH_ART_FINDINGS=()
  _SH_DAEMON_FINDINGS=()
  _SH_DOMAIN_FINDINGS=()

  echo "-- Shai-Hulud scan: $SCAN_PATH (max-depth=$MAX_DEPTH) --"

  _shai_hulud_audit_lockfiles "$SCAN_PATH" "$MAX_DEPTH"
  _shai_hulud_scan_artifacts  "$SCAN_PATH" "$MAX_DEPTH"
  _shai_hulud_scan_daemons
  _shai_hulud_check_dns

  local pkg_count="${#_SH_PKG_FINDINGS[@]}"
  local art_count="${#_SH_ART_FINDINGS[@]}"
  local daemon_count="${#_SH_DAEMON_FINDINGS[@]}"
  local domain_count="${#_SH_DOMAIN_FINDINGS[@]}"

  # Update inherited summary counters
  SUMMARY_SHAI_HULUD_PKGS=$(( SUMMARY_SHAI_HULUD_PKGS + pkg_count ))
  SUMMARY_SHAI_HULUD_ARTIFACTS=$(( SUMMARY_SHAI_HULUD_ARTIFACTS + art_count ))
  SUMMARY_SHAI_HULUD_DAEMONS=$(( SUMMARY_SHAI_HULUD_DAEMONS + daemon_count ))
  SUMMARY_SHAI_HULUD_DOMAINS=$(( SUMMARY_SHAI_HULUD_DOMAINS + domain_count ))

  # Escalate global verdict when integrated in full scan
  if [ "$pkg_count" -gt 0 ]; then
    log_critique "Shai-Hulud: $pkg_count compromised package(s) in lockfiles (CVE-2026-45321)"
    set_verdict CRITIQUE
  fi
  if [ "$(( art_count + daemon_count ))" -gt 0 ]; then
    log_attention "Shai-Hulud: $art_count artifact(s) and $daemon_count daemon(s) detected"
    set_verdict ATTENTION
  fi
  if [ "$domain_count" -gt 0 ]; then
    log_info "Shai-Hulud: $domain_count C2 domain(s) not blocked in network defenses"
    set_verdict INFO
  fi

  if [ "$pkg_count" -eq 0 ] && [ "$(( art_count + daemon_count + domain_count ))" -eq 0 ]; then
    log_ok "Shai-Hulud: no indicators found"
  fi

  _shai_hulud_write_report "$REPORT" "$SCAN_PATH"

  # Return shai-hulud exit code
  if [ "$pkg_count" -gt 0 ]; then
    return 3
  elif [ "$(( art_count + daemon_count ))" -gt 0 ]; then
    return 2
  elif [ "$domain_count" -gt 0 ]; then
    return 1
  fi
  return 0
}

# ─────────────────────────────────────────────
# Standalone execution
# ─────────────────────────────────────────────

if [ "${_SHAI_HULUD_STANDALONE:-0}" = "1" ]; then
  # Parse CLI args: [path] [--max-depth N]
  _sh_scan_path="${1:-/projects}"
  shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --max-depth) _SHAI_HULUD_MAX_DEPTH="${2:-6}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done

  # Ensure reports directory exists
  _sh_reports_dir="${REPORTS_DIR:-./reports}"
  mkdir -p "$_sh_reports_dir"
  _sh_report_file="${_sh_reports_dir}/shai-hulud-$(date -u '+%Y-%m-%dT%H%M%SZ').md"

  cat > "$_sh_report_file" <<HEADER
# Sentinel Shai-Hulud Scan Report

**Date** : $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Host** : $(hostname 2>/dev/null || echo "unknown")
**Path scanned** : ${_sh_scan_path}
**Sentinel version** : ${SENTINEL_VERSION:-dev}
**Module version** : ${_SHAI_HULUD_MODULE_VERSION}

---

HEADER

  _SH_EXIT=0
  run_shai_hulud_scan "$_sh_scan_path" "$_sh_report_file" || _SH_EXIT=$?

  echo ""
  echo "--- Shai-Hulud Scan Report ---"
  cat "$_sh_report_file"
  echo ""
  echo "Report saved: $_sh_report_file"
  echo "Exit code: $_SH_EXIT"

  exit $_SH_EXIT
fi
