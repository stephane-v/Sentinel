#!/bin/bash
# Sentinel IOC Feed Updater
# Fetches latest IOCs from public threat intelligence sources
# Called by sentinel.sh during 'update' command

set -uo pipefail

IOC_DIR="${IOC_DIR:-/sentinel/iocs}"
LOG_PREFIX="[IOC Update]"

log() { echo "$LOG_PREFIX $*"; }

# === Network check ===
check_network() {
  if ! curl -s --max-time 5 "https://api.osv.dev" >/dev/null 2>&1; then
    log "WARNING: No network access — skipping IOC feed update"
    log "Using existing IOC lists"
    return 1
  fi
  return 0
}

# === Backup ===
backup_iocs() {
  local backup_dir="$IOC_DIR/.backup-$(date +%Y%m%d)"
  mkdir -p "$backup_dir" 2>/dev/null || true
  cp "$IOC_DIR"/*.txt "$backup_dir/" 2>/dev/null || true
  log "Backup saved to $backup_dir"
}

# === Deduplicate all IOC files ===
deduplicate() {
  for f in "$IOC_DIR"/*.txt; do
    [ -f "$f" ] || continue
    # Preserve comment lines at top, sort the rest, remove blank line dupes
    local header=$(grep "^#" "$f" 2>/dev/null || true)
    local entries=$(grep -v "^#" "$f" 2>/dev/null | grep -v "^$" | sort -u || true)
    {
      [ -n "$header" ] && echo "$header"
      [ -n "$entries" ] && echo "$entries"
    } > "${f}.tmp"
    mv "${f}.tmp" "$f"
  done
}

# === Count entries (excluding comments and blanks) ===
count_entries() {
  local file="$1"
  grep -v "^#" "$file" 2>/dev/null | grep -c -v "^$" 2>/dev/null || echo 0
}

# === Source 1: OSV.dev API — npm MAL-* advisories ===
update_osv_npm() {
  local tmp=$(mktemp /tmp/osv-npm.XXXXXX)
  local added=0
  local target="$IOC_DIR/compromised_npm.txt"

  # Query MAL-* advisories for npm (last 90 days)
  local since
  since=$(date -d '90 days ago' +%Y-%m-%dT00:00:00Z 2>/dev/null || \
          date -v-90d +%Y-%m-%dT00:00:00Z 2>/dev/null || \
          echo "2025-01-01T00:00:00Z")

  curl -s --max-time 30 "https://api.osv.dev/v1/querybatch" \
    -H "Content-Type: application/json" \
    -d "{\"queries\":[{\"package\":{\"ecosystem\":\"npm\"},\"modified_after\":\"$since\"}]}" \
    > "$tmp" 2>/dev/null || true

  if [ -s "$tmp" ]; then
    local entries
    entries=$(jq -r '
      .results[]?.vulns[]? |
      select(.id | startswith("MAL-")) |
      .affected[]? |
      .package.name as $name |
      (.versions[]? // empty) |
      "\($name)@\(.)"
    ' "$tmp" 2>/dev/null | sort -u || true)

    if [ -n "$entries" ]; then
      while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        if ! grep -qxF "$entry" "$target" 2>/dev/null; then
          echo "$entry" >> "$target"
          added=$((added + 1))
          echo "  + npm: $entry"
        fi
      done <<< "$entries"
    fi
  fi

  rm -f "$tmp"
  log "npm IOCs: $added new entries from OSV.dev"
}

# === Source 1b: OSV.dev API — PyPI MAL-* advisories ===
update_osv_pypi() {
  local tmp=$(mktemp /tmp/osv-pypi.XXXXXX)
  local added=0
  local target="$IOC_DIR/compromised_pypi.txt"

  local since
  since=$(date -d '90 days ago' +%Y-%m-%dT00:00:00Z 2>/dev/null || \
          date -v-90d +%Y-%m-%dT00:00:00Z 2>/dev/null || \
          echo "2025-01-01T00:00:00Z")

  curl -s --max-time 30 "https://api.osv.dev/v1/querybatch" \
    -H "Content-Type: application/json" \
    -d "{\"queries\":[{\"package\":{\"ecosystem\":\"PyPI\"},\"modified_after\":\"$since\"}]}" \
    > "$tmp" 2>/dev/null || true

  if [ -s "$tmp" ]; then
    local entries
    entries=$(jq -r '
      .results[]?.vulns[]? |
      select(.id | startswith("MAL-")) |
      .affected[]? |
      .package.name as $name |
      (.versions[]? // empty) |
      "\($name)@\(.)"
    ' "$tmp" 2>/dev/null | sort -u || true)

    if [ -n "$entries" ]; then
      while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        if ! grep -qxF "$entry" "$target" 2>/dev/null; then
          echo "$entry" >> "$target"
          added=$((added + 1))
          echo "  + pypi: $entry"
        fi
      done <<< "$entries"
    fi
  fi

  rm -f "$tmp"
  log "PyPI IOCs: $added new entries from OSV.dev"
}

# === Source 2: GitHub Advisory Database — MALWARE advisories ===
update_github_advisories() {
  local tmp=$(mktemp /tmp/ghsa.XXXXXX)
  local added=0

  # npm malware advisories
  curl -s --max-time 30 "https://api.github.com/advisories?type=malware&ecosystem=npm&per_page=100" \
    -H "Accept: application/vnd.github+json" \
    > "$tmp" 2>/dev/null || true

  if [ -s "$tmp" ]; then
    local entries
    entries=$(jq -r '
      .[]? | .vulnerabilities[]? |
      select(.package.ecosystem == "npm") |
      "\(.package.name)@\(.vulnerable_version_range // "any")"
    ' "$tmp" 2>/dev/null | sort -u || true)

    if [ -n "$entries" ]; then
      while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        if ! grep -qxF "$entry" "$IOC_DIR/compromised_npm.txt" 2>/dev/null; then
          echo "$entry" >> "$IOC_DIR/compromised_npm.txt"
          added=$((added + 1))
          echo "  + npm (GHSA): $entry"
        fi
      done <<< "$entries"
    fi
  fi

  # PyPI malware advisories
  curl -s --max-time 30 "https://api.github.com/advisories?type=malware&ecosystem=pip&per_page=100" \
    -H "Accept: application/vnd.github+json" \
    > "$tmp" 2>/dev/null || true

  if [ -s "$tmp" ]; then
    local entries
    entries=$(jq -r '
      .[]? | .vulnerabilities[]? |
      select(.package.ecosystem == "pip") |
      "\(.package.name)@\(.vulnerable_version_range // "any")"
    ' "$tmp" 2>/dev/null | sort -u || true)

    if [ -n "$entries" ]; then
      while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        if ! grep -qxF "$entry" "$IOC_DIR/compromised_pypi.txt" 2>/dev/null; then
          echo "$entry" >> "$IOC_DIR/compromised_pypi.txt"
          added=$((added + 1))
          echo "  + pypi (GHSA): $entry"
        fi
      done <<< "$entries"
    fi
  fi

  rm -f "$tmp"
  log "GitHub Advisories: $added new entries"
}

# === Main ===
main() {
  log "Starting IOC feed update..."

  # Check network
  if ! check_network; then
    return 0
  fi

  backup_iocs

  # Count before
  local npm_before pypi_before
  npm_before=$(count_entries "$IOC_DIR/compromised_npm.txt")
  pypi_before=$(count_entries "$IOC_DIR/compromised_pypi.txt")

  # Fetch from sources
  log "Fetching from OSV.dev..."
  update_osv_npm
  update_osv_pypi

  log "Fetching from GitHub Advisory Database..."
  update_github_advisories

  # Deduplicate
  deduplicate

  # Count after
  local npm_after pypi_after
  npm_after=$(count_entries "$IOC_DIR/compromised_npm.txt")
  pypi_after=$(count_entries "$IOC_DIR/compromised_pypi.txt")

  # Summary
  log "Update complete:"
  log "  npm:  $npm_before → $npm_after entries (+$((npm_after - npm_before)) new)"
  log "  PyPI: $pypi_before → $pypi_after entries (+$((pypi_after - pypi_before)) new)"
}

main "$@"
