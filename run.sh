#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ─────────────────────────────────────────────
# Pre-flight: writable directory check
# The container bind-mounts these three directories and needs write access.
# ─────────────────────────────────────────────
_check_writable() {
  local dir="$1"
  local label="$2"

  # Create directory if it doesn't exist
  if ! mkdir -p "$dir" 2>/dev/null; then
    echo ""
    echo "❌ Cannot create $label directory: $dir"
    echo "   Run: sudo mkdir -p $dir && sudo chown $(id -u):$(id -g) $dir"
    exit 1
  fi

  # Test write access with a temp file
  if ! touch "$dir/.sentinel-write-test" 2>/dev/null; then
    echo ""
    echo "⚠️  $label ($dir) is not writable by the current user."
    echo "   The Sentinel container needs write access to this directory."
    printf "   Fix automatically with chmod 777 %s ? [Y/n] " "$dir"
    read -r _answer
    case "${_answer:-Y}" in
      [Yy]*|"")
        if chmod 777 "$dir"; then
          echo "   ✅ Fixed: $dir"
        else
          echo "   ❌ chmod failed. Try: sudo chmod 777 $dir"
          exit 1
        fi
        ;;
      *)
        echo "   ❌ Skipped. Fix manually before retrying:"
        echo "      chmod 777 $dir"
        exit 1
        ;;
    esac
  else
    rm -f "$dir/.sentinel-write-test"
  fi
}

echo "🔍 Checking directory permissions..."
_check_writable "./data"          "Grype/OSV database cache"
_check_writable "./reports"       "Scan reports"
_check_writable "./scanner/iocs"  "IOC feeds"

echo "🔄 Pulling latest Sentinel..."
git pull --ff-only || { echo "⚠️ Git pull failed — continuing with local version"; }

echo "🔨 Building Sentinel image..."
docker compose build --quiet

echo "📦 Updating vulnerability databases..."
docker compose run --rm sentinel update

echo "🔍 Scanning projects..."
docker compose run --rm \
  -e SKIP_SECRETS="${SKIP_SECRETS:-false}" \
  -e SECRETS_MODE="${SECRETS_MODE:-verified}" \
  -e SECRETS_MAX_DEPTH="${SECRETS_MAX_DEPTH:-}" \
  -e SECRETS_SINCE_COMMIT="${SECRETS_SINCE_COMMIT:-}" \
  -e SECRETS_TIMEOUT="${SECRETS_TIMEOUT:-300}" \
  sentinel "$@"
