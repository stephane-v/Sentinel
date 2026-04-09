#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

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
