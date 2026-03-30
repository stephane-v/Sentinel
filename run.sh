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
docker compose run --rm sentinel "$@"
