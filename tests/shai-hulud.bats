#!/usr/bin/env bats
# Bats tests for the Sentinel shai-hulud module
#
# Install bats: npm install -g bats | brew install bats-core | apk add bats
# Run: bats tests/shai-hulud.bats

SCAN_SH="$BATS_TEST_DIRNAME/../scanner/modules/shai-hulud/scan.sh"
FIXTURES="$BATS_TEST_DIRNAME/fixtures/shai-hulud"

# Create a minimal IoC dir with only npm-packages.txt populated (no domains/daemons).
# This lets tests focus on a single detection vector without DNS noise.
_make_ioc_dir() {
  local dir
  dir=$(mktemp -d)
  cp "$BATS_TEST_DIRNAME/../scanner/modules/shai-hulud/iocs/npm-packages.txt" "$dir/"
  cp "$BATS_TEST_DIRNAME/../scanner/modules/shai-hulud/iocs/files.txt"        "$dir/"
  cp "$BATS_TEST_DIRNAME/../scanner/modules/shai-hulud/iocs/workflows.txt"    "$dir/"
  printf '# empty\n' > "$dir/daemons.txt"
  printf '# empty\n' > "$dir/domains.txt"
  echo "$dir"
}

setup() {
  export REPORTS_DIR="${BATS_TMPDIR}/reports-$$"
  mkdir -p "$REPORTS_DIR"
}

teardown() {
  rm -rf "$REPORTS_DIR"
}

@test "compromised package in package-lock.json exits 3 (CRITICAL)" {
  local ioc_dir
  ioc_dir=$(_make_ioc_dir)
  SHAI_HULUD_IOC_DIR="$ioc_dir" run bash "$SCAN_SH" "$FIXTURES/compromised-npm"
  rm -rf "$ioc_dir"
  [ "$status" -eq 3 ]
}

@test "compromised package in pnpm-lock.yaml exits 3 (CRITICAL)" {
  command -v yq || skip "yq not installed"
  local ioc_dir
  ioc_dir=$(_make_ioc_dir)
  SHAI_HULUD_IOC_DIR="$ioc_dir" run bash "$SCAN_SH" "$FIXTURES/compromised-pnpm"
  rm -rf "$ioc_dir"
  [ "$status" -eq 3 ]
}

@test "clean lockfile exits 0 (CLEAN)" {
  local ioc_dir
  ioc_dir=$(_make_ioc_dir)
  SHAI_HULUD_IOC_DIR="$ioc_dir" run bash "$SCAN_SH" "$FIXTURES/clean"
  rm -rf "$ioc_dir"
  [ "$status" -eq 0 ]
}

@test "directory with router_runtime.js exits 2 (HIGH)" {
  local ioc_dir
  ioc_dir=$(_make_ioc_dir)
  SHAI_HULUD_IOC_DIR="$ioc_dir" run bash "$SCAN_SH" "$FIXTURES/runtime-artifact"
  rm -rf "$ioc_dir"
  [ "$status" -eq 2 ]
}
