#!/usr/bin/env bash
set -euo pipefail

cleanup_dir=""
if [ -z "${TMPDIR:-}" ]; then
  cleanup_dir="$(mktemp -d)"
  TMPDIR="$cleanup_dir"
  export TMPDIR
  trap 'rm -rf "$cleanup_dir"' EXIT
fi

export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR"

zig fmt --check build.zig build.zig.zon src
zig build
zig build test
(
  cd test-vectors
  cargo check
)
