#!/usr/bin/env sh
set -e
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"
zig build cli -- "$@"
