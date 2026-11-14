#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
NODE_BIN="${PHP2SHELL_NODE:-node}"

exec "$NODE_BIN" "$SCRIPT_DIR/src/cli.js" "$@"
