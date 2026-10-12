#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
CGO_ENABLED=0 go build -o "$WORK/tokencrypt" ./cmd/tokencrypt
go run ./scripts/e2e.go "$WORK/tokencrypt"
