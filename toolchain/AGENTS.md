# Purpose

Owns the pinned Go build environment and the local check command.

# Ownership

This boundary owns `Containerfile`, `versions.env`, `build`, `run` and `check`. It does not own Go source code or module dependencies.

# Local Contracts

- Go 1.27.2 (stable on go.dev/dl, checked 2026-10-09) from `docker.io/library/golang:1.27.2-bookworm`, pinned by multi-arch index digest in `versions.env`.
- `golang.org/x/crypto` v0.58.0 is the latest tag on proxy.golang.org (checked 2026-10-09); `internal/crypto` imports it (argon2, chacha20poly1305, hkdf).
- `toolchain/build` builds the image `localhost/tokencrypt-toolchain:1` from `Containerfile` and `versions.env`.
- `toolchain/run COMMAND [ARGS...]` runs a command in that image with the worktree mounted at `/workspace`; the Go build and module caches live in ignored `.local/`.
- `toolchain/check` runs `gofmt -l cmd internal scripts` (fails on any output), `go vet ./...`, `go test -race ./...` and `scripts/e2e.sh`.
- Mount only the current worktree; never mount a host home or credentials.
- Change pins only in `versions.env`.

# Work Guidance

- Keep wrappers narrow: `set -eu`, quoted paths, `exec` where possible.

# Verification

- `sh -n toolchain/build toolchain/run toolchain/check` checks wrapper syntax.
- `toolchain/run go version` prints `go1.27.2`.
- `toolchain/check` exits 0 on a clean tree.

# Child DOX Index

None.
