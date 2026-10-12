# Purpose

Owns executable integration checks using temporary vaults and fake credentials.

# Ownership

- `e2e.sh` builds a static binary and runs `e2e.go`.
- `e2e.go` drives the real binary, web forms, Unix-socket CLI and local fake Telegram server. It writes a `0600` env file with fake credentials and starts the daemon with `--env-file`.

# Local Contracts

- Run through `toolchain/run sh scripts/e2e.sh`; `toolchain/check` runs the same check.
- Print PASS or FAIL assertion labels; keep credential values and daemon logs out of output.
- Clean temporary files and daemon processes on success or failure.
- Assert fake Telegram delivery from the env file, including after a locked process restart before login/unlock, with protected CLI reads denied. Scan vault files and the audit log for the bot token.
- Do not invoke `toolchain/check` from the harness.

# Work Guidance

- Keep the harness compatible with the pinned Go container and its standard utilities.

# Verification

- `sh -n scripts/e2e.sh` and `toolchain/run sh scripts/e2e.sh`.

# Child DOX Index

None.
