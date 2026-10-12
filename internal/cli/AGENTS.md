# Purpose

Owns the agent CLI command runner.

# Ownership

- `cli.go`: command parsing, socket calls, byte output and child process environment.
- `cli_test.go`: allowed commands, byte boundaries, metadata escaping and child exit behavior.

# Local Contracts

- Allow `get`, `run`, `request`, `status` and `flag`; validate arguments before dialing.
- Return 0 for success, 1 for operation failure, 2 for usage or the child's exit status; signals use `128 + signal`.
- `get` preserves bytes without adding a newline. `run` obtains all grants before launching the child and replaces matching uppercase variables.
- Reject NUL or environment entries over 128 KiB including name, equals sign and final NUL; direct the caller to `get`.
- `status` prints each secret’s `token_expires_on` as YYYY-MM-DD or Never, separate from a grant’s `expires` timestamp.
- Escape metadata for terminal output and keep upstream errors and credential values out of diagnostics.

# Work Guidance

- Agent commands cannot unlock, grant, create, update, delete or clear flags.

# Verification

- `toolchain/run go test -race ./internal/cli/...`.

# Child DOX Index

None.
