# Purpose

Owns the executable entry points of the module `tokencrypt`.

# Ownership

`cmd/tokencrypt` holds the `main` package for the single `tokencrypt` binary. It parses the command line and calls into `internal/` packages; rules and storage live there.

# Local Contracts

- `tokencrypt` with no arguments, or an unknown command, prints usage to stderr and exits 2.
- Keep `main` thin: no business rules.
- `init` reads and confirms the passphrase from stdin; terminal input disables echo.
- `serve` calls `Harden` before setup or service operations and shares one core service between web and API.
- `serve` flags: `--vault-dir`, `--state-dir`, `--socket`, `--listen`, `--allowed-hosts`, `--secure-cookies`, `--approval-url` (default `http://crypt.local`), `--telegram-api-base`, `--env-file`. Storage uses XDG defaults; `--env-file` defaults to `$XDG_CONFIG_HOME/tokencrypt/telegram.env` (`~/.config/tokencrypt/telegram.env` when unset). CLI socket selection checks `TOKENCRYPT_SOCKET` then `XDG_RUNTIME_DIR`.
- The notifier has one credential source: the env file, read once in `OnService` before the agent socket starts, through `notify.LoadCredentials`. Process environment variables are not read, nothing replaces credentials at runtime, and a token change needs a daemon restart.
- A missing file leaves the notifier off with no audit event. An unsafe file (symlink, not a regular file, not owned by the daemon user, any group or other permission bit), a partial pair or invalid values leave it off and write one generic `notifier.failed` audit event without values or paths.
- Valid credentials start one `notify.Runner` with the `--telegram-api-base` transport; delivery works while the vault is locked and preserves locked grant state. Shutdown cancels and awaits the run, then zeroes the token. The daemon reads no credential file from the vault directory.

# Work Guidance

- Format with `gofmt`; build and run through `toolchain/run`.

# Verification

- `toolchain/check` vets and tests the module.
- `toolchain/run go run ./cmd/tokencrypt` prints usage and exits 2.

# Child DOX Index

None.
