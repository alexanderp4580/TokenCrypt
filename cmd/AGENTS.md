# Purpose

Owns the executable entry points of the module `tokencrypt`.

# Ownership

`cmd/tokencrypt` holds the `main` package for the single `tokencrypt` binary. It parses the command line and calls into `internal/` packages; rules and storage live there.

# Local Contracts

- `tokencrypt` with no arguments, or an unknown command, prints usage to stderr and exits 2.
- Keep `main` thin: no business rules.
- `init` reads and confirms the passphrase from stdin; terminal input disables echo.
- `serve` calls `Harden` before setup or service operations, shares one core service between web and API, and owns notifier credential replacement.
- `serve` flags: `--vault-dir`, `--state-dir`, `--socket`, `--listen`, `--allowed-hosts`, `--secure-cookies`, `--approval-url`, `--telegram-api-base`. Storage uses XDG defaults; CLI socket selection checks `TOKENCRYPT_SOCKET` then `XDG_RUNTIME_DIR`.
- Keep one notification Runner for the daemon lifetime. Cancel and await a credential run, then zero its token before replacement or service closure.
- `serve` reads `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` once at startup and unsets them. Both present and valid (trimmed, `vault.ValidNotifierCredentials`) make the environment the sole credential source: it takes precedence over service and vault settings, settings saves and unlocks leave the transport unchanged, and values are never logged, audited or displayed. A partial or invalid pair audits generic `notifier.failed` and uses service settings.
- Start the notifier from independent service credentials in `OnService`, before the agent socket starts; startup preserves locked grant state. Authenticated settings saves and migration refresh the transport without a restart. Read current credentials under the lifecycle replacement lock so concurrent callbacks cannot activate stale settings. Startup credential failures audit a generic diagnostic. A refresh that finds unreadable service settings keeps a running notifier; a refresh that leaves a running notifier without credentials stops it and audits generic `notifier.failed`. `serve` sets `web.Config.EnvNotifier` when environment credentials are active.

# Work Guidance

- Format with `gofmt`; build and run through `toolchain/run`.

# Verification

- `toolchain/check` vets and tests the module.
- `toolchain/run go run ./cmd/tokencrypt` prints usage and exits 2.

# Child DOX Index

None.
