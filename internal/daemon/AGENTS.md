# Purpose

Owns the shared service, vault lock and listener lifecycle.

# Ownership

- `daemon.go`: `Config`, `Run`, bootstrap, exclusive vault lock and coordinated shutdown.
- `harden_linux.go`: `Harden` reports dumpable and memory-lock limits.
- `daemon_test.go`: lifecycle, lock, recovery, loopback and hardening checks.

# Local Contracts

- Production callers invoke `Harden` before processing passphrases. `Run` does not harden test processes.
- Hold the exclusive vault lock from first-run setup through service shutdown.
- `SetupFactory` handles an uninitialized vault; its callback signals successful initialization. Finish the setup POST before starting the normal service.
- `WebFactory` receives the same `core.Service` as the Unix-socket API.
- `OnService` returns owned-work cleanup. Cancel its context and await cleanup before `core.Service.Close`.
- Bind the website to a loopback IP. Cancel listeners, remove the socket and release the lock on shutdown.

# Work Guidance

- Keep storage policy in core and vault; use generic credential-free diagnostics.

# Verification

- `toolchain/run go test -race ./internal/daemon/...`.
- `toolchain/run sh scripts/e2e.sh` checks first-run lock and restart restoration.

# Child DOX Index

None.
