# Purpose

Owns Telegram notification delivery for request and flag metadata.

# Ownership

- `notify.go`: daemon-lifetime `Runner`, request deduplication and hourly attempt budget.
- `telegram.go`: bounded HTTP transport with credential-free errors.
- `notify_test.go`: fake-clock, fake-transport and HTTP boundary tests.

# Local Contracts

- Keep one `NewRunner` for the daemon lifetime, including credential replacement.
- Credentials come from the daemon environment (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) or, when unset, independent local service storage at cold startup or settings save; delivery needs no vault unlock or secret grant.
- Cancel and await the current run before replacing credentials or closing its service.
- Reserve at most 30 attempts per monotonic hour; request IDs remain deduplicated across replacement. Seen request IDs are kept for 24 monotonic hours and capped at 1024 entries (oldest dropped first).
- An event that cancellation prevents from completing delivery (dequeued after cancellation, or a send cancelled in flight) releases its budget reservation and seen mark and is kept by the Runner; the next run delivers it first.
- Send plaintext metadata and approval links; keep values and credentials out of messages and audit errors.
- Bound HTTP calls to ten seconds, refuse redirects and cap response reads at 64 KiB.

# Work Guidance

- Tests use fake credentials and local HTTP servers.

# Verification

- `toolchain/run go test -race ./internal/notify/...`.
- `toolchain/run go test -race ./cmd/tokencrypt/...` checks credential replacement and shutdown.

# Child DOX Index

None.
