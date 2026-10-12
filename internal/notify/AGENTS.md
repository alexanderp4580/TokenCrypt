# Purpose

Owns Telegram notification delivery for request and flag metadata.

# Ownership

- `notify.go`: daemon-lifetime `Runner`, request deduplication and hourly attempt budget.
- `telegram.go`: bounded HTTP transport with credential-free errors.
- `credentials.go`: env-file credential loader and `ValidNotifierCredentials`.
- `notify_test.go`, `credentials_test.go`: fake-clock, fake-transport, HTTP boundary and env-file tests.

# Local Contracts

- Keep one `NewRunner` for the daemon lifetime.
- `LoadCredentials(path)` reads `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` from a `KEY=VALUE` file: blank and `#` lines ignored, whitespace trimmed, matching single or double quotes around a value stripped, CRLF accepted, unknown keys ignored, last duplicate wins. The file is opened without following symlinks and must be a regular file owned by the current user with no group or other bits, at most 64 KiB. A missing file returns `ErrNotConfigured`; every other failure (unsafe file, missing key, invalid value) returns `ErrUnusable` without file content. The caller owns and zeroes the token.
- `ValidNotifierCredentials`: token 1 to 4096 bytes; chat ID an optional `-` followed by ASCII digits, at most 64 bytes, no whitespace.
- Delivery needs no vault unlock or secret grant.
- Cancel and await the current run before closing its service.
- Reserve at most 30 attempts per monotonic hour; request IDs remain deduplicated for the Runner's lifetime. Seen request IDs are kept for 24 monotonic hours and capped at 1024 entries (oldest dropped first).
- An event that cancellation prevents from completing delivery (dequeued after cancellation, or a send cancelled in flight) releases its budget reservation and seen mark and is kept by the Runner; the next run delivers it first.
- Send plaintext metadata and approval links; keep values and credentials out of messages and audit errors.
- Bound HTTP calls to ten seconds, refuse redirects and cap response reads at 64 KiB.

# Work Guidance

- Tests use fake credentials and local HTTP servers.

# Verification

- `toolchain/run go test -race ./internal/notify/...`.
- `toolchain/run go test -race ./cmd/tokencrypt/...` checks env-file startup, locked delivery and shutdown.

# Child DOX Index

None.
