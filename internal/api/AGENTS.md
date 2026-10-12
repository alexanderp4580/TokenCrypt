# Purpose

Owns the agent's JSON HTTP API over a Unix socket.

# Ownership

- `server.go`: `Serve`, private listener lifecycle, connection admission, handlers and redacted wire errors.
- `peer_linux.go`: kernel peer uid lookup through `SO_PEERCRED`.
- `client.go`: `Dial`, concurrent `Client`, its four operations and idle-connection cleanup through `Close`.
- `api_test.go`: real core/vault integration and socket boundary checks with fake credentials and values.

# Local Contracts

- `Serve(ctx, svc, socketPath)` binds a Unix socket and returns nil after cancellation. The socket parent must belong to the effective uid; path ancestors must be directories without symlinks. The server sets the parent to `0700` and the socket to `0600`.
- Hold a nonblocking exclusive directory `flock` from startup through socket cleanup. One API server owns that directory at a time. Reject an active socket, regular file, symlink or foreign-owned socket. Replace a same-owned socket only after `ECONNREFUSED` and an inode identity check. Shutdown removes its matching socket inode and preserves replacement paths.
- Check `SO_PEERCRED` on each accepted connection before HTTP processing; refuse uid mismatch or credential lookup failure. The injected check belongs to the internal server function for boundary tests.
- Routes: `POST /read` accepts `name`; `POST /request` accepts `name`, `reason`, `duration`, `wait`; `POST /flag` accepts `name`, `kind`, `reason`; `GET /status` accepts no operation body. Other paths return 404 and wrong methods return 405. The server supplies the actor `agent`.
- Request bodies must be JSON objects with the operation's fields; reject unknown fields, trailing JSON, negative waits and bodies over 8192 bytes. Durations use integer nanoseconds. Core enforces name, flag, duration and policy rules.
- Responses use a JSON envelope with `value` (base64 bytes), `request` (`core.Request`), `status` (`core.Status`) or `error` (`code`, optional flagged `name` and `kind`). Empty reads may omit `value`. Values appear through `/read` under a grant; the server zeroes its returned byte copy after writing.
- Status secret metadata includes `expires_on` as a civil-date string; blank means Never. Token expiry remains informational. The socket has no expiry mutation route.
- A request wait timeout returns the pending request and `context.DeadlineExceeded`; pending requests remain available to the user. Waits use the HTTP request context.
- Wire errors carry fixed codes, without raw errors or flag reasons. The client maps policy codes to core/vault sentinels and flagged name/kind to `core.FlaggedError`. Transport and malformed-response errors use package sentinels and omit paths and response text.
- Read headers and bodies within 5 seconds; close idle connections after 30 seconds. Set `MaxHeaderBytes` to 8192. The client limits responses to 32 MiB, verifies read values fit the vault limit and allows 10 seconds plus the requested wait for a response.

# Work Guidance

- Consume core policy methods; keep user-only mutations off the socket.
- Preserve arbitrary secret bytes through JSON base64 encoding.

# Verification

- `toolchain/run go test -race ./internal/api/...` checks socket permissions, same-uid admission and credential failure, route restrictions, bounded input, binary reads through 1 MiB, request outcomes, flag policy, redaction and socket lifecycle.
- `toolchain/check` runs formatting, vet and the repository race tests.

# Child DOX Index

None.
