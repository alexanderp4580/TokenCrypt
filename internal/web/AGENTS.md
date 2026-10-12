# Purpose

Owns the embedded user website and its authentication boundary.

# Ownership

- `web.go`: `Handler(*core.Service, Config)` and `SetupHandler(dir, Config, onReady)`; login, logout, unlock and saved-grant confirmation routes.
- `session.go`: random browser sessions, pre-login sessions, idle expiry and cookies.
- `csrf.go`: bounded URL-encoded forms and session-bound CSRF checks.
- `templates/` and `static/`: embedded HTML and CSS. Pico v2.1.1 is vendored; `static/PICO-LICENSE.txt` contains its MIT license. `style.css` maps Pico to the dark palette and compact layout.
- `web_test.go`: real vault/core HTTP boundary tests using temporary files and fake credentials. `session_test.go` checks monotonic timestamp handling in session creation and refresh.

# Local Contracts

- `AllowedHosts` matches the complete Host header exactly, including a port when present. An empty list denies requests. Forwarded headers do not alter the allow-list or cookie policy.
- `SecureCookies` comes from deployment configuration. Session and pre-login cookies use `HttpOnly`, `SameSite=Strict` and path `/`.
- Sessions expire after `IdleTimeout` on wall or monotonic time; its default is 15 minutes. Store wall timestamps without a monotonic reading at creation and refresh, so wall expiry also covers device suspend. Login rotates the session and CSRF token; logout invalidates the session. The store caps authenticated and pre-login sessions together at 4096 and prunes expired entries when creating one.
- Only `/login` and static assets bypass authentication. State-changing forms use POST, a URL-encoded body and a `csrf` field bound to that browser session. Login and setup have separate pre-login sessions. Forms cap their bodies at 4 MiB and passphrases at 4096 bytes; tokens from query strings cannot authorize a form.
- Every response carries `Cache-Control: no-store`. Templates escape user text; responses omit secret values, passphrases, notifier credentials and underlying storage errors.
- Token expiry: create accepts `expiry_choice` and `expires_on`; authenticated POST `/secrets/expiry` edits metadata with CSRF and no extra passphrase. Edits require one explicit nonempty `expiry_choice`; missing, blank or repeated choices fail without a metadata write. Creation with no expiry fields defaults to Never. Choices: Never, 1/3 days, 1/2 weeks, 1/3/6 months, 1/2 years, Custom date. Presets use clamped calendar arithmetic; custom requires a valid civil date and permits past dates. Forms retain expiry inputs on errors and resolve presets server-side without JavaScript. `static/expiry.js` fills the date picker and supplies optional `expiry_today` from the viewer’s local calendar; list/edit countdowns use that calendar and treat the selected date as Expires today. Without JavaScript, presets and countdowns use the server calendar.
- Login calls `Verify`; unlock calls `Unlock`, displays only candidates and generic warnings, then passes `UnlockResult` to `OnUnlock`. The callback takes ownership of `NotifierToken` and must zero it when released; without a callback the handler zeroes it. The web server keeps candidate metadata only and never a master key.
- `/restore` requires a fresh passphrase and accepts only saved-grant IDs shown by that session's unlock step. Core revalidates the selected grants.
- `/notifier` keeps settings write-only, authenticated, CSRF-protected and passphrase-protected. POST invokes `OnNotifier` after core releases its operation lock, reconciling current service credentials even when an applied write reports a final fsync or audit failure. Unlock errors also reconcile independent settings after possible migration. Read-back grants no access; unchanged credentials preserve the current transport. Settings saved here are the fallback used when the daemon has no `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` environment; the environment takes precedence. The page displays configured, missing or unavailable state without credential values and explains private service storage and authenticated migration. `Config.EnvNotifier` adds a note that environment credentials override saved settings. Chat IDs must be numeric (`vault.ValidNotifierCredentials`).
- Setup requires matching passphrase and confirmation fields, uses `crypto.DefaultParams`, and calls `onReady` only after `vault.Init` succeeds. `InitParams` overrides the KDF parameters for controlled tests; production leaves it nil. Existing or concurrently initialized vaults return a conflict.

# Work Guidance

- Extend authenticated pages through the existing server boundary and escaped templates.
- Keep the dark Pico palette, compact forms, outlined buttons and phone layout.

# Verification

- `toolchain/run go test -race ./internal/web/...` covers authentication, expiry, CSRF, Host matching, throttling, body limits, bootstrap safety and grant recovery.
- `toolchain/check` checks formatting, vet and the full race-enabled Go suite.

# Child DOX Index

None.
