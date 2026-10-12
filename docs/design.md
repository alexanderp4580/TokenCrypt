# TokenCrypt design

Status: approved for autonomous implementation of Slices A–D; execution active. See [progress.md](progress.md). Items marked "to check" are unverified.

## Intent

- A local tool for sharing tokens and secrets between the user and a coding agent
- Secrets stay encrypted at rest. The agent can read a secret while a user grant lasts
- The user works in a website; the agent works in a CLI
- The user or the agent can flag a secret as leaked or as invalid/expired
- The tool cannot control what the agent does with a secret it has read

## Decisions

- Name: TokenCrypt; CLI and daemon binary: `tokencrypt`
- Stack: Go, one static binary holding daemon, CLI and embedded web UI; server-rendered HTML with minimal JS; builds use the pinned Go 1.27.2 Podman toolchain
- Hosting: local first. Web UI listens on `127.0.0.1`; a reverse proxy can serve it under a hostname and forward the `Host` header to the backend. TokenCrypt ignores forwarded identity headers.
- Grants default to 10 minutes and last at most 90 days. The grant form offers 10 minutes, 1 hour, 24 hours, 7 days, 30 days and 90 days. The user picks the duration; the agent's requested duration is a suggestion. Grants longer than 1 hour survive a daemon restart (see Grants)
- Each grant requires the passphrase
- The daemon runs continuously and serves the website; it has no idle exit
- Website writes (create, update, rename, set notifier) need the passphrase; protected values authenticate under vault keys
- Secret values are at most 1 MiB (proposal value). The value can be a token, a note or a message
- Secret names match `[a-z][a-z0-9_]{0,63}`. The environment variable for `run` is the name in upper case

## Components

- `tokencrypt serve`: daemon with vault, grant table, audit log, web UI, unix-socket API, Telegram notifier. One daemon per vault, enforced with a file lock
- `tokencrypt get|run|request|status|flag`: the agent CLI, talking to the unix socket
- Web UI: the place to create, update and delete secrets, set the notifier, grant, deny, revoke and clear flags

## Cryptography

```
passphrase --Argon2id(salt)--> KEK (32 bytes)
KEK  --AEAD--> wraps MK    (random 256-bit master key)
MK   --AEAD--> wraps DK_i  (random 256-bit data key, one per secret value)
DK_i --AEAD--> encrypts secret_i
```

- KDF: Argon2id, 256 MiB, 14 passes, 4 lanes, about one second on this device (benchmark in the toolchain container: 0.85 to 1.16 s per derivation; other devices differ). Salt: 16 random bytes
- AEAD: XChaCha20-Poly1305 with a fresh random 24-byte nonce per encryption with `golang.org/x/crypto` v0.58.0
- Key ID: 16 random bytes generated with each DK
- Associated data: format version, kind (`mk`, `dk`, `secret`, `notifier`), secret name and key ID, so ciphertexts cannot be swapped between names or roles. For `notifier` the name slot holds the chat ID and the key ID is the master key's, so an edited chat ID or a notifier file from another vault fails to open
- Encrypted notifier settings use `HKDF(MK, "tokencrypt notifier v1")` for authenticated migration. Independent service credentials use local file permissions outside vault encryption
- A wrong passphrase fails the AEAD tag when unwrapping MK
- Changing the passphrase re-wraps MK; no secret is re-encrypted. Files copied before the change still open with the old passphrase, so a leaked passphrase needs new secret values, not only a new passphrase
- KEK and MK exist for the length of one operation (grant, create, update, rename, set notifier, unlock, change passphrase), then the daemon zeroes them. Go's GC can copy buffers, so zeroing is best effort
- The daemon calls `prctl(PR_SET_DUMPABLE, 0)` so same-uid processes cannot attach with ptrace or read `/proc/<pid>/mem` (verified on this device); it tries `mlock` on page-isolated key and live-grant buffers, with lock/release outcomes checked in tests

## Vault layout

Under `~/.local/share/tokencrypt/`:

- `header.json`: version, KDF name and parameters, salt, wrapped MK
- `secrets/<name>.json`: version, name, key ID, wrapped DK, nonce, ciphertext. Immutable per value; an update writes a new file
- `meta.json`: plaintext state per secret: description, optional `expires_on` civil date, created, updated, last granted, flag. Names are not secret
- `grants.json`: records of grants longer than 1 hour (see Grants)
- `notifier.json`: encrypted notifier migration source; plaintext chat ID and bot token sealed under the notifier key
- `service/notifier.json`: independent Telegram bot token and chat ID, outside vault encryption; the daemon reads this service credential without keys or grants

Header and secret JSON files have a 2 MiB read/write limit, including the base64 encoding of a 1 MiB value. Metadata and grant records each have an 8 MiB limit; notifier JSON has a 64 KiB limit. Service credentials permit tokens up to 4096 bytes and chat IDs of up to 64 bytes that are an optional `-` followed by digits. Oversized reads fail with a generic diagnostic, and writes reject oversized output before changing the target.

Files are mode `0600`, directories `0700`. Service credential reads reject symlinks, nonregular files and wider permissions. Writes use a temporary file, file fsync, rename and directory fsync; a failure before rename leaves the prior file intact.

## Secret management (web UI)

- Create: name, description, value, optional token expiry; needs the passphrase
- Read: metadata only (name, description, token expiry, timestamps, last granted, flag state). An unreadable secret file appears by name with a corruption marker alongside healthy entries; reads and grants for it fail, and the user can delete it. Corrupt `meta.json` fails the whole list. No page or API response contains a value
- Update value: needs the passphrase; writes a new DK and file, revokes any live grant for that name, and clears the flag
- Update description: no passphrase. Create and description updates replace control, format and line-separator characters with spaces and truncate to 1 KiB of valid UTF-8
- Token expiry: optional YYYY-MM-DD date, with blank/missing meaning Never. The website offers Never, 1/3 days, 1/2 weeks, 1/3/6 months, 1/2 years and Custom date, with a visible date picker. Month/year presets clamp to the last valid day; custom dates may be in the past. Authenticated expiry edits need no extra passphrase and preserve values, encryption, flags, timestamps and grants. Value updates and renames preserve expiry. List/edit pages show a readable date and days left, Expires today or Expired in the viewer’s local calendar; the date remains valid through that day. Without JavaScript, forms resolve presets and display countdowns using the server calendar.
- Rename: needs the passphrase, because the name is part of the associated data; the daemon re-encrypts the file and revokes live grants
- Delete: needs the passphrase; removes the file and metadata, and revokes live grants. Copies in backups still open with the passphrase

## Flags

- A secret carries at most one flag: `leaked` (the user suspects compromise) or `invalid` (the service rejects the token, or it has expired)
- The user sets either flag from the web UI. The agent sets either with `flag NAME --kind leaked|invalid --reason TEXT`, for example after a service rejects a token
- Setting a flag revokes live grants for the secret, denies its pending requests, makes `get`, `run` and `request` fail with a message naming the flag and kind, writes an audit record (kind, actor, reason, time), and sends a Telegram notice
- Only the user clears a flag, through a new value (which clears it automatically) or an explicit "clear flag" action with the passphrase, which is audited
- The flag lives in `meta.json` as plaintext policy. A process with file access can edit it, so a cleared flag does not prove the user cleared it; the audit log and the UI show who last changed it
- A flagged secret can still be updated or deleted

## Grants

- A grant has: ID, secret name, key ID of the DK it covers, expiry, granted-by, optional request ID. The decrypted value lives in daemon memory only
- Granting needs the passphrase in the web form: derive KEK, unwrap MK, unwrap that secret's DK, decrypt, zero KEK and MK. It is refused for a flagged secret
- Other secrets stay locked while one is granted
- Short grants (1 hour or less) exist in memory only; a daemon restart drops them
- Long grants (over 1 hour, up to 90 days) are also recorded in `grants.json`: ID, name, key ID, expiry, granted-by and optional request ID, plus a MAC under `HKDF(MK, "tokencrypt grants v1")`. The file holds no values
- After a restart, long grants stay unusable until the user unlocks in the web UI with the passphrase. The daemon verifies each MAC, drops records that are expired, flagged, tampered, or whose key ID no longer matches the current value, lists the rest for the user to confirm, decrypts the confirmed ones into memory and zeroes MK. `get` before the unlock fails with a message that the daemon is locked
- Corrupt `grants.json` produces a warning after an authenticated unlock: the notifier loads, the daemon ends its locked state and restores no grants. The file stays intact; granting a long grant fails while it is corrupt. A fresh restore verification failure clears previous candidates.
- A long grant means the agent can read the value for that whole period; the UI shows the end date and warns for durations over 24 hours
- Expiry is checked against the wall clock at each use and by a timer. For grants of one day or less the daemon also tracks monotonic time and takes the earlier deadline, because monotonic time can stop while the device is suspended (to check on this device)
- Expiry and revoke zero the plaintext and remove the record from `grants.json`

## Agent CLI

- `get NAME`: prints the value while a grant is live; otherwise exits non-zero with a message. The output lands in the agent's own transcript, so `run` is preferred
- `run --with NAME[,NAME] -- CMD`: runs `CMD` with the values in environment variables (upper-case names); exits non-zero without a grant. Linux limits one environment string to 128 KiB including its name, equals sign and final NUL (measured on this device), so `run` fails with a message for a larger value; use `get`
- `request NAME --for DURATION --reason TEXT [--wait DURATION]`: creates a pending request; with `--wait` it blocks until approved, denied, expired or timed out
- `status`: lists secret names with metadata, token expiry (`token_expires_on`, date or Never), live grants (time left and `expires` timestamp), pending requests and flags; prints no values
- `flag NAME --kind leaked|invalid --reason TEXT`: sets the flag
- The CLI cannot create, update, rename, delete, unlock, grant, revoke or clear flags
- Socket: `$XDG_RUNTIME_DIR/tokencrypt/sock`, directory `0700`, socket `0600`; the daemon also checks the peer uid with `SO_PEERCRED`
- Requests: at most 10 pending, each expires after 10 minutes, at most one Telegram message per request and 30 per hour (proposal values). The reason is capped at 200 characters

## Web UI

- Styling: dark Pico theme, compact spacing, tables, forms and outlined buttons in a single-column phone layout.
- First visit to an uninitialized vault: choose and confirm a vault passphrase through a setup form with CSRF and Host checks; an existing vault cannot be initialized again. A plain-HTTP deployment starts with no stored secrets and uses approval links and cookies without the Secure flag.
- Login: passphrase check, then a random session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS) with an idle timeout
- CSRF token on every state-changing form; `Host` header allow-list against DNS rebinding
- Pages: secrets (create, update, rename, delete, set flag, clear flag; no value display), grant form (duration, passphrase), pending requests (approve with passphrase, deny), live grants with countdown and revoke, write-only notifier settings (bot token, chat ID, passphrase), audit log
- Agent-supplied text (reason, flag reason) is HTML-escaped
- Login throttling after repeated failures, counted per daemon rather than per address, because a reverse proxy presents every client as localhost

## Telegram

- `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in the `serve` environment configure the notifier at startup, need no unlock or website action and take precedence over service and vault settings. Values are trimmed, validated with the service credential limits, unset from the process environment after reading and never logged, audited or displayed. Only one set, or invalid values, writes a generic `notifier.failed` audit event and falls back to the settings below
- Without them, the user saves the bot token and chat ID on the authenticated notifier page with CSRF and a fresh passphrase check. The daemon stores both as private local service credentials and activates them on save
- On a new request the daemon sends a plain-text message (no markup parsing) with secret name, duration, reason and a link to the approval page; the message holds no value. A flag change sends a notice
- Approval needs the passphrase on the approval page; a Telegram tap grants nothing
- The daemon loads independent service credentials on cold startup and sends request and flag notices while the vault and saved grants stay locked. A notifier never reads a protected token or grants access
- A successful unlock migrates encrypted settings only when the service file is absent. Configured or corrupt service settings take precedence; corruption produces a generic diagnostic. The notifier page shows configured, missing or unavailable state
- Credential rotation cancels and awaits the prior transport, zeroes its token buffer and keeps the daemon-lifetime hourly budget and request deduplication state
- Logs and error messages contain no credentials

## Audit log

- JSON lines at `~/.local/state/tokencrypt/audit.log`
- Events: secret created/updated/renamed/deleted, flag set/cleared (with kind, actor and reason), request created/approved/denied/expired, grant started/ended/revoked/restored, login failure, notifier set, daemon unlocked
- Records contain no secret values, passphrases, notifier tokens or chat IDs
- Audit events have a 2 MiB encoded-line limit. The audit viewer reads the newest 2 MiB, drops a partial starting line, and shows valid events from that window

## Threat model

Protected:

- Stolen disk, backups, accidental commits, and any process or agent reading files without a grant
- Tampering with and swapping of vault files
- Offline guessing, bounded by passphrase strength (recommend a 6-word diceware passphrase)

Not protected:

- A secret that is granted and in daemon memory, beyond the dumpable and `mlock` hardening
- Output the agent prints after a grant
- An attacker holding both the passphrase and the vault
- Edits to `meta.json` and the audit log by a process with file access
- Reading or changing the independent notifier credential with local file access; vault encryption protects token values, while private file permissions protect this service credential
- Replay of an older `grants.json` that resurrects a revoked long grant after a restart; the restore step shows every restored grant for the user to confirm
- Old vault copies after a passphrase change or delete

## Acceptance criteria

- Protected vault ciphertext files contain no plaintext secret; notifier service credentials stay private and separate from secret grants
- With no grant, `get` and `run` fail; with a live grant, they return the value; after expiry or revoke, they fail again
- Granting one secret does not make another readable
- A wrong passphrase grants nothing and appears in the audit log
- A request from the CLI appears in the web UI and in Telegram with configured service credentials, including after a locked daemon restart; Deny makes `get` fail
- Create, update, rename and delete each need the passphrase; read shows metadata only
- Update value and rename revoke a live grant; the new value is what `get` returns after the next grant
- A flag (`leaked` or `invalid`) set from the CLI or the web UI revokes live grants, denies pending requests, blocks `get`, `run`, `request` and grant, and appears in the audit log with kind and actor
- The CLI cannot clear a flag; updating the value clears it
- A long grant survives a daemon restart only after the user unlocks; before that, `get` fails as locked. A tampered, expired, flagged or outdated record is not restored
- The grant form accepts durations up to 90 days and rejects longer ones
- No page or API response contains a stored value except the CLI socket response to `get`/`run` under a live grant
- Swapping two secret files makes both fail to decrypt
- The socket directory is `0700` and the socket `0600`; a connection from another uid is refused
- Names outside `[a-z][a-z0-9_]{0,63}` are rejected
- A value over 1 MiB is rejected; empty, multi-line and non-UTF-8 values round-trip unchanged
- More than 10 pending requests are refused; request reasons are escaped in the UI and sent as plain text
- A crash during a write leaves the previous file readable
- Tests cover the vault, grant expiry with a fake clock (including a wall-clock jump), the HTTP handlers, the flag rules, long-grant restore and MAC checks and socket permissions, using fake secrets and a fake Telegram transport

## Open items

- Production memory-lock behavior after user setup (automated key/grant lock checks pass)
- Grant expiry across device suspend
- Request limits and the 10-minute request expiry (proposal values)
- The 1-hour threshold for persisting grants (proposal value)
