# TokenCrypt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax. Workers write the implementation test-first; this plan holds contracts, assertions and commands only.

**Goal:** Build TokenCrypt: an encrypted local secret vault with a web UI for the user, a CLI for the agent, timed grants, flags and Telegram approval requests.

**Architecture:** One Go binary `tokencrypt` holds a daemon (`serve`), the agent CLI and an embedded server-rendered web UI. The `core` package owns all rules; the web UI and the unix-socket API are thin callers of it. The `vault` package owns encryption and files.

**Tech Stack:** Go (version pinned in Task 1), `golang.org/x/crypto` (Argon2id, XChaCha20-Poly1305, HKDF; to check), standard library `net/http`, `html/template`, `embed`; Podman for the pinned toolchain.

**Spec:** [design.md](design.md). Executors read both documents.

## Global Constraints

- Argon2id KDF, 256 MiB, 14 passes, 4 lanes (minimum 3 passes), about one second on this device; salt 16 random bytes
- XChaCha20-Poly1305, fresh random 24-byte nonce per encryption; key ID is 16 random bytes generated with each DK
- Associated data: format version, kind (`mk`, `dk`, `secret`), secret name and key ID
- Secret names match `[a-z][a-z0-9_]{0,63}`; `run` uses the upper-case name as the environment variable
- Secret values are at most 1 MiB (proposal value)
- Grants default to 10 minutes and last at most 90 days; the form offers 10 minutes, 1 hour, 24 hours, 7 days, 30 days, 90 days
- Grants of 1 hour or less live in memory only; longer grants are recorded in `grants.json` with a MAC under `HKDF(MK, "tokencrypt grants v1")`
- Notifier credentials: one env file (`serve --env-file`, default `$XDG_CONFIG_HOME/tokencrypt/telegram.env`) read once at startup; regular file owned by the daemon user, mode `0600` or stricter; token cap 4096 bytes, numeric chat ID cap 64 bytes, file cap 64 KiB
- Files are mode `0600`, directories `0700`; every write is temp file, flush, rename
- Socket: `$XDG_RUNTIME_DIR/tokencrypt/sock`, directory `0700`, socket `0600`, peer uid checked with `SO_PEERCRED`
- Login and passphrase throttle: 5 consecutive failures lock all passphrase attempts for 5 minutes (proposal values)
- Requests: at most 10 pending, expire after 10 minutes, at most one Telegram message per request and 30 per hour (proposal values); reason capped at 200 characters
- Web UI binds `127.0.0.1`; session cookie `HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS; CSRF token on every state-changing form; `Host` header allow-list; login throttle counted per daemon
- Passphrase required for: create, update value, rename, delete, grant, approve request, clear flag, unlock
- Agent CLI commands: `get`, `run`, `request`, `status`, `flag`; the CLI cannot create, update, rename, delete, unlock, grant, revoke or clear flags
- Audit log: JSON lines at `~/.local/state/tokencrypt/audit.log`; no values, no passphrases
- Vault directory `~/.local/share/tokencrypt/`; tests use temporary directories and fake secrets only
- No tombstones in docs, comments or commits; no co-author trailers; available agents suited to scoped implementation and independent review

## Review Focus

1. Values at the edges: empty, multi-line, non-UTF-8, exactly 1 MiB and 1 MiB + 1 round-trip or reject as specified through `get` and `run` (Task 3, Task 9)
2. Names that look like paths or collide: `../x`, `a/b`, `A`, `a-b`, empty, 65 characters are rejected everywhere a name enters (Task 3, Task 8, Task 12)
3. Revoke or expiry racing a read: after a flag, revoke or expiry returns, no `get` returns the value, run under `-race` (Task 6, Task 7)
4. Crash or restart in the middle of a write or with long grants present: the vault stays readable, short grants vanish, long grants wait for unlock (Task 3, Task 6, Task 10)
5. Agent-supplied text with HTML, ANSI escapes or newlines in `reason` shows inert in the UI, `status` output and Telegram (Task 9, Task 12, Task 13)

## Progress

Slices A–D are merged to `main`. See [progress.md](progress.md) for deployment and review state and [evidence.md](evidence.md) for observed checks. The notifier reads credentials from the env file at startup.

## Workspace and slices

- Work on `main`. See [progress.md](progress.md) before resuming or integrating.
- Slices A–D are authorized for autonomous implementation and local deployment. The user checked the integrated website before the merge to `main`.
- Slice A: Tasks 1–7 (toolchain, crypto, vault, audit, grants, core). Headless, fully tested by Go tests
- Slice B: Tasks 8–10 (socket API, CLI, daemon)
- Slice C: Tasks 11–12 (web UI)
- Slice D: Tasks 13–14 (Telegram, end-to-end check, evidence)
- Finish and verify Slice A before starting B and C. B and C can run in parallel on separate branches against the stable `core.Service` interface; C produces `web.Handler`, and B accepts it through `daemon.Config.Web`. Coordinate final wiring in `cmd/tokencrypt/main.go` during integration.

## File structure

- `go.mod`, `go.sum`: module `tokencrypt`
- `cmd/tokencrypt/main.go`: subcommand dispatch only; `cmd/AGENTS.md`
- `internal/crypto/`: KDF, AEAD, HKDF, MAC, zeroing
- `internal/vault/`: files, secrets CRUD, metadata, flags, sessions holding MK
- `internal/audit/`: append-only JSON-lines log
- `internal/clock/`: `Clock` interface, real and fake clocks
- `internal/grants/`: grant table, expiry, `grants.json` persistence and restore
- `internal/core/`: the service: grants, requests, flags, throttle, events
- `internal/api/`: socket server, client, peer check
- `internal/cli/`: agent commands
- `internal/daemon/`: wiring, hardening, file lock, unlock flow
- `internal/web/`: handlers, templates, static assets, sessions, CSRF
- `internal/notify/`: env-file credentials, Telegram transport and notifier
- `internal/AGENTS.md`: ownership of the packages above
- `toolchain/`: `Containerfile`, `versions.env`, `run`, `check`; `toolchain/AGENTS.md`
- `scripts/e2e.sh`: end-to-end check from Task 14

## Task 1: Toolchain and module scaffold

**Files:**
- Create: `toolchain/Containerfile`, `toolchain/versions.env`, `toolchain/run`, `toolchain/check`, `toolchain/AGENTS.md`, `go.mod`, `cmd/tokencrypt/main.go`, `cmd/AGENTS.md`, `internal/AGENTS.md`, `internal/clock/clock.go`, `internal/clock/clock_test.go`
- Modify: `AGENTS.md` (Child DOX Index), `README.md`

**Interfaces:**
- Produces: `clock.Clock` with `Wall() time.Time` and `Mono() time.Duration`; `clock.Real{}`; `clock.Fake` with `SetWall(time.Time)`, `AdvanceWall(d)`, `AdvanceMono(d)` so tests can jump wall time and monotonic time separately
- Produces: `toolchain/run CMD...` runs a command in the pinned Go container with the worktree mounted at `/workspace` and a module cache under ignored `.local/`; `toolchain/check` runs `gofmt -l`, `go vet ./...` and `go test -race ./...`

- [x] **Step 1:** Check the current stable Go release and the `golang.org/x/crypto` version against primary sources (go.dev, pkg.go.dev); pin the Go base image by digest in `versions.env`. Record both versions in `toolchain/AGENTS.md`
- [x] **Step 2:** Write `clock_test.go`: `Fake.AdvanceMono(5m)` moves `Mono()` by 5m and leaves `Wall()` unchanged; `SetWall` moves `Wall()` and leaves `Mono()`; `Real` returns non-decreasing `Mono()`
- [x] **Step 3:** Run `toolchain/run go test ./internal/clock/...`. Expected: FAIL (package has no implementation)
- [x] **Step 4:** Build the image, implement `clock`, add the `main.go` stub printing usage for no arguments (exit 2)
- [x] **Step 5:** Run `toolchain/run go version`. Expected: prints the pinned version
- [x] **Step 6:** Run `toolchain/check`. Expected: exit 0, `ok  tokencrypt/internal/clock`
- [x] **Step 7:** Write the three AGENTS.md files per the DOX child-doc shape and update the root index. Commit: `Add Go toolchain and module scaffold`

## Task 2: Crypto primitives

**Files:**
- Create: `internal/crypto/crypto.go`, `internal/crypto/crypto_test.go`

**Interfaces:**
- Produces: `type Params struct{ Time uint32; MemoryKiB uint32; Threads uint8 }`; `DefaultParams() Params`
- Produces: `DeriveKEK(passphrase, salt []byte, p Params) ([]byte, error)`; `NewKey() ([]byte, error)` (32 random bytes); `NewID() ([]byte, error)` (16 random bytes); `NewSalt() ([]byte, error)` (16 bytes)
- Produces: `Seal(key, plaintext, aad []byte) ([]byte, error)` returning nonce‖ciphertext; `Open(key, blob, aad []byte) ([]byte, error)`; `ErrAuth`
- Produces: `AAD(version int, kind, name string, keyID []byte) []byte`
- Produces: `HKDF(key []byte, label string) ([]byte, error)`; `MAC(key, msg []byte) []byte`; `VerifyMAC(key, msg, mac []byte) bool`; `Zero(b []byte)`

- [x] **Step 1:** Write tests: Seal/Open round-trip for empty, 1-byte and 1 MiB plaintexts; Open with a wrong key, wrong AAD (each AAD field changed in turn) or a flipped ciphertext bit returns `ErrAuth`; two Seals of the same input differ; `DeriveKEK` is deterministic for equal inputs and differs for a different passphrase or salt; `HKDF` with different labels yields different keys; `VerifyMAC` rejects a changed message; `Zero` sets every byte to 0; `NewKey` outputs differ between calls
- [x] **Step 2:** Run `toolchain/run go test ./internal/crypto/...`. Expected: FAIL
- [x] **Step 3:** Implement. Tests use small KDF params (`Params{Time:1, MemoryKiB:64, Threads:1}`) for speed; `DefaultParams` holds the Global Constraints values
- [x] **Step 4:** Run the same command. Expected: PASS
- [x] **Step 5:** Add `BenchmarkDeriveKEK` with `DefaultParams`; run `toolchain/run go test -bench DeriveKEK -run '^$' ./internal/crypto/`. Record the time per operation in the task report, and adjust `DefaultParams` so it takes about one second on this device
- [x] **Step 6:** Commit: `Add crypto primitives`

## Task 3: Vault storage and secret CRUD

**Files:**
- Create: `internal/vault/vault.go`, `internal/vault/files.go`, `internal/vault/vault_test.go`

**Interfaces:**
- Consumes: Task 2 `crypto`
- Produces: `Init(dir string, passphrase []byte, p crypto.Params) error`; `Open(dir string) (*Vault, error)`; `(*Vault).Unlock(passphrase []byte) (*Session, error)`; `(*Session).Close()` (zeroes MK)
- Produces on `*Session`: `Create(name, description string, value []byte) error`; `UpdateValue(name string, value []byte) error`; `Rename(oldName, newName string) error`; `Delete(name string) error`; `Reveal(name string) (value []byte, keyID []byte, err error)`; `DeriveKey(label string) ([]byte, error)`; `ChangePassphrase(newPassphrase []byte) error`
- Produces: `ValidName(string) bool`; `MaxValueBytes = 1 << 20`; errors `ErrWrongPassphrase`, `ErrNotFound`, `ErrExists`, `ErrBadName`, `ErrTooLarge`
- Produces: `(*Vault).Exists(name string) bool`; `(*Vault).KeyID(name string) ([]byte, error)`

- [x] **Step 1:** Write tests (temporary directory, small KDF params, fake values):
  - Init then Unlock with the right passphrase succeeds; a wrong one returns `ErrWrongPassphrase` and no session
  - Create then Reveal returns the value; round-trips empty, multi-line, non-UTF-8 and exactly 1 MiB values; 1 MiB + 1 returns `ErrTooLarge`
  - Names `../x`, `a/b`, `A`, `a-b`, empty and 65 characters return `ErrBadName`; creating an existing name returns `ErrExists`
  - Raw bytes of every file in the vault directory contain neither the canary value nor the passphrase
  - UpdateValue changes the key ID and the value; the old file content no longer opens
  - Rename keeps the value, removes the old name, and fails Reveal under the old name
  - Delete removes the file; Reveal returns `ErrNotFound`
  - Swapping the ciphertext files of two secrets makes Reveal fail for both
  - ChangePassphrase: the new passphrase unlocks, the old one fails, and a secret created before still reveals
  - Files are `0600` and directories `0700`
  - Crash safety: with a write hook that fails after the temp file is written and before the rename, the previous file is still readable and no partial target exists
- [x] **Step 2:** Run `toolchain/run go test ./internal/vault/...`. Expected: FAIL
- [x] **Step 3:** Implement with the vault layout from the spec (`header.json`, `secrets/<name>.json`); the AAD of each ciphertext includes version, kind, name and key ID; writes go through one atomic-write helper
- [x] **Step 4:** Run the same command with `-race`. Expected: PASS
- [x] **Step 5:** Commit: `Add vault storage and secret CRUD`

## Task 4: Vault metadata and flags

**Files:**
- Create: `internal/vault/meta.go`, `internal/vault/meta_test.go`
- Modify: `internal/vault/vault.go` (delete and rename update metadata)

**Interfaces:**
- Consumes: Task 3 `Vault`, `Session`
- Produces: `type Flag struct{ Kind string; Actor string; Reason string; At time.Time }` with kinds `leaked` and `invalid`
- Produces: `type Meta struct{ Name, Description string; Created, Updated, LastGranted time.Time; Flag *Flag; KeyID []byte; Corrupt bool }`
- Produces on `*Vault` (no passphrase): `List() ([]Meta, error)`; `Get(name string) (Meta, error)`; `SetDescription(name, description string) error`; `SetFlag(name string, f Flag) error`; `ClearFlag(name string) error`; `TouchGranted(name string, at time.Time) error`
- Behavior: UpdateValue clears the flag; Rename moves metadata; Delete removes it. `List` marks unreadable secret files with `Meta{Name, Corrupt: true}` alongside healthy entries; `Get` fails for those files. Whole-file metadata corruption fails the list. Header/secret JSON have 2 MiB read/write caps; metadata 8 MiB. Writes reject oversized output before changing the target; reads return `ErrCorrupt`

- [x] **Step 1:** Write tests: Create fills Created and Updated; `List` returns metadata sorted by name and never contains a value; SetFlag with kind `leaked` or `invalid` shows in `Get`; an unknown kind returns an error; UpdateValue clears the flag; ClearFlag removes it; Rename and Delete carry metadata with them; SetDescription changes only the description; `meta.json` is written atomically
- [x] **Step 2:** Run `toolchain/run go test ./internal/vault/...`. Expected: FAIL on the new tests
- [x] **Step 3:** Implement
- [x] **Step 4:** Run with `-race`. Expected: PASS
- [x] **Step 5:** Commit: `Add vault metadata, flags and notifier storage`

## Task 5: Audit log

**Files:**
- Create: `internal/audit/audit.go`, `internal/audit/audit_test.go`

**Interfaces:**
- Consumes: `clock.Clock`
- Produces: `type Event struct{ Time time.Time; Type string; Actor string; Secret string; Detail string }`
- Produces: `Open(path string, clk clock.Clock) (*Log, error)`; `(*Log).Write(e Event) error` (sets `Time` from the clock when zero); `(*Log).Tail(n int) ([]Event, error)`
- Event types: `secret.created`, `secret.updated`, `secret.renamed`, `secret.deleted`, `flag.set`, `flag.cleared`, `request.created`, `request.approved`, `request.denied`, `request.expired`, `grant.started`, `grant.ended`, `grant.revoked`, `grant.restored`, `login.failed`, `notifier.failed`, `notifier.dropped`, `daemon.unlocked`

- [x] **Step 1:** Write tests: Write then Tail returns events in order; each line is valid JSON; Tail(n) returns the last n; the file is `0600` and its directory `0700`; concurrent Writes from 20 goroutines produce 20 intact lines under `-race`; reopening appends instead of truncating; `Detail` containing newlines stays on one line (JSON-escaped)
- [x] **Step 2:** Run `toolchain/run go test ./internal/audit/...`. Expected: FAIL
- [x] **Step 3:** Implement
- [x] **Step 4:** Run with `-race`. Expected: PASS
- [x] **Step 5:** Commit: `Add audit log`

## Task 6: Grants manager

**Files:**
- Create: `internal/grants/grants.go`, `internal/grants/persist.go`, `internal/grants/grants_test.go`

**Interfaces:**
- Consumes: `clock.Clock`; `vault.Meta` flag and key ID checks via a small `Checker` interface the manager receives
- Produces: `type Grant struct{ ID, Secret string; KeyID []byte; Expires time.Time; GrantedBy, RequestID string }`
- Produces: `type Checker interface{ Flagged(name string) bool; KeyID(name string) ([]byte, error) }`
- Produces: `New(clk clock.Clock, dir string, chk Checker) *Manager`
- Produces: `(*Manager).Add(g Grant, value []byte, macKey []byte) error` (records in `grants.json` when the duration exceeds 1 hour)
- Produces: `(*Manager).Read(name string) (value []byte, g Grant, err error)`; errors `ErrNoGrant`, `ErrLocked`
- Produces: `(*Manager).Revoke(id string) error`; `RevokeSecret(name string) int`; `List() []Grant`
- Produces: `(*Manager).Candidates(macKey []byte) ([]Grant, error)` (verified, unexpired, unflagged, current key ID); `Restore(ids []string, reveal func(name string) ([]byte, error)) error`; `SetLocked(bool)`

- [x] **Step 1:** Write tests with `clock.Fake`:
  - Add then Read returns the value until `Expires`; at `Expires` it returns `ErrNoGrant` and the stored buffer is zeroed
  - A wall-clock jump forward past `Expires` expires the grant even if monotonic time did not advance; monotonic time advancing past the duration expires it even if wall time did not (earlier deadline wins) for grants of 24 hours or less
  - `Revoke` and `RevokeSecret` remove grants and zero values; `RevokeSecret` returns the count
  - A grant for one secret never returns another secret's value
  - Grants of 1 hour or less leave no `grants.json` entry; longer grants do, and the file contains no value
  - A new Manager on the same directory starts empty and locked: `Read` returns `ErrLocked` until `Restore`
  - `Candidates` drops: expired records, flagged secrets, records whose key ID no longer matches, records with a bad MAC (flip a byte), records with a changed expiry
  - `Restore` loads only the confirmed IDs and `Read` then returns the value
  - Revoke and expiry remove the record from `grants.json`
  - 50 goroutines calling `Read` while another calls `Revoke` and `Advance`: under `-race`, no `Read` returns a value after `Revoke` has returned
- [x] **Step 2:** Run `toolchain/run go test -race ./internal/grants/...`. Expected: FAIL
- [x] **Step 3:** Implement; expiry runs on a timer owned by the Manager and is also checked on each `Read`
- [x] **Step 4:** Run the same command. Expected: PASS
- [x] **Step 5:** Commit: `Add grants manager with long-grant persistence`

## Task 7: Core service

**Files:**
- Create: `internal/core/core.go`, `internal/core/requests.go`, `internal/core/throttle.go`, `internal/core/core_test.go`

**Interfaces:**
- Consumes: Tasks 3–6
- Produces: `New(v *vault.Vault, g *grants.Manager, a *audit.Log, clk clock.Clock, cfg Config) *Service` with `Config{MaxPending int; RequestTTL time.Duration; MaxGrant time.Duration; DefaultGrant time.Duration; MaxFailures int; Lockout time.Duration}` and `DefaultConfig()` holding the Global Constraints values
- Produces passphrase operations: `Create(name, desc string, value, pass []byte, actor string) error`; `UpdateValue(name string, value, pass []byte, actor string) error`; `Rename(old, new string, pass []byte, actor string) error`; `Delete(name string, pass []byte, actor string) error`; `Grant(name string, d time.Duration, pass []byte, actor, requestID string) (grants.Grant, error)`; `ClearFlag(name string, pass []byte, actor string) error`; `Unlock(pass []byte) (UnlockResult, error)` where `UnlockResult{GrantsErr error; Candidates []grants.Grant}`; `RestoreGrants(pass []byte, ids []string) (int, error)` restores only confirmed candidates after a fresh passphrase check
- Produces agent operations: `Read(name string) ([]byte, error)` (touches last granted); `Request(name, reason string, d time.Duration) (Request, error)`; `Wait(ctx context.Context, id string) (Request, error)`; `Flag(name, kind, reason, actor string) error`; `Status() Status`
- Produces user operations: `Verify(pass []byte) error` (login check; counts toward the throttle); `Deny(id, actor string) error`; `SetDescription(name, description string) error` (no passphrase); `Revoke(id, actor string) error`; `AuditTail(n int) ([]audit.Event, error)`; `LogNotifierEvent(typ, detail string) error` (only `notifier.` types); approving a request is `Grant` with its request ID
- Produces: `type Status struct{ Secrets []vault.Meta; Grants []grants.Grant; Pending []Request; Locked bool; Error string }`
- Produces: `type Request struct{ ID, Secret, Reason string; Duration time.Duration; Created time.Time; State string }` with states `pending`, `approved`, `denied`, `expired`
- Produces: `Events() <-chan Event` with `Event{Kind, Secret, RequestID, Actor, FlagKind, Reason string; Duration time.Duration}` for kinds `request.created` and `flag.set`
- Recovery: corrupt grants storage yields a generic `UnlockResult.GrantsErr`, ends both locked states and restores no values. `RestoreGrants` clears stale candidates and returns a generic `grants.ErrCorrupt` warning while ending both locked states. The file stays intact and long grants fail closed; grant JSON reads and writes have an 8 MiB cap.
- Text and audit limits: Create and SetDescription clean control, format and line-separator characters and truncate at 1 KiB of valid UTF-8 bytes. AuditTail reads the newest 2 MiB, discarding a partial starting line; audit writes reject encoded lines over 2 MiB.
- Errors: `ErrThrottled`, `ErrFlagged` (carries kind and reason), `ErrTooManyPending`, `ErrDurationTooLong`, `ErrNotFound`

- [x] **Step 1:** Write tests (real vault in a temporary directory with small KDF params, `clock.Fake`, canary values):
  - Every passphrase operation with a wrong passphrase fails, changes nothing, writes `login.failed` and counts toward the throttle; after 5 consecutive failures the next attempt returns `ErrThrottled` regardless of correctness until the fake clock passes the lockout
  - `Grant` then `Read` returns the value; `Read` without a grant fails; `Grant` for a flagged secret returns `ErrFlagged`; a duration over 90 days returns `ErrDurationTooLong`
  - `UpdateValue`, `Rename` and `Delete` revoke live grants for the secret
  - `Flag` (kind `leaked` or `invalid`) revokes live grants, moves the secret's pending requests to `denied`, makes `Read`, `Request` and `Grant` return `ErrFlagged`, writes `flag.set` with actor and reason, and emits an event; an unknown kind is rejected
  - `ClearFlag` needs the passphrase; `UpdateValue` clears the flag
  - `Request` creates a pending request and emits an event; the 11th pending request returns `ErrTooManyPending`; a request expires after 10 minutes of fake time; `Wait` returns when approved, denied or expired and honors context cancellation
  - `Grant` with a request ID marks it `approved`; `Deny` marks it `denied`; the agent's requested duration is only a default for the form
  - A reason over 200 characters is truncated; control characters in a reason are replaced with spaces
  - Granting one secret leaves another unreadable
  - `Unlock` after constructing a new `Service` on a vault with a long grant returns saved-grant candidates and restores confirmed grants only; before `Unlock`, `Read` returns a locked error
  - Audit entries for all operations contain no canary value and no passphrase
  - Under `-race`: concurrent `Grant`, `Read`, `Flag` and `Revoke` calls leave no readable value after `Flag` returns
- [x] **Step 2:** Run `toolchain/run go test -race ./internal/core/...`. Expected: FAIL
- [x] **Step 3:** Implement. Passphrase operations unlock a vault session, perform the action, then close the session
- [x] **Step 4:** Run the same command, then `toolchain/check`. Expected: PASS, exit 0
- [x] **Step 5:** Commit: `Add core service`

**Slice A ends here.** Run a whole-slice review (spec, plan, diff range, observed check output), fix Critical and Important findings, then proceed to B and C.

## Task 8: Socket API

**Files:**
- Create: `internal/api/server.go`, `internal/api/client.go`, `internal/api/peer_linux.go`, `internal/api/api_test.go`

**Interfaces:**
- Consumes: `core.Service`
- Produces: `Serve(ctx context.Context, svc *core.Service, socketPath string) error`; `type Client`, `Dial(socketPath string) (*Client, error)`
- Produces on `*Client`: `Read(name string) ([]byte, error)`; `Request(name, reason string, d time.Duration, wait time.Duration) (core.Request, error)`; `Flag(name, kind, reason string) error`; `Status() (core.Status, error)`
- The wire format is JSON over HTTP on the unix socket; only these four operations exist

- [x] **Step 1:** Write tests: the socket directory is `0700` and the socket `0600` after `Serve` starts; a client with the right uid reads a granted value; a request from a fake peer with another uid is refused (peer check function injected); an unknown route returns 404; there is no route for create, update, delete, grant or clear flag (each attempted path returns 404); a stale socket file from a crashed run is replaced; context cancellation removes the socket
- [x] **Step 2:** Run `toolchain/run go test -race ./internal/api/...`. Expected: FAIL
- [x] **Step 3:** Implement with `SO_PEERCRED` in `peer_linux.go`
- [x] **Step 4:** Run the same command. Expected: PASS
- [x] **Step 5:** Commit: `Add socket API`

## Task 9: Agent CLI

**Files:**
- Create: `internal/cli/cli.go`, `internal/cli/cli_test.go`
- Modify: `cmd/tokencrypt/main.go`

**Interfaces:**
- Consumes: `api.Client`
- Produces: `Run(args []string, stdout, stderr io.Writer, dial func() (*api.Client, error)) int` returning exit codes (0 success, 1 operation failed, 2 usage)
- Commands: `get NAME`; `run --with NAME[,NAME] -- CMD...`; `request NAME --for DURATION --reason TEXT [--wait DURATION]`; `status`; `flag NAME --kind leaked|invalid --reason TEXT`; `serve` is dispatched by `main.go` to the daemon

- [ ] **Step 1:** Write tests with a fake API server: `get` prints the value and exits 0; without a grant it exits 1 with a message and prints nothing on stdout; `get` preserves empty, multi-line and non-UTF-8 values byte for byte; `run` starts a child whose environment contains `GITHUB_TOKEN` for secret `github_token` and exits with the child's exit code; `run` with two names sets both and fails before starting the child when one lacks a grant; `run` with a value over the environment-string limit (about 128 KiB, to check on this device) exits 1 with a message naming `get`, and `get` returns a 1 MiB value intact; `status` output contains no value and escapes control characters and ANSI sequences in reasons; `request --wait` returns the final state; `flag` rejects a kind other than `leaked` or `invalid`; bad names exit 2; no subcommand exists for create, update, delete, grant, unlock or clear
- [ ] **Step 2:** Run `toolchain/run go test -race ./internal/cli/...`. Expected: FAIL
- [ ] **Step 3:** Implement
- [ ] **Step 4:** Run the same command. Expected: PASS
- [ ] **Step 5:** Commit: `Add agent CLI`

## Task 10: Daemon

**Files:**
- Create: `internal/daemon/daemon.go`, `internal/daemon/harden_linux.go`, `internal/daemon/daemon_test.go`
- Modify: `cmd/tokencrypt/main.go` (`serve`, `init`)

**Interfaces:**
- Consumes: Tasks 3–9; the web handler (Task 11) is attached later through `Config.Web http.Handler`
- Produces: `Run(ctx context.Context, cfg Config) error` with `Config{VaultDir, StateDir, SocketPath, Listen string; Web http.Handler; Clock clock.Clock}`; `tokencrypt init` creates a vault from a passphrase read twice on the terminal; `tokencrypt serve` runs the daemon
- Produces: file lock on `<VaultDir>/lock` (a second daemon fails with a clear error); `Harden()` calling `prctl(PR_SET_DUMPABLE, 0)` and best-effort `mlock`

- [ ] **Step 1:** Write tests: a second `Run` on the same directory returns the lock error; `Run` creates the socket and, when `Web` is set, serves it on `Listen`; cancelling the context shuts both down and removes the socket; after a restart with a long grant on disk, `Read` through the socket fails as locked; `Harden` reports whether dumpable is 0 (read `/proc/self/status` or `prctl(PR_GET_DUMPABLE)`)
- [ ] **Step 2:** Run `toolchain/run go test -race ./internal/daemon/...`. Expected: FAIL
- [ ] **Step 3:** Implement
- [ ] **Step 4:** Run the same command, then `toolchain/check`. Expected: PASS, exit 0
- [ ] **Step 5:** Manual checks on this device, recorded in `docs/evidence.md` as passed, failed or not run:
  - after `Harden()`, a second process of the same uid cannot read `/proc/<daemon pid>/mem` and `strace -p` fails (to check)
  - `mlock` result and any `RLIMIT_MEMLOCK` limit
  - a grant of 1 minute across a device suspend and resume expires on time (to check; skip with a reason if suspend is not practical)
- [ ] **Step 6:** Commit: `Add daemon with hardening and file lock`

**Slice B ends here.** Whole-slice review, then integration on the development branch.

## Task 11: Web server, login and sessions

**Files:**
- Create: `internal/web/web.go`, `internal/web/session.go`, `internal/web/csrf.go`, `internal/web/web_test.go`, `internal/web/templates/layout.html`, `internal/web/templates/login.html`

**Interfaces:**
- Consumes: `core.Service`
- Produces: `Handler(svc *core.Service, cfg Config) http.Handler` with `Config{AllowedHosts []string; SecureCookies bool; IdleTimeout time.Duration; Clock clock.Clock; InitParams *crypto.Params}`
- Behavior: every route except `/login` and static assets needs a session; state-changing methods need a valid CSRF token

- [x] **Step 1:** Write tests with `httptest`: unauthenticated GET of `/` redirects to `/login`; a wrong passphrase returns the login page, sets no cookie and counts toward the throttle; the right passphrase sets a cookie with `HttpOnly`, `SameSite=Strict`, and `Secure` when configured; the session expires after the idle timeout of fake time; a POST without a CSRF token or with another session's token returns 403; a request with a `Host` header outside the allow-list returns 403; after 5 failures the login returns 429 even for the right passphrase; logout invalidates the session; responses carry `Cache-Control: no-store`
- [x] **Step 2:** Run `toolchain/run go test -race ./internal/web/...`. Expected: FAIL
- [x] **Step 3:** Implement
- [x] **Step 4:** Run the same command. Expected: PASS
- [x] **Step 5:** Commit: `Add web login, sessions and CSRF`

## Task 12: Web pages

**Files:**
- Create: `internal/web/secrets.go`, `internal/web/grants.go`, `internal/web/requests.go`, `internal/web/audit.go`, `internal/web/pages_test.go`, one template per page under `internal/web/templates/`, `internal/web/static/app.css`
- Modify: `internal/web/web.go` (routes)

**Interfaces:**
- Consumes: Task 11 handler and session; `core.Service`
- Pages: secrets list with create, update value, rename, delete, set flag and clear flag forms; grant form with the six duration choices; pending requests with approve (passphrase and duration) and deny; live grants with countdown and revoke; unlock page after a restart showing restorable grants for confirmation; audit log
- Every action has a visible button; the layout works on a phone screen (single column)
- Follow the styling in [design.md#web-ui](design.md#web-ui). Check the rendered desktop and phone pages during the Slice C manual review.

- [ ] **Step 1:** Write tests with `httptest` and a logged-in session: the secrets page lists names and flags and never contains a canary value, including after create and update; create with a wrong passphrase shows an error and creates nothing; a 1 MiB multi-line note posted through the create form is stored intact and a larger one is rejected with a message (the form body limit sits above 1 MiB); grant form offers exactly the six durations; granting 91 days is rejected; a flagged secret's grant button is replaced by its flag state and a clear-flag form; a request reason with `<script>` and ANSI escapes renders escaped; approve with the right passphrase creates the grant and marks the request approved; deny marks it denied; the unlock page lists restorable long grants and restores only the checked ones; names `../x` and `A` are rejected by every form; the audit page shows flag kind and actor; every state-changing form includes a CSRF field
- [ ] **Step 2:** Run `toolchain/run go test -race ./internal/web/...`. Expected: FAIL on the new tests
- [ ] **Step 3:** Implement
- [ ] **Step 4:** Run the same command, then `toolchain/check`. Expected: PASS, exit 0
- [ ] **Step 5:** Commit: `Add web pages`

**Slice C ends here.** Whole-slice review, then integration on the development branch. Record desktop and phone checks in `docs/evidence.md`; the user checks the final website after D.

## Task 13: Telegram notifier

**Files:**
- Create: `internal/notify/notify.go`, `internal/notify/telegram.go`, `internal/notify/credentials.go`, `internal/notify/notify_test.go`, `internal/notify/credentials_test.go`
- Modify: `cmd/tokencrypt/runtime.go` (read the env file once at startup and start the notifier)

**Interfaces:**
- Consumes: `core.Service.Events()`
- Produces: `type Transport interface{ Send(chatID, text string) error }`; `NewTelegram(token string, client *http.Client, baseURL string) Transport`; `Start(ctx context.Context, svc *core.Service, t Transport, chatID, approvalBaseURL string, clk clock.Clock)`

- [ ] **Step 1:** Write tests with a fake transport and a fake HTTP server: a new request sends one plain-text message with secret name, duration, reason and an approval link, and no value; a flag event sends a notice naming kind and actor; the 31st message within one hour is dropped and audited; the transport call uses no markup parse mode; reasons with newlines and markup characters appear unparsed; a transport error is logged without the token or chat ID in the message; an env file with valid credentials delivers notices from a locked startup while protected reads fail; unsafe, partial or invalid files leave the notifier off with one generic audit event; the Runner keeps the hourly budget and request deduplication
- [ ] **Step 2:** Run `toolchain/run go test -race ./internal/notify/...`. Expected: FAIL
- [ ] **Step 3:** Implement; verify the Telegram `sendMessage` request shape against the Bot API documentation before coding (to check)
- [ ] **Step 4:** Run the same command. Expected: PASS
- [ ] **Step 5:** Commit: `Add Telegram notifier`

## Task 14: End-to-end check, evidence and docs

**Files:**
- Create: `scripts/e2e.sh`, `docs/evidence.md`
- Modify: `README.md` (usage), `docs/AGENTS.md` (ownership of the plan and evidence), `toolchain/check` (runs `scripts/e2e.sh`)

- [ ] **Step 1:** Write `scripts/e2e.sh`: build the binary, `init` a vault in a temporary directory with a fake passphrase, start `serve` with a fake Telegram HTTP server, then drive the web forms with `curl` and the CLI with the built binary. Assertions, each printing PASS or FAIL:
  - `get` fails with no grant; create and grant through the web; `get` and `run` return the value; revoke makes `get` fail
  - the agent's `flag --kind invalid` blocks `get` and the next grant; a new value clears the flag
  - a request from the CLI appears in the web UI and the fake Telegram; approval grants it
  - a long grant survives killing and restarting the daemon only after the unlock page confirms it
  - notifier delivery from a `0600` env file on locked restart needs no login, unlock or grant restoration
  - vault files contain no canary value
- [ ] **Step 2:** Run `scripts/e2e.sh`. Expected: every line PASS, exit 0
- [ ] **Step 3:** Run `toolchain/check`. Expected: exit 0
- [ ] **Step 4:** Fill `docs/evidence.md` with commands, exit status and observed results for each acceptance criterion in `design.md`, the benchmark from Task 2, the manual checks from Task 10 and the web check from Task 12, each marked passed, failed or not run with a reason
- [ ] **Step 5:** Update the README with install, `init`, `serve` and CLI usage; run a stop-slop pass over all changed documents and reread them whole
- [ ] **Step 6:** Whole-branch review by an independent reviewer with the spec, this plan, the diff range and the evidence. Fix Critical and Important findings and recheck. Commit: `Add end-to-end check and evidence`

**Slice D ends here.** Deploy locally and provide the link for the user's website check. Keep the development branch until merge approval.

## Spec coverage

- Intent, decisions, components: Tasks 1, 8–10
- Cryptography and vault layout: Tasks 2–4
- Secret management: Tasks 3, 4, 7, 12
- Flags: Tasks 4, 7, 9, 12, 13
- Grants, long grants, restore: Tasks 6, 7, 10, 12
- Agent CLI and socket: Tasks 8, 9
- Web UI: Tasks 11, 12
- Telegram: Task 13
- Audit log: Task 5, with events emitted in Task 7
- Threat model and acceptance criteria: Tasks 3–14, evidence in Task 14
- Open items: Go and library versions (Task 1), Argon2id timing (Task 2), dumpable, `mlock`, suspend (Task 10), request limits and the 1-hour threshold (Task 7, proposal values)
