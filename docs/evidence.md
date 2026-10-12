# TokenCrypt verification evidence

Integrated Slices A–D are on `main`. The 2026-10-10 final checks below cover the integrated runtime.

## Executed commands

| Check | Runner / snapshot | Observed result |
|---|---|---|
| `toolchain/run sh scripts/e2e.sh` before runtime integration | Direct pinned-Go 1.27.2 fallback; main placeholder | Failed, exit 1: daemon exited before listening; expected RED |
| `toolchain/run sh scripts/e2e.sh` after integration | Direct pinned-Go fallback | Passed, exit 0, 32 assertions before adding setup-lock and stdin-init coverage |
| `toolchain/run go test -race ./cmd/tokencrypt ./internal/daemon -count=1` | Direct pinned-Go fallback; integrated runtime | Passed, exit 0; main 2.762s, daemon 2.114s |
| `toolchain/run env CGO_ENABLED=0 go build -o .local/tokencrypt-candidate ./cmd/tokencrypt` | Direct pinned-Go fallback | Passed, exit 0; `file` reports statically linked |
| First real `toolchain/check` during a harness edit | Real Podman, integrated runtime | Failed compiling scripts: context import configuration lagged a concurrent source edit; cmd/internal race packages passed |
| `toolchain/run go test ./scripts` with frozen source | Real Podman | Passed, exit 0 without a source or cache change |
| Final `toolchain/check` with frozen source | Real Podman; integrated runtime on 2026-10-10 | Passed, exit 0: formatting, vet, full race suite and 35 e2e PASS assertions |
| `sh -n scripts/e2e.sh toolchain/check`; `git diff --check` | Integration checkout | Passed, exit 0 |
| `toolchain/run go test -bench DeriveKEK -benchtime=1x -run '^$' ./internal/crypto/` | Pinned container; coordinator observation | Passed, exit 0: 1,217,096,541 ns/op; default 256 MiB, 14 passes, 4 lanes |

The shell harness builds a static binary and uses a Go HTTP client and local fake Telegram server; it needs no Python or curl in the container. It exercises the actual CLI socket, web forms and daemon processes, using temporary storage and fake credentials.

## Design acceptance criteria

The final real-container suite passed the named tests. The end-to-end assertions also passed where listed.

| Criterion | Evidence | Result |
|---|---|---|
| Ciphertext contains no secret or bot token | E2E vault scan; vault `TestNoPlaintextOnDisk` | Passed |
| No grant, live grant, expiry and revoke | E2E get/run/revoke; grants `TestReadReturnsValueUntilExpires` | Passed |
| Grant isolates the selected secret | E2E alpha/beta; core `TestGrantOfOneSecretLeavesAnotherUnreadable` | Passed |
| Wrong passphrase grants nothing and is audited | E2E wrong-passphrase/audit assertions | Passed |
| CLI request appears on web and Telegram; denial blocks access | E2E escaped request, fake Telegram, approval and denial | Passed |
| CRUD needs passphrase; metadata view omits value | web `TestSecretPagesCRUDNeverRenderValues`; core throttle tests | Passed |
| Value update and rename revoke grants; next grant reads new value | core `TestUpdateRenameDeleteRevokeLiveGrants`, `TestUpdateMakesNextGrantReturnNewValue`; E2E replacement value | Passed |
| Both flag kinds revoke, deny and block operations; audit includes actor/kind | core `TestFlagRevokesDeniesBlocksAndReports`; E2E invalid flag | Passed |
| CLI cannot clear flag; new value clears it | CLI usage tests; E2E clear refusal and replacement | Passed |
| Long-grant restart requires unlock and confirmation; invalid records stay blocked | E2E killed-daemon restart; grants `TestCandidatesKeepOnlyVerifiedCurrentRecords`, `TestRestoreRechecksFlagKeyAndReveal` | Passed |
| Duration limit is 90 days | core `TestGrantDurationBounds`; web `TestGrantChoicesCountdownAndRevoke` | Passed |
| Website and metadata API omit stored values | E2E pages/status; web CRUD tests; CLI escaped-status test | Passed |
| Swapped ciphertext fails to decrypt | vault `TestSwappedFilesFail` | Passed |
| Socket 0700/0600 and same-uid admission | API `TestSocketPermissionsReadAndCancellation`, `TestPeerUIDCheckedForEachConnection`; E2E socket mode | Passed |
| Invalid names fail | vault `TestNames`; core `TestCreateRejectsDuplicateAndBadName` | Passed |
| 1 MiB boundary and empty/multiline/binary round trips | vault `TestRoundTripValues`; API `TestBinaryReads`; CLI `TestGetBytesAndDeniedRead` | Passed |
| Pending-request limit and escaped/plain-text reasons | core `TestEleventhPendingRequestIsRefusedUntilOneEnds`; web request tests; E2E escaped reason and fake Telegram | Passed |
| Crash before atomic rename preserves the previous file | vault `TestCrashBeforeRename` and write recovery tests | Passed |
| Fake-clock expiry, HTTP, flag, restore/MAC, socket and fake-Telegram tests | Final full race suite | Passed |
| First-run setup and daemon lifetime | E2E setup/lock/init; main `TestNotifierEnvFileWorksLockedAndHidesToken` | Passed |

## Notifier env-file checks (2026-10-12)

| Command / behavior | Observed result |
|---|---|
| `toolchain/run go test -race ./internal/notify ./cmd/tokencrypt` | Passed, exit 0; env-file parsing (quotes, whitespace, comments, unknown keys, CRLF), rejection of symlink, modes `0640`/`0644`, wrong owner, oversized file, partial and invalid values, and missing file as not configured |
| Main tests `TestNotifierEnvFileWorksLockedAndHidesToken`, `TestConfiguredNotifierStartsLockedAfterRestart` | Passed; fake Telegram received request and flag notices on a locked daemon across two starts, protected reads stayed denied, token and chat ID absent from the audit log and pages |
| Main tests `TestNotifierUnusableEnvFileIsOffWithOneGenericAuditEvent`, `TestNotifierMissingEnvFileIsOffWithoutAuditEvent`, `TestNotifierIgnoresProcessEnvironment`, `TestStrayNotifierFilesInVaultAreIgnored` | Passed; one generic `notifier.failed` event per unusable file, none for a missing file, process environment ignored, stray vault files ignored |
| Final `toolchain/check` | Passed, exit 0; formatting, vet, full race suite and 39 process e2e PASS assertions. The e2e harness wrote a `0600` env file and passed `--env-file`; cold process restart delivered fake Telegram before login or unlock, while the saved long grant stayed locked |

Live Telegram delivery from the env file remains a coordinator check.

## Device and browser checks

| Check | Observed result |
|---|---|
| Desktop/phone viewport authenticated browser flows | Passed: coordinator checked seven pages at 1280×900 and 375×812 with no horizontal overflow; setup, login, create, 10-minute grant, countdown tick and revoke passed using a temporary fake vault |
| Dumpable and memory-lock limits | Passed: production startup reports dumpable 0 and soft/hard limits 8,388,608 bytes |
| Same-uid `/proc/PID/mem` and `strace -p` | Passed: coordinator observed permission denial; strace exits 1 with Operation not permitted |
| Key and live-grant memory locks | Automated locking/release tests passed; tests check page-isolated buffers without exposing credential values |
| Suspend/resume expiry | Not run: user requested uninterrupted completion; fake-clock wall/monotonic expiry tests passed |
| Live Telegram account with the env file | Not run (to check) |

