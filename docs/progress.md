# TokenCrypt progress

Status: Slices A–D are merged to `main`. Formatting, vet, race tests and 39 end-to-end assertions pass in the pinned Podman toolchain. User grants control agent access.

| Deliverable | State |
|---|---|
| Vault, metadata, audit, grants and core | Complete with recovery and byte-boundary tests |
| Unix-socket API and agent CLI | Integrated; private socket and same-uid checks passed |
| Daemon and hardening | Integrated; exclusive vault lock, bootstrap and coordinated shutdown passed |
| Authenticated website and management pages | Integrated; shared core service, CSRF and Host checks |
| Telegram notifier | One credential source: an env file read at daemon startup (`serve --env-file`, `0600`). Works while locked; changing credentials needs a restart. One daemon-lifetime budget |
| End-to-end harness | Complete; fake HTTP Telegram and real web/CLI/restart flows passed |
| Desktop/phone viewport checks | Passed: seven pages at both viewport sizes, setup/login/create/grant/countdown/revoke; temporary fake vault |

## Verification

[Evidence](evidence.md) records exact commands, acceptance criteria and device observations. Do not initialize a production vault with a test or OS password.
