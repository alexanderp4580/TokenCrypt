# TokenCrypt progress

Status: Slices A–D are merged to `main`. Formatting, vet, race tests and 35 end-to-end assertions pass in the pinned Podman toolchain. User grants control agent access.

| Deliverable | State |
|---|---|
| Vault, metadata, audit, grants and core | Complete with recovery and byte-boundary tests |
| Unix-socket API and agent CLI | Integrated; private socket and same-uid checks passed |
| Daemon and hardening | Integrated; exclusive vault lock, bootstrap and coordinated shutdown passed |
| Authenticated website and management pages | Integrated; shared core service, CSRF and Host checks |
| Telegram notifier | Credentials come from `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in the daemon environment, work while locked and override saved settings; website save and `service/notifier.json` are the fallback. One daemon-lifetime budget; cancel/await/zero before rotation |
| End-to-end harness | Complete; fake HTTP Telegram and real web/CLI/restart flows passed |
| Desktop/phone viewport checks | Passed: seven pages at both viewport sizes, setup/login/create/grant/countdown/revoke; temporary fake vault |

## Verification

[Evidence](evidence.md) records exact commands, acceptance criteria and device observations. Do not initialize a production vault with a test or OS password.
