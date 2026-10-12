# TokenCrypt

TokenCrypt gives a coding agent encrypted secrets for a limited time. You store secrets and approve access in a website. The agent calls `get`, `run`, `request`, `status` and `flag` over a private Unix socket.

## Build and install

Install Podman, then build with the pinned Go toolchain:

```sh
toolchain/build
toolchain/check
toolchain/run env CGO_ENABLED=0 go build -o .local/tokencrypt ./cmd/tokencrypt
install -Dm755 .local/tokencrypt "$HOME/.local/bin/tokencrypt"
```

`toolchain/check` runs formatting, vet, race tests and the fake-secret end-to-end harness. [Verification evidence](docs/evidence.md) lists the observed results.

## Run the website

```sh
tokencrypt serve --allowed-hosts 127.0.0.1:8765,localhost:8765 \
  --approval-url http://127.0.0.1:8765
```

Open `http://127.0.0.1:8765` and set a vault passphrase. To initialize from a terminal, run `tokencrypt init`; it reads the passphrase twice with echo off. Never pass the passphrase as a command argument or service environment variable.

The vault lives in `$XDG_DATA_HOME/tokencrypt` (`~/.local/share/tokencrypt`), audit state in `$XDG_STATE_HOME/tokencrypt` (`~/.local/state/tokencrypt`) and the socket at `$XDG_RUNTIME_DIR/tokencrypt/sock`. Override them with `--vault-dir`, `--state-dir` and `--socket`. The CLI reads `TOKENCRYPT_SOCKET` as a socket override.

To serve the website under a hostname through a reverse proxy on port 80, use:

```sh
tokencrypt serve --listen 127.0.0.1:8765 \
  --allowed-hosts crypt.local,localhost,127.0.0.1 \
  --approval-url http://crypt.local
```

The listener binds loopback addresses only. An allowed host must equal the full Host header, port included when present. The proxy forwards that header to the listener. Plain HTTP uses cookies without the Secure flag; add `--secure-cookies` for HTTPS.

To run it as a user service, put the command in `~/.config/systemd/user/tokencrypt.service` with `Restart=always`, `UMask=0077` and `NoNewPrivileges=yes`. Then run `systemctl --user daemon-reload` and `systemctl --user enable --now tokencrypt.service`. The first website visit sets the vault passphrase.

## Agent commands

Examples use the fake secret name `api_token`:

```sh
tokencrypt status
tokencrypt request api_token --for 10m --reason 'Run the integration check'
tokencrypt run --with api_token -- sh -c 'your-command'
tokencrypt get api_token
tokencrypt flag api_token --kind invalid --reason 'Service rejected this token'
```

`get` prints the granted bytes. `run` passes values as uppercase environment variables such as `API_TOKEN`. A flag revokes access and blocks new grants until you clear it in the website or update the value.

## Telegram notices

The daemon sends request notices to Telegram, including while the vault is locked. It reads the bot token and chat ID once at startup from one env file, `$XDG_CONFIG_HOME/tokencrypt/telegram.env` (`~/.config/tokencrypt/telegram.env`). Use `--env-file PATH` to choose another path.

```sh
TELEGRAM_BOT_TOKEN=123456:fake-token
TELEGRAM_CHAT_ID=123456789
```

Lines are `KEY=VALUE`. Blank lines and `#` comments are ignored, and quotes around a value are removed. Make the file a regular file you own with mode `0600`. The daemon refuses symlinks and files readable by group or others; it then leaves notices off and writes a `notifier.failed` audit entry without values. A missing file leaves notices off with no entry. A systemd unit needs no `EnvironmentFile`.

Process environment variables are not read. To change the token, edit the file and restart the daemon.

After a daemon restart, unlock and confirm each saved long grant you want back. A notice grants no access, and unlock alone confirms nothing.

## HTTPS and tests

For HTTPS, add the public hostname to `--allowed-hosts`, pass `--secure-cookies` and set `--approval-url` to the HTTPS URL. TokenCrypt ignores forwarded identity headers and always asks for the vault passphrase. `--telegram-api-base` points the notifier at a fake server in tests; it defaults to Telegram's API.

- [Design](docs/design.md)
- [Implementation plan](docs/implementation-plan.md)
- [Current progress](docs/progress.md)
- [Agent rules](AGENTS.md)
