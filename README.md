# TokenCrypt

Share encrypted secrets with a coding agent through time-limited grants. You manage secrets and approve access in the website; the agent uses `get`, `run`, `request`, `status` and `flag` through a private Unix socket.

## Build and install

Install Podman, then build with the pinned Go toolchain:

```sh
toolchain/build
toolchain/check
toolchain/run env CGO_ENABLED=0 go build -o .local/tokencrypt ./cmd/tokencrypt
install -Dm755 .local/tokencrypt "$HOME/.local/bin/tokencrypt"
```

`toolchain/check` checks formatting, vet, race tests and the fake-secret end-to-end harness. [Verification evidence](docs/evidence.md) records observed results and pending device checks.

## Start the website

```sh
tokencrypt serve --allowed-hosts 127.0.0.1:8765,localhost:8765 \
  --approval-url http://127.0.0.1:8765
```

Visit `http://127.0.0.1:8765` to choose and confirm your vault passphrase. For terminal initialization, run `tokencrypt init`; it reads the passphrase twice with terminal echo disabled. Passphrases never belong in command arguments or service environment variables.

The vault defaults to `$XDG_DATA_HOME/tokencrypt` (or `~/.local/share/tokencrypt`), audit state to `$XDG_STATE_HOME/tokencrypt` (or `~/.local/state/tokencrypt`), and the socket to `$XDG_RUNTIME_DIR/tokencrypt/sock`. Override these with `--vault-dir`, `--state-dir` and `--socket`. The CLI accepts `TOKENCRYPT_SOCKET` as a socket override.

To serve the website under a hostname through a reverse proxy on port 80, use:

```sh
tokencrypt serve --listen 127.0.0.1:8765 \
  --allowed-hosts crypt.local,localhost,127.0.0.1 \
  --approval-url http://crypt.local
```

The listener accepts loopback IP addresses. Allowed hosts must match the complete Host header, including a port when present. The reverse proxy forwards that Host header to the loopback listener. Plain-HTTP deployments use cookies without the Secure flag; `--secure-cookies` is available for an HTTPS deployment.

A user service can run that command with `Restart=always`, `UMask=0077` and `NoNewPrivileges=yes`. After installing its unit at `~/.config/systemd/user/tokencrypt.service`, run `systemctl --user daemon-reload` and `systemctl --user enable --now tokencrypt.service`. The first website visit initializes the production vault with your own passphrase.

## Agent commands

Examples use the fake secret name `api_token`:

```sh
tokencrypt status
tokencrypt request api_token --for 10m --reason 'Run the integration check'
tokencrypt run --with api_token -- sh -c 'your-command'
tokencrypt get api_token
tokencrypt flag api_token --kind invalid --reason 'Service rejected this token'
```

`get` prints the granted bytes. `run` supplies values through uppercase environment variables such as `API_TOKEN`. A flag revokes access and blocks another grant until you clear it through the website or update the value.

Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in the daemon's environment; with both set, `serve` delivers notices from them, including while the vault is locked, and they take precedence over saved settings. For a systemd user unit, keep them in a file readable only by you (for example `~/.config/tokencrypt/telegram.env`, mode `0600`) and reference it with `EnvironmentFile=%h/.config/tokencrypt/telegram.env` in the unit's `[Service]` section. Surrounding whitespace is trimmed; if only one is set, the daemon writes a generic `notifier.failed` audit entry and uses the saved settings below.

Without those variables, save Telegram credentials on the notifier page with your vault passphrase. Delivery starts on save and daemon startup, including while the vault is locked. The daemon stores these service credentials outside vault encryption in `service/notifier.json` under your vault directory (directory `0700`, file `0600`); the page keeps them hidden. It shows when settings are missing or unreadable. If you have encrypted settings in `notifier.json` and no service file, one successful unlock migrates them. Configured service credentials take precedence.

After a daemon restart, unlock and confirm the saved long grants you want to restore. Notification delivery grants no access; unlock alone does not confirm a saved grant.

## HTTPS and test options

For HTTPS, add the public hostname to `--allowed-hosts`, set `--secure-cookies` and use the HTTPS URL as `--approval-url`. TokenCrypt always requires the vault passphrase and ignores forwarded identity headers. `--telegram-api-base` selects a fake HTTP server for tests; production uses Telegram's API by default.

- [Design](docs/design.md)
- [Implementation plan](docs/implementation-plan.md)
- [Current progress](docs/progress.md)
- [Agent rules](AGENTS.md)
