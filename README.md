# tsnet-http-relay

Single Go binary HTTP relay:

```text
Cloudflare Worker -> tsnet Funnel HTTPS -> this binary -> CycleTLS outbound request
```

## Tailscale setup

Enable in the tailnet:

- MagicDNS
- HTTPS certificates
- Funnel

Tailnet policy:

```json
{
  "nodeAttrs": [
    {
      "target": ["autogroup:member"],
      "attr": ["funnel"]
    }
  ]
}
```

Funnel listeners must use `:443`, `:8443`, or `:10000`.

## Run

```sh
export TS_AUTHKEY="tskey-auth-..." # optional after first auth
export RELAY_TOKEN="$(openssl rand -base64 32)"
export RELAY_ALLOWED_HOSTS="*" # arbitrary HTTP(S) target hosts

go run .
```

Defaults:

- `TSNET_HOSTNAME=laptop-relay`
- `TSNET_DIR=./tsnet-state`
- `TSNET_FUNNEL_ADDR=:443`
- `RELAY_TIMEOUT=30s`
- `RELAY_MAX_BODY_BYTES=10485760`

`RELAY_ALLOWED_HOSTS="*"` allows arbitrary HTTP(S) target hosts. Use `RELAY_ALLOWED_HOSTS="ifconfig.me,example.com"` to restrict to exact hosts.

Optional CycleTLS knobs:

- `RELAY_USER_AGENT`
- `RELAY_JA3`
- `RELAY_JA4R`
- `RELAY_HTTP2_FINGERPRINT`
- `RELAY_FORCE_HTTP1=true`
- `RELAY_FORCE_HTTP3=true`
- `RELAY_DISABLE_REDIRECTS=true`

Redirects are followed by default. Set `RELAY_DISABLE_REDIRECTS=true` to stop following them.

Avoid `RELAY_INSECURE_SKIP_VERIFY=true` unless debugging.

## Call

```sh
curl "https://laptop-relay.your-tailnet.ts.net/https://ifconfig.me" \
  -H "Authorization: Bearer $RELAY_TOKEN"
```

Use the inbound method as the outbound method:

```sh
curl -X PATCH "https://laptop-relay.your-tailnet.ts.net/https://example.com/resource" \
  -H "Authorization: Bearer $RELAY_TOKEN" \
  --data '{"ok":true}'
```

Forwarded when provided:

- `User-Agent`
- `Accept`
- `Accept-Language`
- `Referer`

Healthcheck:

```sh
curl "https://laptop-relay.your-tailnet.ts.net/healthz"
```

Returns:

```text
ok
```

Cloudflare Worker:

```ts
export default {
  async fetch(_req: Request, env: Env): Promise<Response> {
    return fetch("https://laptop-relay.your-tailnet.ts.net/https://ifconfig.me", {
      headers: {
        authorization: `Bearer ${env.RELAY_TOKEN}`,
      },
    });
  },
};

interface Env {
  RELAY_TOKEN: string;
}
```

## Security model

Relay requires:

- bearer token via `Authorization: Bearer ...`
- exact host allowlist via `RELAY_ALLOWED_HOSTS`, unless set to `*`
- HTTP and HTTPS target URLs only
- redirects followed by default
- hop-by-hop/proxy headers stripped
- relay auth / control headers not forwarded upstream

Target URL must be provided as the request path: `https://relay-host/https://target-host/path`.

Supported methods: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. The inbound method is used as the outbound method.

## Run as a service on macOS

Use a LaunchAgent.

Build and install:

```sh
mise run build
mkdir -p ~/.local/bin
cp ./tsnet-http-relay ~/.local/bin/tsnet-http-relay
chmod +x ~/.local/bin/tsnet-http-relay
```

Create env file:

```sh
mkdir -p ~/.config/tsnet-http-relay ~/.local/state/tsnet-http-relay
chmod 700 ~/.config/tsnet-http-relay

cat > ~/.config/tsnet-http-relay/env <<'EOF'
export RELAY_TOKEN="replace-me"
export RELAY_ALLOWED_HOSTS="*"
export TSNET_HOSTNAME="laptop-relay"
export TSNET_DIR="$HOME/.local/state/tsnet-http-relay"
export TSNET_FUNNEL_ADDR=":443"
EOF

chmod 600 ~/.config/tsnet-http-relay/env
```

Generate token:

```sh
perl -0777 -pi -e 's/replace-me/'"$(openssl rand -base64 32 | sed 's/[\/&]/\\&/g')"'/g' ~/.config/tsnet-http-relay/env
```

Create wrapper:

```sh
cat > ~/.local/bin/tsnet-http-relay-launchd <<'EOF'
#!/bin/zsh
set -eu

source "$HOME/.config/tsnet-http-relay/env"

exec "$HOME/.local/bin/tsnet-http-relay"
EOF

chmod +x ~/.local/bin/tsnet-http-relay-launchd
```

Create LaunchAgent:

```sh
mkdir -p ~/Library/LaunchAgents ~/Library/Logs/tsnet-http-relay

cat > ~/Library/LaunchAgents/com.gmcabrita.tsnet-http-relay.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.gmcabrita.tsnet-http-relay</string>

    <key>ProgramArguments</key>
    <array>
      <string>$HOME/.local/bin/tsnet-http-relay-launchd</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>$HOME/Library/Logs/tsnet-http-relay/stdout.log</string>

    <key>StandardErrorPath</key>
    <string>$HOME/Library/Logs/tsnet-http-relay/stderr.log</string>
  </dict>
</plist>
EOF
```

Start:

```sh
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.gmcabrita.tsnet-http-relay.plist
launchctl enable "gui/$(id -u)/com.gmcabrita.tsnet-http-relay"
launchctl kickstart -k "gui/$(id -u)/com.gmcabrita.tsnet-http-relay"
```

Check:

```sh
launchctl print "gui/$(id -u)/com.gmcabrita.tsnet-http-relay"
tail -f ~/Library/Logs/tsnet-http-relay/stdout.log
tail -f ~/Library/Logs/tsnet-http-relay/stderr.log
```

Restart:

```sh
launchctl kickstart -k "gui/$(id -u)/com.gmcabrita.tsnet-http-relay"
```

If you changed the plist, reload it:

```sh
launchctl bootout "gui/$(id -u)" ~/Library/LaunchAgents/com.gmcabrita.tsnet-http-relay.plist
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.gmcabrita.tsnet-http-relay.plist
launchctl kickstart -k "gui/$(id -u)/com.gmcabrita.tsnet-http-relay"
```

Stop:

```sh
launchctl bootout "gui/$(id -u)" ~/Library/LaunchAgents/com.gmcabrita.tsnet-http-relay.plist
```

First run can print a Tailscale auth URL. Open it once. Future runs reuse `TSNET_DIR`.

Keep Mac awake if needed:

```sh
sudo pmset -a sleep 0
```

## Run as a service on Linux (systemd)

Use a systemd user service.

Build and install:

```sh
mise run build
mkdir -p ~/.local/bin
cp ./tsnet-http-relay ~/.local/bin/tsnet-http-relay
chmod +x ~/.local/bin/tsnet-http-relay
```

Create env file:

```sh
mkdir -p ~/.config/tsnet-http-relay ~/.local/state/tsnet-http-relay
chmod 700 ~/.config/tsnet-http-relay

cat > ~/.config/tsnet-http-relay/env <<'EOF'
export RELAY_TOKEN="replace-me"
export RELAY_ALLOWED_HOSTS="*"
export TSNET_HOSTNAME="laptop-relay"
export TSNET_DIR="$HOME/.local/state/tsnet-http-relay"
export TSNET_FUNNEL_ADDR=":443"
EOF

chmod 600 ~/.config/tsnet-http-relay/env
```

Generate token:

```sh
perl -0777 -pi -e 's/replace-me/'"$(openssl rand -base64 32 | sed 's/[\/&]/\\&/g')"'/g' ~/.config/tsnet-http-relay/env
```

Create wrapper:

```sh
cat > ~/.local/bin/tsnet-http-relay-systemd <<'EOF'
#!/bin/sh
set -eu

. "$HOME/.config/tsnet-http-relay/env"

exec "$HOME/.local/bin/tsnet-http-relay"
EOF

chmod +x ~/.local/bin/tsnet-http-relay-systemd
```

Create systemd unit:

```sh
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/tsnet-http-relay.service <<'EOF'
[Unit]
Description=tsnet HTTP relay

[Service]
Type=simple
ExecStart=%h/.local/bin/tsnet-http-relay-systemd
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target
EOF
```

Start:

```sh
systemctl --user daemon-reload
systemctl --user enable --now tsnet-http-relay.service
```

Run without an active login session:

```sh
sudo loginctl enable-linger "$USER"
```

Check:

```sh
systemctl --user status tsnet-http-relay.service
journalctl --user -u tsnet-http-relay.service -f
```

If service fails with `Permission denied`, check executable bits:

```sh
chmod +x ~/.local/bin/tsnet-http-relay
chmod +x ~/.local/bin/tsnet-http-relay-systemd
systemctl --user restart tsnet-http-relay.service
```

If it still fails, check for a `noexec` home mount:

```sh
findmnt -no OPTIONS -T ~/.local/bin/tsnet-http-relay
```

If output contains `noexec`, install outside home:

```sh
sudo cp ~/.local/bin/tsnet-http-relay /usr/local/bin/tsnet-http-relay
sudo chmod +x /usr/local/bin/tsnet-http-relay
perl -0777 -pi -e 's#exec "\$HOME/\.local/bin/tsnet-http-relay"#exec /usr/local/bin/tsnet-http-relay#' ~/.local/bin/tsnet-http-relay-systemd
systemctl --user restart tsnet-http-relay.service
```

Restart:

```sh
systemctl --user restart tsnet-http-relay.service
```

If you changed the unit, reload it:

```sh
systemctl --user daemon-reload
systemctl --user restart tsnet-http-relay.service
```

Stop:

```sh
systemctl --user disable --now tsnet-http-relay.service
```

First run can print a Tailscale auth URL. Open it once. Future runs reuse `TSNET_DIR`.
