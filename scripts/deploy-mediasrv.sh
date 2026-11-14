#!/usr/bin/env bash
# Deploys dist/tsnet-http-relay-linux-amd64 to mediasrv without `tailscale file cp`
# or SSH, both of which trigger a Tailscale reauth check.
#
# Flow: this Mac serves the binary over HTTP on its tailnet IP under a random
# path, then Rex runs a command on mediasrv that pulls it with curl, verifies
# the sha256, installs it, and restarts the systemd user service.
set -euo pipefail

host="${DEPLOY_REX_HOST:-Mediasrv}"
port="${DEPLOY_PORT:-8765}"
binary="dist/tsnet-http-relay-linux-amd64"

[[ -f "$binary" ]] || { echo "missing $binary" >&2; exit 1; }

ip="$(tailscale ip -4 | head -1)"
token="$(openssl rand -hex 16)"
sum="$(shasum -a 256 "$binary" | cut -d' ' -f1)"

serve_dir="$(mktemp -d)"
cp "$binary" "$serve_dir/$token"

# Bind to the tailnet IP only, so the file is not reachable on the LAN.
python3 -m http.server "$port" --bind "$ip" --directory "$serve_dir" >/dev/null 2>&1 &
server_pid=$!
block=""
session=""
cleanup() {
  kill "$server_pid" 2>/dev/null || true
  rm -rf "$serve_dir"
  if [[ -n "$block" ]]; then
    rex -S "$host" block close -s "$session" "$block" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Wait for the server to accept connections.
for _ in {1..20}; do
  curl -fs -o /dev/null "http://$ip:$port/$token" && break
  sleep 0.1
done

remote_script=$(cat <<EOF
set -euo pipefail
tmp=\$(mktemp)
trap 'rm -f "\$tmp"' EXIT
curl -fsS "http://$ip:$port/$token" -o "\$tmp"
echo "$sum  \$tmp" | sha256sum -c --quiet
chmod +x "\$tmp"
mv "\$tmp" "\$HOME/.local/bin/tsnet-http-relay"
systemctl --user restart tsnet-http-relay.service
sleep 1.5
systemctl --user --no-pager status tsnet-http-relay.service
EOF
)

# `rex -S` needs a session on the remote host. Reuse the first one, or create one.
session="$(rex -S "$host" ls --json | jq -r '.sessions[0].session_id // empty')"
if [[ -z "$session" ]]; then
  session="$(rex -S "$host" new deploy --json | jq -r '.session_id')"
fi

status=0
created="$(rex -S "$host" run -s "$session" --label deploy --keep-open --focus=false \
  --json --wait -- bash -c "$remote_script")" || status=$?
block="$(printf '%s' "$created" | jq -rs '.[0].block_ids[0]')"

rex -S "$host" capture -s "$session" -b "$block" --trim
exit "$status"
