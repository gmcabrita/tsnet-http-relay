#!/usr/bin/env bash
# Deploys dist/tsnet-http-relay-linux-amd64 to mediasrv without `tailscale file cp`
# or SSH, both of which trigger a Tailscale reauth check.
#
# Flow: `rex cp` uploads the binary to a staging path next to the installed
# one, then Rex runs a command on mediasrv that verifies the sha256, moves it
# into place, and restarts the systemd user service.
set -euo pipefail

host="${DEPLOY_REX_HOST:-Mediasrv}"
binary="dist/tsnet-http-relay-linux-amd64"
# Same directory as the installed binary, so the final mv is an atomic rename.
staged=".local/bin/.tsnet-http-relay.new"

[[ -f "$binary" ]] || { echo "missing $binary" >&2; exit 1; }

sum="$(shasum -a 256 "$binary" | cut -d' ' -f1)"

block=""
created_session=""
cleanup() {
  if [[ -n "$created_session" ]]; then
    rex -S "$host" kill "$created_session" >/dev/null 2>&1 || true
  elif [[ -n "$block" ]]; then
    rex -S "$host" block close -s "$session" "$block" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# `rex -S` and `rex cp` need a session on the remote host. Reuse the first one,
# or create a temporary one.
session="$(rex -S "$host" ls --json | jq -r '.sessions[0].session_id // empty')"
if [[ -z "$session" ]]; then
  session="$(rex -S "$host" new deploy --json | jq -r '.session_id')"
  created_session="$session"
fi

rex -S "$host" cp -s "$session" --progress "$binary" ":$staged"

remote_script=$(cat <<EOF
set -euo pipefail
staged="\$HOME/$staged"
trap 'rm -f "\$staged"' EXIT
echo "$sum  \$staged" | sha256sum -c --quiet
chmod +x "\$staged"
mv "\$staged" "\$HOME/.local/bin/tsnet-http-relay"
systemctl --user restart tsnet-http-relay.service
sleep 1.5
systemctl --user --no-pager status tsnet-http-relay.service
EOF
)

status=0
created="$(rex -S "$host" run -s "$session" --label deploy --keep-open --focus=false \
  --json --wait -- bash -c "$remote_script")" || status=$?
block="$(printf '%s' "$created" | jq -rs '.[0].block_ids[0]')"

rex -S "$host" capture -s "$session" -b "$block" --trim
exit "$status"
