# Supervise the validator audit tunnel on macOS

This LaunchDaemon keeps one remotely managed Cloudflare Tunnel connected to the
Mac validator's loopback-only audit origin. It carries no wallet and reads the
tunnel token from a private file; the token itself never appears in the plist or
process arguments.

The UMI coordinator first creates a dedicated tunnel in the `umi.vision` account,
maps the validator's declared audit hostname to
`http://127.0.0.1:8093`, and sends only that tunnel's token to the validator
operator through a private channel. Do not post the token in GitHub or Discord.

Install `cloudflared`, place the one-line token in a private file, and start the
local audit services before rendering the daemon:

```sh
brew install cloudflared
install -d -m 0700 "$HOME/.cloudflared"
install -m 0600 /absolute/private/downloaded-token \
  "$HOME/.cloudflared/umi-validator-audit.token"

deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env audit-start
curl --silent --show-error http://127.0.0.1:8093/not-a-public-route \
  --output /dev/null --write-out '%{http_code}\n'
```

The final command must print `404`. Verify that the token is one regular,
non-symlink file owned by the operator with one hard link and mode `0400` or
`0600`:

```sh
export TOKEN_FILE="$HOME/.cloudflared/umi-validator-audit.token"
test -f "$TOKEN_FILE" && test ! -L "$TOKEN_FILE"
test "$(stat -f '%u' "$TOKEN_FILE")" = "$(id -u)"
test "$(stat -f '%l' "$TOKEN_FILE")" = 1
case "$(stat -f '%Lp' "$TOKEN_FILE")" in 400|600) ;; *) exit 1 ;; esac
```

Render the checked-in template without putting the token value on a command line.
The plist contains only its path:

```sh
export UMI_REPO=/absolute/path/to/clean/umi
export CLOUDFLARED_BIN="$(command -v cloudflared)"
export PREVIEW_DIR="$(mktemp -d "${TMPDIR:-/tmp}/umi-audit-tunnel.XXXXXX")"
export PREVIEW_PLIST="$PREVIEW_DIR/vision.umi.validator-audit-tunnel.plist"

cp "$UMI_REPO/deploy/macos-validator/launchd/vision.umi.validator-audit-tunnel.plist.in" \
  "$PREVIEW_PLIST"
plutil -replace ProgramArguments.0 -string "$CLOUDFLARED_BIN" "$PREVIEW_PLIST"
plutil -replace ProgramArguments.9 -string "$TOKEN_FILE" "$PREVIEW_PLIST"
plutil -replace UserName -string "$(id -un)" "$PREVIEW_PLIST"
plutil -replace GroupName -string "$(id -gn)" "$PREVIEW_PLIST"
plutil -replace EnvironmentVariables.HOME -string "$HOME" "$PREVIEW_PLIST"
plutil -lint "$PREVIEW_PLIST"
plutil -p "$PREVIEW_PLIST"
test -z "$(grep -F 'REPLACE_WITH_' "$PREVIEW_PLIST" || true)"
```

Inspect the printed executable, user, token-file path, metrics listener, and log
paths. Then install exactly that file. Refuse to overwrite a different installed
daemon; stop and review it first:

```sh
export INSTALLED_PLIST=/Library/LaunchDaemons/vision.umi.validator-audit-tunnel.plist
if sudo test -e "$INSTALLED_PLIST"; then
  sudo cmp -s "$PREVIEW_PLIST" "$INSTALLED_PLIST" || {
    echo "installed audit-tunnel plist differs; stop and review it" >&2
    exit 1
  }
else
  sudo install -o root -g wheel -m 0644 "$PREVIEW_PLIST" "$INSTALLED_PLIST"
fi
sudo launchctl bootstrap system "$INSTALLED_PLIST" 2>/dev/null || \
  sudo launchctl kickstart -k system/vision.umi.validator-audit-tunnel
```

Check both the tunnel connection and the public hostname supplied by the
coordinator. The public probe must return `404` over HTTPS; a redirect, origin
bypass, or successful response for the non-route fails the check:

```sh
export PUBLIC_AUDIT_ORIGIN=https://audit-validator-name.umi.vision
curl --fail --silent --show-error http://127.0.0.1:49093/ready
test "$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  "$PUBLIC_AUDIT_ORIGIN/not-a-public-route")" = 404
sudo launchctl print system/vision.umi.validator-audit-tunnel >/dev/null
```

Repeat these checks after the controlled reboot drill. For planned maintenance,
stop the tunnel without deleting its plist, token, logs, or audit evidence:

```sh
sudo launchctl bootout system/vision.umi.validator-audit-tunnel
```

The daemon sends stdout and stderr to `/dev/null` so an always-on tunnel cannot
fill the host disk with unbounded logs. Use the loopback metrics endpoint and the
Cloudflare tunnel dashboard for health; Docker separately keeps bounded local
logs for the validator, audit publisher, and audit origin.

FileVault may still require a person to unlock the Mac after a cold boot, and
Docker Desktop requires the operator login that starts its Linux VM. Do not join a
timed window until the local origin, tunnel readiness endpoint, and public HTTPS
probe all pass after that login.
