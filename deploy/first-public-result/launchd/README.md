# macOS launchd deployment

These assets supervise the read-only observer and its remotely managed Cloudflare
Tunnel on an always-on Mac. Both processes run as the macOS account that invokes
the installer. The root-owned LaunchDaemon plists contain a token-file path, never
the tunnel token.

The Linux units in the parent directory remain the deployment reference for a
dedicated server. This directory covers the current Mac Studio host without
requiring an active GUI login or a stored sudo password. FileVault can still
require a person to unlock the startup volume after a cold boot.

## Prerequisites

- Install the UMI environment and `cloudflared` before rendering the plists.
- Keep the tunnel token outside the repository as one regular file owned by the
  service account, with mode `0400` or `0600` and one hard link.
- Do not run `manage.sh` through `sudo`. The installer requests sudo only for
  `/Library/LaunchDaemons` and the system launchd domain.
- Stop the temporary screen processes before installation:

```sh
screen -S umi-observer -X quit
screen -S umi-cloudflared -X quit
```

The installer refuses to continue while either named screen session exists. It
also refuses an unrelated listener on the observer or tunnel-metrics port.

## Render and inspect

Render the exact plists into a new temporary directory before installing them:

```sh
preview_directory=$(mktemp -d "${TMPDIR:-/tmp}/umi-launchd-preview.XXXXXX")
./manage.sh render \
  --output-dir "$preview_directory" \
  --token-file "$HOME/.cloudflared/umi-observer-api.token"
plutil -lint "$preview_directory"/*.plist
plutil -p "$preview_directory"/*.plist
```

Pass `--bundle-feed-config /absolute/path/observer-bundle-feed.json` when the
observer should ingest released validator bundles. The config is treated as
private operator input and must meet the same ownership and mode checks as the
tunnel token. The observer itself loads no wallet or signing material.

## Install and check

Run the installer from the account that will own the processes:

```sh
./manage.sh install \
  --token-file "$HOME/.cloudflared/umi-observer-api.token"
```

It renders and lints both plists before prompting for sudo, installs them as
`root:wheel` mode `0644`, starts the observer first, and waits for both local
readiness endpoints. The sudo timestamp is invalidated before the script exits.
The installed files are:

```text
/Library/LaunchDaemons/vision.umi.observer.plist
/Library/LaunchDaemons/vision.umi.cloudflared.plist
```

Re-running the same command is idempotent. A changed configuration requires
`--replace`; the script keeps the prior plists and launch state in its private
temporary directory and restores them if bootstrap or readiness fails. It never
copies or removes the tunnel token.

Check the installed files, launchd registration, observer readiness, and tunnel
connections at any time:

```sh
./manage.sh check \
  --token-file "$HOME/.cloudflared/umi-observer-api.token"
```

Use `sudo launchctl bootout system/vision.umi.observer` and
`sudo launchctl bootout system/vision.umi.cloudflared` for planned maintenance.
Killing a child process is ineffective because `KeepAlive` causes launchd to
restart it. Logs are written beneath `$HOME/Library/Logs/UMI`.

## Cloudflare edge check

The observer sends `Strict-Transport-Security: max-age=2592000` on every response.
The tunnel preserves that header, but it does not redirect public HTTP. In the
Cloudflare dashboard for `umi.vision`:

1. Under SSL/TLS -> Edge Certificates, enable Always Use HTTPS.
2. Set Minimum TLS Version to TLS 1.2.

The current Wrangler OAuth grant cannot change those settings because it lacks
Zone Settings Write. Use a dashboard session with the required zone role or a
separately scoped API token.

After deploying the rules, include the edge assertions in the normal check:

```sh
./manage.sh check \
  --token-file "$HOME/.cloudflared/umi-observer-api.token" \
  --check-public-edge
```

That check requires a permanent HTTP redirect preserving the path and query, an
HTTPS success, and a nonzero HSTS `max-age`.
