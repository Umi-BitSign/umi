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
- Close the temporary screen sessions before installation:

```sh
screen -S umi-observer -X quit
screen -S umi-cloudflared -X quit
```

Closing a screen session can remove its socket while leaving the child process
alive. Check the two listener ports after closing the sessions:

```sh
./manage.sh migration-check
```

When a listener remains, the check reports its PID without printing its command
arguments. Inspect each reported process, confirm its user and executable, then
send `TERM` to that PID only:

```sh
/bin/ps -p REPORTED_PID -o pid=,ppid=,user=,comm=
/bin/kill -TERM REPORTED_PID
```

Run `migration-check` again and continue only after it prints
`migration_preflight_ready=1`. The installer repeats the port check and refuses
to replace an unverified listener. It never stops a process automatically.

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
observer should ingest released validator bundles. Pass
`--pilot-feed-config /absolute/path/observer-pilot-feed.json` only when it should
serve fully replayed, explicitly nonconforming component pilots from the separate
`/api/v1/pilots` namespace. Both configs are treated as private operator input and
must meet the same ownership and mode checks as the tunnel token. The observer
itself loads no wallet or signing material.

By default, the plist runs `.venv/bin/umi-observer` from the selected repository.
`--observer-bin /absolute/path/to/umi-observer` keeps that entry-point form while
allowing a different installed binary. For a component pilot, use
`--observer-python /absolute/path/to/python` with the exact Python environment
that generated the evidence. This renders the observer command as
`python -m umi.observer`, so launchd cannot select a different interpreter through
an entry-point shebang. The two observer options are mutually exclusive.

## Install and check

Run the installer from the account that will own the processes:

```sh
./manage.sh migration-check
./manage.sh install \
  --token-file "$HOME/.cloudflared/umi-observer-api.token"
```

When serving component-pilot evidence, include the interpreter and feed config in
both `install` and later `check` commands:

```sh
observer_python="$HOME/umi-miner/umi-reference-model/.venv/bin/python"
pilot_config="$HOME/Library/Application Support/UMI/observer-pilot-feed.json"
test -x "$observer_python"
"$observer_python" -c 'import bitsign_motion, umi'

./manage.sh install \
  --observer-python "$observer_python" \
  --pilot-feed-config "$pilot_config" \
  --token-file "$HOME/.cloudflared/umi-observer-api.token"
./manage.sh check \
  --observer-python "$observer_python" \
  --pilot-feed-config "$pilot_config" \
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

That check requires a permanent HTTP redirect preserving the path and query, a
nonzero HSTS `max-age`, rejection of TLS 1.1, and successful TLS 1.2.
