#!/bin/bash
# Run as sam in a terminal. sudo is used only for this one LaunchDaemon.
set -euo pipefail

if [[ "$(/usr/bin/id -un)" != sam || "$(/usr/bin/id -u)" != 502 ]]; then
  echo 'Run this script as sam (UID 502), without an outer sudo.' >&2
  exit 1
fi

source_plist=/Users/sam/umi-miner-setup/cloudflare/com.umi.studio-miner-tunnel.plist
target_plist=/Library/LaunchDaemons/com.umi.studio-miner-tunnel.plist
system_service=system/com.umi.studio-miner-tunnel
background_service=user/502/com.umi.studio-miner-tunnel

test -x /opt/homebrew/bin/cloudflared
test -x /opt/homebrew/bin/node
test -s /Users/sam/umi-miner-setup/cloudflare/tunnel-token
/usr/bin/plutil -lint "$source_plist"
test "$(/usr/libexec/PlistBuddy -c 'Print :Label' "$source_plist")" = com.umi.studio-miner-tunnel
test "$(/usr/libexec/PlistBuddy -c 'Print :UserName' "$source_plist")" = sam

if [[ -e "$target_plist" || -L "$target_plist" ]]; then
  if [[ -L "$target_plist" ]] || ! /usr/bin/cmp -s "$source_plist" "$target_plist"; then
    echo 'An existing, different LaunchDaemon needs review; nothing was changed.' >&2
    exit 1
  fi
fi

/usr/bin/sudo -v
/usr/bin/sudo /usr/bin/install -o root -g wheel -m 644 "$source_plist" "$target_plist"
/usr/bin/sudo /bin/launchctl enable "$system_service"
if ! /usr/bin/sudo /bin/launchctl print "$system_service" >/dev/null 2>&1; then
  /usr/bin/sudo /bin/launchctl bootstrap system "$target_plist"
fi

# The boot connector has its own metrics port. Leave the existing connector
# running until the new one reports at least one ready connection.
for attempt in {1..30}; do
  if /usr/bin/curl --fail --silent --max-time 2 http://127.0.0.1:20247/ready |
    /opt/homebrew/bin/node -e 'let s=""; process.stdin.on("data", x => s += x); process.stdin.on("end", () => { try { const v=JSON.parse(s); process.exit(v.status === 200 && v.readyConnections > 0 ? 0 : 1); } catch { process.exit(1); } });'
  then
    if /bin/launchctl print "$background_service" >/dev/null 2>&1; then
      /bin/launchctl bootout "$background_service"
    fi
    echo 'Tunnel boot service installed and connected. Validator services were not changed.'
    exit 0
  fi
  /bin/sleep 1
done

echo 'Boot service installed but not ready. The existing connector was left running.' >&2
exit 1
