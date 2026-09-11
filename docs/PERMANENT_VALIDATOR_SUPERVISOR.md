# Install the UMI validator supervisor

This is the one-time installation path for SN78 validators. Every validator uses
the same command and signed release stream. There is no validator-specific
configuration, directive URL, authorization file, or upload key.

The installer supports Ubuntu 24.04 or later and Debian 12 or later on Linux
x86_64 or arm64. It requires Podman 4.3.0 or later with `crun`; the installer
installs or verifies both. The host should have at least 8 CPU cores, 16 GiB RAM,
and 100 GiB of local storage. A GPU is not required.

The current signed worker runs bootstrap service weights: it replays existing
pilot evidence and checks the frozen miners' HTTPS `/healthz` endpoints before
submitting or renewing the row. It does not send new translation requests.
Installing this release alone does not start translation scoring. Miner operators
should follow [current miner operation](CURRENT_MINER_OPERATION.md); frozen
bootstrap participants still need their health endpoints online.

## Install

Clone the current `main` branch into a new directory and keep the checkout
clean:

```sh
git clone git@github.com:Umi-BitSign/umi.git umi-validator
test -z "$(git -C umi-validator status --porcelain=v1 --untracked-files=all)"
```

The current `main` commit is the one-time installation trust boundary. Review
that commit before running the installer with `sudo`. After installation, the
runtime does not execute later `main` commits; it accepts only signed,
hash-pinned UMI release directives.

Run one installer command. The wallet path must be absolute and must contain the
named hotkey:

```sh
sudo ./umi-validator/deploy/linux-validator-supervisor/install.sh \
  --wallet-name YOUR_WALLET \
  --hotkey-name YOUR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS \
  --legacy-unit YOUR_OLD_SN78_VALIDATOR.service
```

Use `--legacy-unit` only when the old SN78 writer is one system-level systemd
service. The installer verifies the complete signed release path before it
stops, disables, and masks that service.

If the old writer runs under Docker, Podman, PM2, cron, a user service, or
another process manager, stop and disable it first. Confirm that no old SN78
weight process remains, then omit `--legacy-unit`:

```sh
sudo ./umi-validator/deploy/linux-validator-supervisor/install.sh \
  --wallet-name YOUR_WALLET \
  --hotkey-name YOUR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS
```

Do not run an old writer and the UMI supervisor at the same time.

On supported Ubuntu and Debian hosts, the installer adds missing distribution
packages for rootless Podman. It does not explicitly request upgrades for
packages already present and refuses any package removal. It selects the
correct amd64 or arm64 stream,
installs the locked Python environment and signed host artifacts, creates an
isolated service account, and copies only the selected plaintext hotkey. It does
not read or copy a coldkey.

The installer checkout and runtime release are deliberately separate. The
installer reads `CURRENT_RELEASE_REVISION` from its own committed Git tree,
installs that exact release commit, and requires the coordinator-signed platform
artifact manifest to name the same commit. Advancing `main` for documentation or
API work therefore does not invalidate installation, while a replayed or altered
release manifest still fails before any legacy writer is stopped.

The installer is safe to rerun after a failure that occurs before the legacy
shutdown boundary. It removes the source tree and isolated hotkey that it staged
during that attempt. Once it begins retiring a named legacy service, it keeps
the verified installation for diagnosis and never silently restarts the old
writer.

Before that shutdown boundary, the installer loads the verified production
unit under its final `umi-validator-supervisor.service` name from
`/run/systemd/system`. A fixed checked-in drop-in temporarily replaces the
supervisor process with `/usr/bin/true`, while leaving the production
`ExecStartPre` and every sandbox directive in force. The rehearsal must start
successfully, after which the installer stops and completely unloads the
runtime unit before touching a legacy writer. Installation refuses to proceed
if that unit name or either transient systemd path is already occupied.

## Check the service

The installer waits for the supervisor process lock and prints
`status=installed` only after that check succeeds. Operators can inspect the
bounded status later with:

```sh
sudo systemctl status --no-pager umi-validator-supervisor.service
(
  cd /
  sudo -u umi-validator env -i \
    CONTAINERS_CONF_OVERRIDE=/opt/umi-validator-supervisor/deploy/linux-validator-supervisor/containers.conf \
    HOME=/var/lib/umi-validator-supervisor/home \
    XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
    XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
    XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /opt/umi-validator-supervisor/.venv/bin/umi-validator-supervisor status \
    --config /etc/umi/validator-supervisor.json
)
```

The release includes an immutable root-owned Podman override. It selects
`cgroupfs` without depending on a user login-manager or D-Bus session and clears
Podman's default container sysctls. The delegated service cgroup keeps older
supported Podman releases from moving the worker into a user-session scope, while
the worker runs with nested cgroup management disabled. It therefore inherits
the systemd service's fixed aggregate envelope: 8 CPUs, a 12 GiB hard memory
limit (with pressure control beginning at 11 GiB), and 512 tasks. The root-owned
parent limits cap the complete delegated subtree, keeping the supervisor,
container monitor, network helper, and worker under one lifecycle and resource
boundary. The worker does not require the cleared sysctls, which keeps startup
compatible with hosts where the service sandbox makes `/proc/sys` read-only.

Before each supervisor start, systemd also runs a fixed container smoke test
under that same sandbox. It exercises the production slirp4netns mode and two
empty dummy bind mounts, one read-only and one read-write, but mounts no wallet,
operator input, or worker state. A fixed `/bin/sh` expression only reads the
inherited cgroup files and verifies the CPU, memory, and task limits. It makes no
network request and exercises no signing path. Installation cannot report
success if rootless execution or resource enforcement is broken.

Rootless Podman normally keeps one unprivileged pause process alive to retain
its user and mount namespaces. The unit preserves only its dedicated
`/run/umi-validator-supervisor` directory across service stops so Podman can
reuse that process instead of losing its PID metadata and accumulating orphaned
namespace keepers. The directory remains mode `0700`, contains no wallet, and
is cleared with the rest of `/run` at boot.

The unit intentionally omits systemd's `ProtectHostname`, `ProtectKernelLogs`,
and `ProtectKernelTunables` directives. Each creates a host mount-namespace
restriction that prevents rootless Podman from creating the worker's own UTS or
proc namespace. The supervisor still runs under a dedicated non-root account
with no ambient capabilities; the container drops every capability, enables
no-new-privileges, uses a read-only root filesystem, and receives only its
fixed mounts.

If installation reaches the legacy shutdown boundary but the new service does
not become ready, do not unmask or restart the old writer. Inspect the service
with:

```sh
sudo journalctl -u umi-validator-supervisor.service --since=-10m --no-pager
```

The journal and status output should not contain wallet secrets. Never post a
hotkey file, wallet path, seed phrase, or private key.

## What is automatic

The installed service polls one UMI release stream every 30 seconds. The
installer selects a separate deterministic channel for each platform:

| Platform | Channel ID |
|---|---|
| `linux/amd64` | `a3ca19a108fe7d1a8e53a2db76f480ebe237b7942595f23135d6e11889ed40c0` |
| `linux/arm64` | `85ea6ef2c7e4f24d9d0eefa367425119b509e8604ce1675443efcbacc7bb4461` |

Every accepted directive is canonical, monotonic, and signed by the configured
UMI release authority. It selects a hash-pinned OCI image, source-tree digest,
entrypoint profile, and bounded input bundle. The supervisor verifies those
objects before changing the worker.

A directive can select only one of the fixed UMI profiles allowed by the local
configuration: hold, bootstrap service weights, inactive shadow validation, or
translation validation. It cannot provide a shell command, arbitrary arguments,
arbitrary mounts, or a container socket. The bootstrap profile always runs the
fixed `umi-simple-bootstrap-validator` entrypoint.

The common bootstrap directive applies to any hotkey that currently holds an
SN78 validator permit. The local configuration still binds one exact wallet and
hotkey. The worker checks the hotkey mapping and live permit in finalized chain
state before every write.

The common bootstrap input bundle contains only the frozen signed eligibility
manifest and coordinator-signed common lease. It has no validator-specific
transition authorization. It also has no result-upload credential: the exact
finalized row and `LastUpdate` on chain are the public receipt.

Signed, hash-pinned container updates are automatic after installation. The
local policy already permits the typed shadow and translation profiles, so a
later governed release can move the same installation beyond bootstrap without
another host migration. A new profile or trust authority would still require an
explicit operator change.

## Security boundary

The service runs as a dedicated non-login account through rootless Podman. The
worker sees only the selected hotkey, the signed input bundle, its signed release
manifest, and its durable worker-state directory. It cannot read the coldkey,
other wallets, supervisor control state, or the host container socket.

The worker container uses a read-only root filesystem, drops all capabilities,
sets `no-new-privileges`, and has fixed CPU, memory, and process limits. The
supervisor preserves one worker-state root across updates so an uncertain chain
submission is reconciled before another write.

The release signature authenticates exactly what operators delegated to the UMI
authority. It does not prove that signed code is harmless. A signed worker can
use the isolated validator hotkey for transactions that the chain permits. An
operator who no longer accepts that delegation must stop the service and rotate
the hotkey if compromise is suspected.

The bootstrap lease hard-pins its manifest, policy, required chain tuple, and
sunset. The worker renews the same authorized row before the effective
360-block activity cutoff, remains idle after the row covers the sunset, and
stops at the signed hard sunset. Invalid, expired, rolled-back, or incompatible
directives fail closed.

## Public artifact layout

The shared origin is:

```text
https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev
```

For each platform, the signed host manifest is published at:

```text
validator-supervisor/channels/<channel-id>/<linux-amd64|linux-arm64>/host-artifacts.json
```

Directive cursor pages are published under the same platform base:

```text
validator-supervisor/channels/<channel-id>/<linux-amd64|linux-arm64>/after/<sequence>/<digest-or-initial>.json
```

OCI archives, release bundles, and input bundles use immutable digest-addressed
URLs recorded in the signed objects. A cursor page at the current head can gain
a successor, so cursor responses must use `Cache-Control: no-store`. Immutable
digest-addressed artifacts may use long-lived immutable caching.
