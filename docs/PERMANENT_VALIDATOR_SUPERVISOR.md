[Documentation](README.md) / Validator supervisor

# Install the UMI validator supervisor

[Install](#install) | [Check the service](#check-the-service) |
[Automatic updates](#what-is-automatic) | [Troubleshooting](#troubleshooting)

This is the one-time installation path for SN78 validators. Every validator uses
the same command and signed release stream. There is no validator-specific
configuration, directive URL, authorization file, or result-upload credential.

The installer supports Ubuntu 24.04 or later and Debian 12 or later on Linux
x86_64 or arm64. It requires Podman 4.3.0 or later with `crun`; the installer
installs or verifies both. The host should have at least 8 CPU cores, 16 GiB RAM,
and 100 GiB of local storage. A GPU is not required.

On a Mac, provision a supported Linux VM and follow this guide inside it.
There is no native Darwin validator-supervisor installation path. The retired
Docker calibration guide is not the current validator setup.

Ubuntu 22.04's distribution package is Podman 3.4.4, below this requirement.
Use Ubuntu 24.04 or later, or Debian 12 or later. Installing a third-party Podman
build on Ubuntu 22.04 is outside the supported installation path. Do not bypass
the Podman version check or install Ubuntu 24.04 packages into Ubuntu 22.04.
See the official [Ubuntu 22.04 package](https://packages.ubuntu.com/jammy/podman)
and [Ubuntu 24.04 package](https://packages.ubuntu.com/noble/podman) listings.

The [registration bridge](operators/bridge.md) replaces the frozen-pilot
worker with temporary live-miner weights grouped by coldkey, HTTPS IP or a
recorded funder in the signed policy. It does not
send translation requests. Miner operators should follow
[current miner operation](CURRENT_MINER_OPERATION.md).

The ongoing bridge policy has no scheduled submission cutoff or sunset. It
continues until a signed replacement or revocation, subject to its health,
registration and chain checks. Existing finite policies retain their original
expiry; installing source alone does not extend an old signed policy.

Ordinary weight-writing validators do not need private evaluation videos or
labels. Operators nominated for competition evaluation must separately follow
the [private holdout setup](operators/private-holdout.md#open-competition-private-holdout--private-storage-and-evaluator-setup).
Never put the holdout in this checkout, a public release bundle, or a miner mount.

This bridge's first rollout is to UMI's existing UID 0 and UID 54 installations,
with their submission journals preserved. Existing supervisors need the host
parser/profile update before accepting it. An unrelated validator with an old
on-chain row and no UMI submission journal will hold for reconciliation. Do not
delete journals, reinstall over a running supervisor, or assume a successful
installation proves that weights were submitted.

## Install

### Optional temporary funding audit

Operators running the separate [registration-funding audit](operators/funding-audit.md#registration-funding-audit)
need a Taostats API key. The deployed weight-writing validator does not require
one. UMI runs one cached audit worker on the coordinator; validators do not each
need to repeat the scan. The [funding-cap policy](operators/bridge.md)
carries the reviewed funding snapshot and its report digest. The audit cannot
change weights without a new signed policy and directive. New registration
checks are automatic; publishing new funding bindings is still a separate step.

### Validator installation

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
installer reads `CURRENT_RELEASE_REVISION` and the signed platform manifest in
`deploy/linux-validator-supervisor/host-artifacts/` from its own committed Git
tree. It installs that exact release commit and requires the signed manifest to
name the same commit. Advancing `main` or publishing a later channel manifest
therefore does not change an existing checkout's host bootstrap. Altered
signatures or mismatched release bindings still fail before any legacy writer
is stopped. Release publishers must update the pin and both signed manifests in
one commit; the deployment tests verify their signatures and revision bindings.

The installer explicitly fetches the pinned commit from the same local source
repository into its installed clone. This also works when a fresh source clone
holds the release only under a remote-tracking branch. An older installer can
fail at checkout with `reference is not a tree` or `unable to read tree` despite
the commit existing in the operator's checkout. That failure precedes legacy
shutdown. Retry using a fresh, reviewed main checkout; do not change the release
pin or delete a running installation. The release need not be an ancestor of
the installer's `main` commit.

The installer is safe to rerun after a failure that occurs before the legacy
shutdown boundary. It removes the source tree and isolated hotkey that it staged
during that attempt. Once it begins retiring a named legacy service, it keeps
the verified installation for diagnosis and never silently restarts the old
writer.

If installation reports `common_host_artifact_binding_mismatch`, the signed
manifest's platform, channel or release revision does not match the installer's
expected values. This is separate from a Podman version error. Earlier
installers fetched a mutable channel manifest and could encounter this mismatch
after a channel release. Use a fresh, reviewed `main` checkout after a failed
pre-shutdown attempt; do not edit the manifest, disable signature checks, delete
submission journals or rerun the fresh installer over a running supervisor.

If installation reports `operator_input_bundle_invalid`, the host could not
validate the signed operator-input bundle. This is separate from a missing
validator permit, which the worker reports as `validator_permit_missing`.
The runtime-458 bridge update exposed an older installer pin whose host parser
accepted only runtime 455. The installer now pins the runtime-independent
host release and its matching signed manifests for both architectures. The
legacy runtime field remains in signed bundles for compatibility; the worker
checks actual chain settings rather than requiring that version number. After
a failed pre-shutdown installation, use a fresh, reviewed main checkout.
Do not edit the bundle or bypass validation. A permitted SN78 hotkey is still
required to submit weights, and an unrelated old weight row may require the
reconciliation described above.

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
configuration: hold, bootstrap service weights, registration-bridge weights,
inactive shadow validation, or translation validation.
It cannot provide a shell command, arbitrary arguments, arbitrary mounts, or a
container socket. The legacy bootstrap profile runs the fixed
`umi-simple-bootstrap-validator` entrypoint. The registration-bridge
profile runs `umi-registration-bridge` with its separate signed policy.

The common bootstrap directive applies to any hotkey that currently holds an
SN78 validator permit. The local configuration still binds one exact wallet and
hotkey. The worker checks the hotkey mapping and live permit in finalized chain
state before every write.

The legacy bootstrap input bundle contained the frozen signed eligibility
manifest and coordinator-signed lease. The registration-bridge input bundle
contains the signed availability policy instead. Neither requires a per-validator
upload credential. The exact finalized row and `LastUpdate` are publicly visible;
the local journal also retains the submitted transaction identity and inputs.

Signed, hash-pinned container updates are automatic after installation. The
local policy permits the existing typed shadow and translation profile names,
but the current worker implements bootstrap only. The open-competition
successor needs new host-side input and durable-state contracts, a compatible
worker and a consented host upgrade. An image update alone cannot perform that
transition. See [successor upgrade requirements](validators/successor-upgrade.md#successor-supervisor-upgrade).
Do not rerun the fresh-install script over an existing supervisor installation.

## Troubleshooting

A running supervisor and a present container do not prove that the worker is
writing weights. Check the worker reason code and the finalized `LastUpdate`.
Supervisor `durable_hold:false` applies only to the supervisor's own journal.

| Observation | Meaning and next step |
| --- | --- |
| `prior_submission_outcome_unknown` | An earlier attempt has no confirmed successful receipt. The current bridge worker does not clear this automatically. Preserve its journal; do not reinstall, erase state or start another writer. |
| `validator_not_registered` | The configured hotkey is not currently registered. Verify its public identity and registration; a service restart does not register it. |
| `validator_permit_missing` | Registration alone is insufficient to write weights. Verify the current permit. |
| `operator_input_bundle_invalid` | Signed input validation failed; this is separate from a missing permit. Do not edit the bundle or bypass checks. |
| `common_host_artifact_binding_mismatch` | The host artifact does not match the installation binding. Follow the failed-install retry guidance above. |
| Unit changed on disk | Run `sudo systemctl daemon-reload` to refresh systemd's unit definition. This does not restart the process, upgrade the release or clear a worker hold. |

For an unknown submission, report only this bounded journal summary with your
public hotkey. It reads no wallet. Keep the full journal private and unchanged.

```sh
sudo jq '{validator_hotkey, phase, last_observed_block, updated_at_unix_ms, attempt_id: .attempt.attempt_id, preflight_block: .attempt.preflight_block, prior_last_update: .attempt.prior_last_update, weight_call}' /var/lib/umi-validator-worker-state/registration-bridge-journal.json
```

The missing outcome may reflect a timeout, disconnect, interrupted process or
submission failure. The reason code alone cannot identify which happened.
The current bridge records an attempt before submission but not signed bytes,
nonce and exact era. A matching row or elapsed time alone therefore cannot
clear its hold. A returned finalized receipt follows a separate verification
and recovery path. See [bridge diagnostics](operators/bridge.md#unknown-submissions).

For routine signed container updates, leave the supervisor running. A Git pull,
restart or rerun of the installer is not a host-upgrade procedure. Use the
[state-preserving host upgrade](validators/successor-upgrade.md) when an explicitly
announced transition requires one.

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

The registration-bridge policy pins eligibility, chain requirements and lifetime.
The ongoing profile renews until replaced or stopped; historical finite policies
retain their expiry. Freshness, submission and recovery checks still apply.
Invalid, expired, rolled-back or incompatible directives fail closed.

## Public artifact layout

The shared origin is:

```text
https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev
```

For each platform, a signed host manifest is also published at:

```text
validator-supervisor/channels/<channel-id>/<linux-amd64|linux-arm64>/host-artifacts.json
```

The fresh installer uses the signed manifest committed with its release pin,
not this mutable channel copy. It downloads the files from the digest-addressed
URLs in that committed manifest and verifies each file's size and SHA-256.

Directive cursor pages are published under the same platform base:

```text
validator-supervisor/channels/<channel-id>/<linux-amd64|linux-arm64>/after/<sequence>/<digest-or-initial>.json
```

OCI archives, release bundles, and input bundles use immutable digest-addressed
URLs recorded in the signed objects. A cursor page at the current head can gain
a successor, so cursor responses must use `Cache-Control: no-store`. Immutable
digest-addressed artifacts may use long-lived immutable caching.
