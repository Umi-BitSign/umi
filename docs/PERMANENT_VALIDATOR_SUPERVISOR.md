# Install the permanent UMI validator supervisor on Linux

The permanent supervisor lets an SN78 validator accept UMI assignments through a
signed release channel. An existing operator can retire one legacy writer during
installation; a clean host can explicitly install without naming or changing any
legacy service.
The operator chooses the allowed modes during installation. A directive cannot
enable a mode that is absent from that local list.

Version 2 starts with no managed worker and never restores the legacy process.
Invalid, expired, rolled-back, or unsupported directives also leave the managed
worker in `hold`.
Finalized chain observations, rather than a local supervisor receipt, determine
when the old pending queue and rows have cleared.

## Rollout prerequisite

Do not install this service from the example file alone. UMI must first publish a
migration notice that names all of the following:

- one exact 40-character UMI revision;
- the channel ID and release-authority hotkey set;
- the validator-specific directive URL; and
- a sequence-1 signed `hold` directive available from that URL.

The directive publication route is a required deployment component. The presence
of this code in the repository does not mean that `api.umi.vision` already serves
the route. The migration notice must identify a live endpoint, and the operator
must verify the initial signed directive with the pinned supervisor before retiring
the old validator. Placeholder values in the example configuration are
deliberately invalid.

The observer implementation includes an optional file-backed publication route.
That code is not evidence that a production channel exists. Before sharing an
install command, UMI must publish the exact feed-config hash, each validator's
configuration hash, sequence-1 directive hash, initial-page hash, and public
URL, then verify that the public bytes match those hashes through the Cloudflare
edge. See the directive-feed section of [`DASHBOARD_API.md`](DASHBOARD_API.md).

## Current capability

The mode names have these meanings:

| Mode | Intended signed runner action | Current state |
|---|---|---|
| `hold` | No worker container or chain write | Available at installation |
| `bootstrap_service_weights` | Manifest anchor and permit-bound emergency direct full row described by the release | The directive binds one immutable bundle containing the signed manifest, target-bound transition authorization, drain preflight, and owner-fence receipt. The worker repeats the preflight before submission. |
| `inactive_shadow` | Three transcript anchors, no weight call | The standalone live validator implements this mode, but this supervisor worker profile is not implemented and fails closed |
| `translation_weights` | Future governed translation-weight calls | No translation-active runner exists in version 0.1; the current policy model and live validator reject this mode |

Including `translation_weights` in `allowed_modes` records advance operator
consent for a later signed implementation. It does not make the current release
weight-active. Omitting it means the operator must edit and recheck the local
configuration before a later translation release can start.

The supervisor's release authority can select and execute a signed UMI runner as
the validator service account. A selected runner can read and copy the raw hotkey
and use it to sign arbitrary calls during its signed lease. The fixed container
profile is not transaction-scoped signing and does not prevent authority-approved
code from exfiltrating the key. An exfiltrated key remains usable outside the
supervisor until the operator rotates it. Threshold signatures authorize the exact
directive and image, but accepting them delegates the full hotkey capability to
that code. A signer broker or HSM with call-level policy enforcement is future
hardening.

The service receives no coldkey, owner key, sudo access, host container socket, or
authority over unrelated system services. Worker containers run through rootless
Podman. The service account has no supplementary groups, and neither the supervisor
nor a worker receives a Docker or Podman API socket.

## Signed channel

The checked-in example reserves a validator-specific URL base under
`https://api.umi.vision/api/v1/validator-directives/`; the migration notice must
confirm the live publication route before installation. The installed configuration
pins the base without a trailing slash. Every accepted directive is canonical JSON
signed by the configured threshold of release-authority hotkeys. It binds the channel,
validator, sequence, previous directive hash, mode, immutable release and input-bundle
digests, worker role, and activation bounds.

Version 2 uses one independent channel and sequence chain per validator. Every
directive on that channel must contain exactly the configured validator hotkey as
its sole `validator_hotkeys` entry. A shared sequence across a changing validator
cohort is unsupported: omitting a validator from any intermediate signed directive
would correctly prevent that host from skipping the entry or rejoining later.

The local high-water record is monotonic. A repeated sequence with different
bytes, a skipped predecessor, an authority or threshold mismatch, and a release
hash mismatch all fail closed. A directive cannot carry a shell command or
arbitrary arguments. That restriction applies to the directive envelope, not to
the behavior of an authority-approved image. HTTPS transports the object; its
signatures authorize it.
The record also binds the accepted mode, immutable OCI manifest digest, and
bootstrap input-bundle digest. The OCI digest is null only for `hold`; the input
digest exists only for bootstrap mode. After a process restart, any existing record
forces one stop-and-hold reconciliation before a later poll may verify, preflight,
and resume the same signed directive.

For a worker directive, the supervisor first persists the authenticated monotonic
state and establishes `hold`. It then downloads the bounded release bundle from an
allowed HTTPS origin, verifies its hashes and signed manifest, resolves the allowed
OCI repository to the exact signed manifest digest, and rereads owned Finney
finality before starting the candidate. The fixed Podman profile uses a read-only
root filesystem,
`--cap-drop=all`, `--security-opt=no-new-privileges`, the configured CPU, memory,
and PID limits, and an exact mount list. It never mounts a host container socket.

Supervisor control state and worker state use separate host roots. The container
can write only `/var/lib/umi-validator-worker-state`, mounted inside the container
as `/var/lib/umi-worker`. It cannot see the supervisor directive high-water file
or its lock under `/var/lib/umi-validator-supervisor/state`. Worker releases must
store commit journals, transaction receipts, replay checkpoints, and other state
needed to classify an interrupted chain operation in the worker-state root. Do not
delete or reuse that root during an upgrade.

The fixed profile bounds CPU, memory, and process count. Artifact retrieval bounds
each release bundle by size and each network operation by time. It does not enforce
a filesystem quota on the cumulative OCI image store, release cache, or worker-state
root, and it does not rate-limit worker egress. Monitor free space on those paths.
Before broad rollout, place them on a dedicated filesystem or apply a tested project
quota. Retain the active release and every worker journal or receipt needed to
resolve an in-flight or failed chain operation; delete only superseded, unreferenced
releases and images under a published retention procedure.

## Host prerequisites

This installer targets a Linux host booted with systemd and unified cgroup v2. It
uses GNU `stat`, `readlink`, `find`, `install`, `getent`, `runuser`, `awk`, and
rootless Podman at `/usr/bin/podman`, and `slirp4netns` at
`/usr/bin/slirp4netns`. Podman's `newuidmap` and `newgidmap` helpers must come from
the host distribution. The host also needs Git, `jq`, and the pinned `uv` release
used below. Finality freshness also depends on a sane host clock;
confirm `timedatectl show --property=NTPSynchronized --value` reports `yes`. Run
the installation on a console that will remain connected until the final service
checks finish.

The checked-in resource profile requires at least 8 CPU cores, 16 GiB RAM, and
100 GiB of local storage. The validator does not need a GPU. Outbound HTTPS, OCI
release downloads, DNS, and Finney peer connectivity must work from the dedicated
service account.

## 1. Prepare one pinned supervisor environment

Use the exact 40-character revision named by the UMI migration notice. Clone over
SSH into a temporary path as an ordinary user, verify the detached checkout, then
install the immutable source under `/opt`:

```sh
revision=REPLACE_WITH_40_CHARACTER_UMI_REVISION
checkout="$PWD/umi-validator-supervisor-$revision"
test ! -e /opt/umi-validator-supervisor && test ! -L /opt/umi-validator-supervisor
git clone --no-checkout git@github.com:Umi-BitSign/umi.git "$checkout"
git -C "$checkout" checkout --detach "$revision"
test "$(git -C "$checkout" rev-parse HEAD)" = "$revision"
test -z "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)"
sudo mv "$checkout" /opt/umi-validator-supervisor
sudo chown -R root:root /opt/umi-validator-supervisor
test "$(sudo git -C /opt/umi-validator-supervisor rev-parse HEAD)" = "$revision"
test -z "$(sudo git -C /opt/umi-validator-supervisor status --porcelain=v1 --untracked-files=all)"
```

Install the locked runtime with a hash-verified `uv 0.12.9` binary and CPython
3.12.14. The migration notice must publish the expected `uv` binary hash for the
host architecture. Do not execute a user-writable `uv` binary through `sudo` or
install from a moving branch:

```sh
uv_source=/absolute/path/to/hash-verified/uv
uv_sha256=REPLACE_WITH_PUBLISHED_UV_BINARY_SHA256
printf '%s  %s\n' "$uv_sha256" "$uv_source" | sha256sum --check
sudo install -o root -g root -m 0755 "$uv_source" \
  /opt/umi-validator-supervisor/.uv-0.12.9
printf '%s  %s\n' "$uv_sha256" /opt/umi-validator-supervisor/.uv-0.12.9 \
  | sudo sha256sum --check
test "$(sudo /opt/umi-validator-supervisor/.uv-0.12.9 --version | awk '{print $1 " " $2}')" = "uv 0.12.9"
sudo env \
  UV_PYTHON_INSTALL_DIR=/opt/umi-validator-supervisor/.uv-python \
  /opt/umi-validator-supervisor/.uv-0.12.9 python install 3.12.14
sudo env \
  UV_PYTHON_INSTALL_DIR=/opt/umi-validator-supervisor/.uv-python \
  UV_PROJECT_ENVIRONMENT=/opt/umi-validator-supervisor/.venv \
  /opt/umi-validator-supervisor/.uv-0.12.9 sync \
    --project /opt/umi-validator-supervisor --locked --no-dev --no-editable \
    --python 3.12.14
test "$(sudo /opt/umi-validator-supervisor/.venv/bin/python --version)" = "Python 3.12.14"
sudo /opt/umi-validator-supervisor/.venv/bin/umi-validator-supervisor --help
```

Install the exact GRANDPA finality verifier and Finney raw chain specification
named by the migration notice. Obtain both from the notice's immutable artifact
links before running these commands. The chain-spec digest is fixed in the
supervisor source; the verifier digest is target-specific and belongs in the local
configuration:

```sh
finality_verifier_source=/absolute/path/to/umi-grandpa-finality-observer
finality_verifier_sha256=REPLACE_WITH_PUBLISHED_FINALITY_VERIFIER_SHA256
finney_chain_spec_source=/absolute/path/to/raw_spec_finney.json
finney_chain_spec_sha256=f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105
printf '%s  %s\n' "$finality_verifier_sha256" "$finality_verifier_source" | sha256sum --check
printf '%s  %s\n' "$finney_chain_spec_sha256" "$finney_chain_spec_source" | sha256sum --check
sudo install -d -o root -g root -m 0755 \
  /opt/umi-validator-supervisor/artifacts
sudo install -o root -g root -m 0555 "$finality_verifier_source" \
  /opt/umi-validator-supervisor/artifacts/umi-grandpa-finality-observer
sudo install -o root -g root -m 0444 "$finney_chain_spec_source" \
  /opt/umi-validator-supervisor/artifacts/raw_spec_finney.json
printf '%s  %s\n' "$finality_verifier_sha256" \
  /opt/umi-validator-supervisor/artifacts/umi-grandpa-finality-observer \
  | sudo sha256sum --check
printf '%s  %s\n' "$finney_chain_spec_sha256" \
  /opt/umi-validator-supervisor/artifacts/raw_spec_finney.json \
  | sudo sha256sum --check
```

Make the completed environment immutable to non-root users. The installer repeats
this check before it touches the legacy service:

```sh
sudo chown -R root:root /opt/umi-validator-supervisor
sudo chmod -R go-w /opt/umi-validator-supervisor
test -z "$(sudo find /opt/umi-validator-supervisor -xdev \
  ! -type l \( ! -user root -o -perm /0022 -o -perm /07000 \) -print -quit)"
test -z "$(sudo find /opt/umi-validator-supervisor -xdev \
  -type l ! -user root -print -quit)"
```

The venv may contain root-owned symlinks. The installer resolves every one and
requires its target to stay below `/opt/umi-validator-supervisor`; broken or
escaping links fail the installation.

The service path stays fixed. Signed releases are stored separately below
`/var/lib/umi-validator-supervisor/releases`; the supervisor never runs Git or a
moving checkout.

## 2. Prepare the dedicated runtime hotkey

The system service runs as `umi-validator`. Give it a dedicated wallet tree that
contains only the selected validator hotkey and optional public coldkey metadata.
Never copy a coldkey, seed phrase, unrelated hotkey, SSH key, or cloud credential.

The version 1 adapter requires a plaintext Bittensor hotkey file so it can verify
the configured SS58 identity and support unattended signing. An encrypted hotkey
is rejected; there is no reviewed noninteractive credential adapter in this
release. Never put a wallet password, mnemonic, seed, or private key in the JSON
file, command line, or a general environment file. If the source hotkey is
encrypted, stop and wait for an approved migration procedure instead of manually
rewriting it.

Create the dedicated account before preparing Podman or the runtime wallet:

```sh
if ! getent group umi-validator >/dev/null 2>&1; then
  sudo groupadd --system umi-validator
fi
if ! id umi-validator >/dev/null 2>&1; then
  sudo useradd --system --gid umi-validator --no-create-home \
    --home-dir /var/lib/umi-validator-supervisor --shell /usr/sbin/nologin \
    umi-validator
fi
```

Install rootless Podman after the account exists. The account needs
non-overlapping ranges of at least 65,536 IDs in both `/etc/subuid` and
`/etc/subgid`. Use the distribution's rootless Podman procedure to allocate those
ranges; do not copy a range already assigned to another account. A direct
`usermod --add-subuids START-END --add-subgids START-END umi-validator` is valid
only after the administrator proves that the complete range is unused. The
installer checks the ranges, rootless status, cgroup v2, private graph and run
roots, user namespace, and absence of supplementary group membership before it
stops the legacy service.

The system service does not set `RestrictSUIDSGID` or host-level
`NoNewPrivileges`: rootless Podman needs the distribution's narrowly scoped
setuid `newuidmap` and `newgidmap` helpers to create the configured subordinate
mapping. Those helpers can map only the assigned subordinate ranges. The worker
container itself runs with all capabilities dropped and no-new-privileges. Do
not replace either helper or grant the service account another setuid program.

The supervisor keeps Podman's configuration, storage, and runtime directory under
its private systemd state paths. It invokes `/usr/bin/podman` directly. Do not run
a privileged container daemon or give this account a container API socket. The
production adapter runs the one managed container in the foreground under the
systemd control group; it does not use a detached container as a second supervisor.
Its fixed `--userns=keep-id:uid=WORKER_UID,gid=WORKER_GID` mapping maps the host
`umi-validator` account to the configured container identity. Without that mapping,
a non-root container worker cannot read the `0400` hotkey through the read-only
wallet bind.

Now create the restricted runtime wallet. Replace the names and source root:

```sh
wallet_name=REPLACE_WITH_RUNTIME_WALLET_NAME
hotkey_name=REPLACE_WITH_RUNTIME_HOTKEY_NAME
source_wallet_root=/absolute/path/to/existing/bittensor/wallets
runtime_wallet_root=/var/lib/umi-validator-runtime-wallets
sudo install -d -o root -g umi-validator -m 0750 "$runtime_wallet_root"
sudo install -d -o umi-validator -g umi-validator -m 0700 \
  "$runtime_wallet_root/$wallet_name" \
  "$runtime_wallet_root/$wallet_name/hotkeys"
sudo install -o umi-validator -g umi-validator -m 0400 \
  "$source_wallet_root/$wallet_name/hotkeys/$hotkey_name" \
  "$runtime_wallet_root/$wallet_name/hotkeys/$hotkey_name"
if test -f "$source_wallet_root/$wallet_name/coldkeypub.txt"; then
  sudo install -o umi-validator -g umi-validator -m 0400 \
    "$source_wallet_root/$wallet_name/coldkeypub.txt" \
    "$runtime_wallet_root/$wallet_name/coldkeypub.txt"
fi
```

The named wallet directory must contain only `hotkeys/` and the optional
`coldkeypub.txt`; `hotkeys/` must contain only the selected hotkey file. The
adapter rejects extra wallet or hotkey entries, symlinks, hard links, unexpected
owners, broader modes, encrypted keyfiles, and a key whose SS58 identity differs
from `validator_hotkey`. The container receives the complete restricted wallet
root as a read-only bind. Because the file is plaintext, protect the host and treat
every authority-approved worker image as fully trusted with that hotkey.

UMI also supplies one 32-byte result-upload key to each validator through a
private channel. This is a narrowly scoped transport credential, not a wallet or
R2 account credential. It permits create-only writes under the validator bootstrap
result route; the published body must still carry the validator-hotkey signature.
Never reuse one validator's key on another host. Save the supplied 64-character
lowercase hexadecimal value in an owner-only file without printing it:

```sh
bootstrap_result_upload_key=/absolute/private/path/bootstrap-result-upload.key
chmod 0600 "$bootstrap_result_upload_key"
credential_size=$(wc -c <"$bootstrap_result_upload_key")
test "$credential_size" -eq 64 -o "$credential_size" -eq 65
LC_ALL=C grep -Eq '^[0-9a-f]{64}$' "$bootstrap_result_upload_key"
```

The installer copies it to a fixed service-only path. A bootstrap worker mounts
only that file read-only. It does not receive the general pilot credential or any
Cloudflare API token.

## 3. Create the one-time configuration

After UMI has published the rollout prerequisites above, copy
`deploy/linux-validator-supervisor/validator-supervisor.json.example` outside the
repository. Replace every placeholder. `channel_id` is the 64-character ID in the
public migration notice. Convert the validator SS58 address to AccountId32 for the
directive URL base using the pinned UMI environment; do not append `.json`, add a
trailing slash, or copy another validator's base.

```sh
validator_hotkey=REPLACE_WITH_VALIDATOR_HOTKEY
validator_account_id32=$(
  /opt/umi-validator-supervisor/.venv/bin/python -c \
    'import sys; from umi.encoding import account_id32; print(account_id32(sys.argv[1]).hex())' \
    "$validator_hotkey"
)
printf '%s\n' "$validator_account_id32"
```

`trusted_authorities` are sorted by decoded AccountId32. The signature threshold
cannot exceed their count. `allowed_modes` are an operator decision. To avoid a
later local edit, an operator who intends to remain with UMI may approve all four
declared names now, with the current limitations in the table above.

`allowed_oci_repositories` and `release_origins` are separate local allowlists.
The first contains registry repository names without a tag or digest. The second
contains canonical HTTPS origins without a path. `target_platform`, worker UID and
GID, CPU, memory, and PID ceilings constrain every selected worker. The checked-in
Linux example uses `linux/amd64`, container UID/GID `65532`, 8 CPUs, 12 GiB, and
512 PIDs. `release_origins` applies to release bundles and canonical input bundles.
Bootstrap inputs are downloaded, hash-checked, and staged beneath the
directive-specific release directory. The mutable `operator_input_root` is not
mounted in bootstrap mode. Keep it empty and never place it beneath the wallet,
release, supervisor state, or worker state root. `worker_state_root` is the only
persistent read-write container bind. Keep the example memory and PID ceilings in
version 2: the system service reserves
the remaining headroom within its 16 GiB and 640-task aggregate limits.

`finality_verifier_binary` and `finality_chain_spec_path` must retain the fixed
artifact paths from the example. Set `finality_verifier_sha256` to the
target-specific digest from the migration notice. The supervisor reads finalized
heads from that hash-pinned smoldot verifier over its peer path. It does not accept
a provider RPC endpoint as a finality source.

Encode the completed object as canonical JSON without a trailing newline. Keep it
owned by the operator at mode `0600` until installation:

```sh
config=/absolute/private/path/validator-supervisor.json
canonical_config="$config.canonical"
umask 077
chmod 0600 "$config"
test ! -e "$canonical_config"
jq -cSj . "$config" >"$canonical_config"
chmod 0600 "$canonical_config"
```

Before it touches the legacy process, the installer runs both `check-config` and
`preflight-initial-hold` as the restricted service account. The latter reads a fresh
owned Finney finality result, fetches the configured directive URL, and requires a
current, validator-bound, threshold-signed sequence-1 `hold` directive with no
predecessor. It does not write supervisor directive state or worker state. A
placeholder, wrong identity, unsafe path, stale finality result, missing route, or
invalid hold stops the installation before the old service is disabled.

The supervisor directive-state and worker-state directories must both be empty on
this first installation. The installer fails on old contents instead of deleting
or adopting them; inspect and archive unexpected state before trying again.

## 4. Start the supervisor

Choose exactly one installation mode. Do not create a dummy unit to satisfy the
legacy mode.

### Clean host

Use `--fresh-install` only when the host has no existing SN78 weight writer under
systemd, a container runtime, PM2, cron, a user service, or another supervisor.
This is an explicit operator assertion; the installer does not try to discover
those launch paths. It performs the same configuration, signed-hold, finality,
wallet, and rootless-container checks as the legacy path, then installs the UMI
service without inspecting, stopping, disabling, masking, or inventing a legacy
service.

```sh
canonical_config=/absolute/private/path/validator-supervisor.json.canonical
bootstrap_result_upload_key=/absolute/private/path/bootstrap-result-upload.key
sudo /opt/umi-validator-supervisor/deploy/linux-validator-supervisor/install.sh \
  --config "$canonical_config" \
  --bootstrap-result-upload-key "$bootstrap_result_upload_key" \
  --fresh-install
```

### Existing systemd validator

Version 1 accepts exactly one systemd system service. It does not search process
names or touch Docker, PM2, cron, user services, or another supervisor. If the old
writer has more than one start path, remove those other exact paths before using
this installer. The installer kills and checks every process still present in the
selected unit's cgroup. It cannot discover a process that previously escaped that
cgroup or started elsewhere. The finalized-chain drain remains the authoritative
check that the old writer has stopped submitting.

Record the old unit's exact name, including `.service`, and inspect it locally:

```sh
legacy_unit=REPLACE_WITH_EXACT_LEGACY_UNIT.service
systemctl show "$legacy_unit" --property=LoadState,FragmentPath,UnitFileState,ActiveState
```

Run the pinned installer:

```sh
canonical_config=/absolute/private/path/validator-supervisor.json.canonical
bootstrap_result_upload_key=/absolute/private/path/bootstrap-result-upload.key
sudo /opt/umi-validator-supervisor/deploy/linux-validator-supervisor/install.sh \
  --config "$canonical_config" \
  --bootstrap-result-upload-key "$bootstrap_result_upload_key" \
  --legacy-unit "$legacy_unit"
```

In legacy mode the installer creates the service account and private state paths,
verifies the new configuration and initial hold, then disables and stops the exact
old service and permanently masks it. A locally defined unit at
`/etc/systemd/system/UNIT` is moved into the root-only
`/var/lib/umi-validator-retired-units` archive before the `/dev/null` mask is
created. The wallet and old checkout are not deleted.

In either mode the installer then enables the permanent supervisor. Before
reporting success, it requires the daemon singleton lock, no managed worker
container, and a durably accepted signed `hold` directive for five consecutive
checks. The daemon obtains a fresh owned-finality result again during that
reconciliation and writes a receipt whose nonce must match the live lock holder;
it does not rely on the installer's earlier preflight observation. This bounded
readiness check may take up to three minutes while the owned finality verifier
connects.

It will not unmask or restart the legacy writer if the new service fails. Inspect
the new unit and correct its configuration while the old writer remains retired.

## 5. Verify the one-time migration

```sh
sudo systemctl is-active --quiet umi-validator-supervisor.service
sudo systemctl --no-pager --full status umi-validator-supervisor.service
sudo journalctl -u umi-validator-supervisor.service -n 100 --no-pager
```

For a legacy installation, also verify the retired unit:

```sh
test "$(systemctl is-enabled "$legacy_unit" 2>/dev/null || :)" = masked
if systemctl is-active --quiet "$legacy_unit"; then exit 1; fi
```

Post only the supervisor's bounded public enrollment or status receipt when the
migration notice asks for it. Do not post the configuration, wallet tree, process
list, unit file, retired-unit archive, journal, or environment.

After an applied bootstrap row, the worker publishes its signed terminal result
automatically and verifies the public bytes. A failed upload cannot cause another
chain submission: the durable completed journal is recovered first and only the
publication is retried. The operator does not need to send receipts or upload an
evidence bundle manually.

UMI will independently watch finalized chain state. The first bootstrap commit
remains blocked until all old pending entries are absent and old rows are inactive.
After that checkpoint, a signed directive can assign this host to an allowed
implemented mode. Operators do not need to pull a branch or restart the old
validator.

## Operations

Check bounded service state:

```sh
sudo systemctl is-active umi-validator-supervisor.service
sudo systemctl --no-pager --full status umi-validator-supervisor.service
sudo -u umi-validator env -i \
  HOME=/var/lib/umi-validator-supervisor/home \
  XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
  XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
  XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
  LOGNAME=umi-validator \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONUTF8=1 \
  USER=umi-validator \
  /opt/umi-validator-supervisor/.venv/bin/umi-validator-supervisor \
  status --config /etc/umi/validator-supervisor.json
```

Monitor the residual unbounded disk consumers without deleting active evidence:

```sh
df -h /var/lib/umi-validator-supervisor /var/lib/umi-validator-worker-state
sudo du -sh \
  /var/lib/umi-validator-supervisor/container-data \
  /var/lib/umi-validator-supervisor/releases \
  /var/lib/umi-validator-worker-state
sudo -u umi-validator env -i \
  HOME=/var/lib/umi-validator-supervisor/home \
  XDG_CONFIG_HOME=/var/lib/umi-validator-supervisor/container-config \
  XDG_DATA_HOME=/var/lib/umi-validator-supervisor/container-data \
  XDG_RUNTIME_DIR=/run/umi-validator-supervisor \
  LOGNAME=umi-validator \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  USER=umi-validator \
  /usr/bin/podman system df
```

Do not run an indiscriminate image prune or delete worker-state records. Remove an
old image or release only after the public retention record says no accepted
directive or unresolved chain operation references it.

Restarting the supervisor is fail-closed. Its first reconciliation stops the
exact managed container, establishes `hold`, and returns `restart_fence` without
fetching a directive. A later poll repeats signature, finality, release, and
preflight checks before it may resume the persisted assignment:

```sh
sudo systemctl restart umi-validator-supervisor.service
```

Do not delete its state, replace the release authority, lower its sequence, edit
an accepted release, or restore the masked unit. Host replacement, wallet
replacement, authority rotation, or a newly approved mode changes the one-time
trust decision and requires an explicit local migration.

## Release-authority publication procedure

This is release-authority work, not a validator-host command sequence. Never copy
an authority wallet to a validator. All source JSON must be converted to RFC 8785
form with `jq -cSj .` before it is passed to the pinned CLI. Output paths must not
already exist.

For a worker release, start with this complete
`umi-validator-supervisor-release-manifest/1` source shape:

```json
{
  "schema": "umi-validator-supervisor-release-manifest/1",
  "oci_repository": "ghcr.io/umi-bitsign/umi-validator",
  "oci_manifest_sha256": "64-lowercase-hex-without-sha256-prefix",
  "oci_archive_sha256": "64-lowercase-hex",
  "oci_archive_size_bytes": 123456,
  "target_platform": "linux/amd64",
  "umi_git_revision": "40-lowercase-hex",
  "umi_source_tree_sha256": "64-lowercase-hex",
  "entrypoint_profile": "umi-bootstrap-weight-validator/2",
  "state_schema_minimum": 1,
  "state_schema_maximum": 1
}
```

The entrypoint profile must be `umi-live-shadow-validator/1`,
`umi-bootstrap-weight-validator/2`, or `umi-translation-validator/1` for its
corresponding mode. Derive the archive digest and size from the final OCI archive,
and derive the UMI tree digest from the exact pinned environment:

```sh
sha256sum image.oci.tar
stat -c '%s' image.oci.tar
/opt/umi-validator-supervisor/.venv/bin/python -c \
  'from umi.policy import umi_source_tree_sha256; print(umi_source_tree_sha256())'
jq -cSj . release-manifest.source.json >release-manifest.json
```

One release signer frames the manifest, detached signature, and OCI archive into
the bounded bundle and writes the exact `SupervisorReleaseTarget` object used by a
directive:

```sh
supervisor_cli=/opt/umi-validator-supervisor/.venv/bin/umi-validator-supervisor
"$supervisor_cli" build-release-bundle \
  --manifest release-manifest.json \
  --oci-archive image.oci.tar \
  --release-bundle-url https://REPLACE_WITH_ALLOWED_ORIGIN/path/release.bundle \
  --wallet-path /secure/authority-wallets \
  --wallet-name REPLACE_WITH_AUTHORITY_WALLET \
  --wallet-hotkey REPLACE_WITH_RELEASE_HOTKEY_NAME \
  --expected-hotkey REPLACE_WITH_RELEASE_HOTKEY_SS58 \
  --output release.bundle \
  --target-output release-target.json
```

The release bundle URL must use an origin in every target validator's
`release_origins`. Publish the bundle bytes unchanged. Do not hand-edit
`release-target.json`.

For bootstrap mode, build one canonical input bundle from the four reviewed
records. The command validates each typed record and its cross-bindings, then
writes the exact `SupervisorOperatorInputTarget` object used by the directive:

```sh
"$supervisor_cli" build-bootstrap-input-bundle \
  --signed-manifest signed-manifest.json \
  --authorization direct-transition-authorization.json \
  --drain-checkpoint drain-checkpoint.json \
  --owner-fence-receipt owner-fence-receipt.json \
  --bundle-url https://REPLACE_WITH_ALLOWED_ORIGIN/path/bootstrap-inputs.json \
  --output bootstrap-inputs.json \
  --target-output bootstrap-input-target.json
```

Publish `bootstrap-inputs.json` unchanged. The validator downloads it once per
directive, verifies the signed URL, size, and SHA-256 binding, and materializes
the four canonical files beneath that directive's immutable staging directory.
The operator does not copy or replace bootstrap files after installation.

Create sequence 1 as a hold. This is the complete directive source shape; replace
the values, AccountId32-sort `validator_hotkeys`, then canonicalize it:

```json
{
  "schema": "umi-validator-supervisor-directive/2",
  "channel_id": "64-lowercase-hex",
  "sequence": 1,
  "previous_directive_sha256": null,
  "issued_at_block": 1,
  "valid_from_block": 1,
  "valid_through_block": 2,
  "network": "finney",
  "netuid": 78,
  "mechanism_id": 0,
  "mode": "hold",
  "validator_hotkeys": ["validator-ss58"],
  "policy_sha256": null,
  "release": null,
  "operator_inputs": null
}
```

For a worker directive, increment `sequence`, set
`previous_directive_sha256` to the prior assembled directive's hash, use current
ordered block bounds, set the approved non-hold mode and policy digest, and inject
the generated target without re-encoding it by hand:

```sh
jq -cSj . directive.source.json >directive.base.json
jq -cSj --slurpfile release release-target.json \
  --slurpfile inputs bootstrap-input-target.json \
  '.release = $release[0] | .operator_inputs = $inputs[0]' \
  directive.base.json >directive.json
```

Use the input-target injection only for `bootstrap_service_weights`. Set
`operator_inputs` to null for every other mode.

For a hold, canonicalize the source directly. Each participating configured
directive authority signs the same canonical bytes on its own host. The signature
output has the exact `SupervisorDirectiveSignature` fields `hotkey`,
`signature_scheme`, and `signature`:

```sh
"$supervisor_cli" sign-directive \
  --directive directive.json \
  --wallet-path /secure/authority-wallets \
  --wallet-name REPLACE_WITH_AUTHORITY_WALLET \
  --wallet-hotkey REPLACE_WITH_AUTHORITY_HOTKEY_NAME \
  --expected-hotkey REPLACE_WITH_AUTHORITY_HOTKEY_SS58 \
  --output authority.signature.json

"$supervisor_cli" assemble-directive \
  --directive directive.json \
  --signature authority.signature.json \
  --output signed-directive.json
```

Repeat `--signature FILE` for every participating authority. The assembler sorts
them by AccountId32 and produces the canonical
`umi-validator-supervisor-signed-directive/2` object. Use at least the configured
threshold and publish only after every target validator's local trust policy is
confirmed.

The configured `directive_url` is a base, not an object URL. Consumers request:

```text
${directive_url}/after/${after_sequence}/${cursor}.json
```

`cursor` is `initial` only for sequence 0 with no prior digest; otherwise it is the
lowercase 64-character prior directive hash. Build pages with the checked CLI, not
manual JSON. Pass the exact canonical target-validator configuration; this checks
the signatures, threshold, channel, validator, mode, release, and local allowlists
without probing the authority workstation's host paths. The initial install page
contains exactly sequence 1 and omits the `--more` option, which encodes `more` as
false:

```sh
"$supervisor_cli" assemble-directive-page \
  --config validator-supervisor.json \
  --after-sequence 0 \
  --directive signed-directive-1.json \
  --output after-0-initial.json
```

A later nonempty page names its prior cursor and one to 64 contiguous signed
directives. Add `--more` only when another page is required. A caught-up empty page
uses `--head` to repeat the signed directive matching the cursor:

```sh
"$supervisor_cli" assemble-directive-page \
  --config validator-supervisor.json \
  --after-sequence "$prior_sequence" \
  --after-directive-sha256 "$prior_hash" \
  --directive signed-directive-next.json \
  --output directive-page.json

"$supervisor_cli" assemble-directive-page \
  --config validator-supervisor.json \
  --after-sequence "$head_sequence" \
  --after-directive-sha256 "$head_hash" \
  --head signed-directive-head.json \
  --output caught-up-page.json
```

Publish each canonical page at its exact cursor path with no redirect, query,
authentication credential, compression transform, or intermediary cache. The page
limit is 1 MiB. Preserve every signed directive, but treat cursor responses as
dynamic views of that append-only log. When a newer directive is published,
atomically regenerate every affected earlier cursor response so it either reaches
the latest current terminal head or sets `more: true` and leads through contiguous
pages to that head. A previously terminal `more: false` response must not remain
cached until its head expires, because an offline validator at that cursor would
be unable to persist the expired terminal entry and advance to the next cursor.

The special `/after/0/initial.json` response must remain exactly the current,
sequence-1 hold required by `preflight-initial-hold` while initial enrollment is
open. The sequence-2 cursor page may already exist, so a new installation can
accept the hold and advance on its first normal poll. A validator that cannot
verify and persist sequence 1 needs a separate reviewed state-bootstrap procedure;
it must not synthesize or skip the first directive.

For the production observer route, stage pages on the same filesystem as
`/srv/www/umi-validator-directives`, set every page to `root:root` mode `0444`, and
rename it into the exact route only after its canonical byte length and SHA-256
match the release record. Direct writes into a live route are forbidden. In
addition to `/after/0/initial.json`, install the caught-up page at
`/after/1/<initial-directive-sha256>.json`; readiness begins at that cursor and
walks every `more: true` page to a terminal signed head. Install the canonical
public feed config as
`/etc/umi/observer-validator-directive-feed.json`, owned by `root:root` at mode
`0444`, and start the observer with:

```sh
--directive-feed-config /etc/umi/observer-validator-directive-feed.json
```

The production loader accepts only root-owned config, directory, and page paths
with no group or world write bit. The observer service account therefore cannot
alter its own directive feed. The observer refuses to start unless the config and
every configured initial page exist, each initial page matches its pinned hashes,
is a single sequence-1 hold, and passes threshold-signature and validator-channel
verification. It also walks the live cursor chain from sequence 1 to a terminal
page and requires the configured minimum readiness head to be reachable. It repeats
file, canonicalization, signature, hash, and route-binding checks on every GET or
HEAD. `/readyz` rereads the startup-pinned config, every initial page, and every
reachable current cursor page. Public reads and readiness use separate bounded
gates with five- and thirty-second watchdogs respectively. A timed-out worker keeps
its slot until its thread exits; saturation, timeout, drift, and verification
failure return 503. The public service never loads an authority wallet and cannot
create or sign a directive.

The current VPS observer starts through a systemd override that does not repeat
every optional CLI argument. The CLI reads
`UMI_OBSERVER_DIRECTIVE_FEED_CONFIG` when the explicit option is absent. Install and
verify the new immutable observer release before changing that environment or
installing the drop-in. Run these commands as `sam` from a directory outside the
repository:

```sh
set -euo pipefail
observer_revision=REPLACE_WITH_40_CHARACTER_OBSERVER_REVISION
observer_checkout="/home/sam/umi-observer-source-${observer_revision}"
observer_release="/opt/umi-observer-releases/${observer_revision}"
[[ "${observer_revision}" =~ ^[0-9a-f]{40}$ ]]
test ! -e "${observer_checkout}" && test ! -e "${observer_release}"
test "$(/usr/local/bin/uv --version)" = "uv 0.12.9"
git clone --no-checkout git@github.com:Umi-BitSign/umi.git "${observer_checkout}"
git -C "${observer_checkout}" checkout --detach "${observer_revision}"
test "$(git -C "${observer_checkout}" rev-parse HEAD)" = "${observer_revision}"
test -z "$(git -C "${observer_checkout}" status --porcelain=v1 --untracked-files=all)"
observer_base_python="$(/opt/umi-observer/.venv/bin/python -c \
  'import sys; print(sys._base_executable)')"
test -x "${observer_base_python}"
sudo install -d -o root -g root -m 0755 /opt/umi-observer-releases
sudo mv "${observer_checkout}" "${observer_release}"
sudo chown -R root:root "${observer_release}"
sudo env UV_PROJECT_ENVIRONMENT="${observer_release}/.venv" \
  /usr/local/bin/uv sync --project "${observer_release}" \
    --python "${observer_base_python}" --locked --no-dev --no-editable
sudo chown -R root:root "${observer_release}"
sudo chmod -R go-w "${observer_release}"
test "$(sudo git -C "${observer_release}" rev-parse HEAD)" = "${observer_revision}"
test -z "$(sudo git -C "${observer_release}" status --porcelain=v1 --untracked-files=all)"
test -z "$(sudo find "${observer_release}" -xdev ! -type l \
  \( ! -user root -o -perm /022 \) -print -quit)"
sudo "${observer_release}/.venv/bin/python" -c \
  'import umi.observer, umi.observer_directive_feed'
sudo "${observer_release}/.venv/bin/python" -m umi.observer --help | \
  grep -Fq -- '--directive-feed-config'
observer_link="/opt/.umi-observer-${observer_revision}"
test ! -e "${observer_link}" && test ! -L "${observer_link}"
sudo ln -s "${observer_release}" "${observer_link}"
sudo mv -Tf "${observer_link}" /opt/umi-observer
test "$(readlink -f /opt/umi-observer)" = "${observer_release}"
/opt/umi-observer/.venv/bin/python -c \
  'import umi.observer, umi.observer_directive_feed'
/opt/umi-observer/.venv/bin/python -m umi.observer --help | \
  grep -Fq -- '--directive-feed-config'
```

Do not proceed if either import, help check, revision check, or ownership check
fails. After those checks pass, install the environment value and read-only
drop-in, then restart:

```sh
set -euo pipefail
sudo grep -q '^UMI_OBSERVER_DIRECTIVE_FEED_CONFIG=' /etc/umi/umi-observer.env || \
  printf '%s\n' \
    'UMI_OBSERVER_DIRECTIVE_FEED_CONFIG=/etc/umi/observer-validator-directive-feed.json' | \
    sudo tee -a /etc/umi/umi-observer.env >/dev/null
sudo sed -i \
  's#^UMI_OBSERVER_DIRECTIVE_FEED_CONFIG=.*#UMI_OBSERVER_DIRECTIVE_FEED_CONFIG=/etc/umi/observer-validator-directive-feed.json#' \
  /etc/umi/umi-observer.env
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/umi-observer.service.d
sudo install -o root -g root -m 0644 \
  /opt/umi-observer/deploy/public-pilot-automation/systemd/umi-observer-validator-directives.conf \
  /etc/systemd/system/umi-observer.service.d/40-validator-directives-read-only.conf
sudo systemctl daemon-reload
sudo systemctl restart umi-observer.service
test "$(systemctl show umi-observer.service -p ProtectSystem --value)" = strict
systemctl show umi-observer.service -p ReadOnlyPaths --value | \
  grep -Fq '/srv/www/umi-validator-directives'
```

At the Cloudflare zone, add a cache-bypass rule for
`/api/v1/validator-directives/*` and exclude that path from compression, HTML,
header, and body transformation rules. Keep the existing Tunnel origin. Apply a
rate limit to that path and `/readyz` that permits the documented polling cadence
while rejecting sustained public abuse. No Worker, KV, D1, R2, or new secret is
involved.

Before treating the edge as ready, use
[Cloudflare Trace](https://developers.cloudflare.com/rules/trace-request/how-to/)
in the Cloudflare dashboard for a `GET` of the exact initial-page URL with
`Accept-Encoding: identity`. Select **All configurations** and export the trace
JSON. Review the evaluated and executed steps and require all of the following:

- the enabled path-specific bypass rule executes in `http_request_cache_settings`;
- no later cache rule, Page Rule, or Worker makes the response cache-eligible;
- no response-compression, configuration, body, or response-header transform
  executes for the path;
- the intended enabled rate-limit rule matches both the directive path and a
  separate `/readyz` trace, with thresholds that permit the polling interval; and
- no unexpected account-level rule overrides the zone result.

Archive both trace exports with the release record and repeat them after any
Cloudflare ruleset change. Trace is a configuration simulation, so retain the live
byte/header probe below as the independent behavior check. Conversely,
`CF-Cache-Status: DYNAMIC` or `BYPASS` from one live response is not ruleset
evidence: Cloudflare documents that `DYNAMIC` can also mean default ineligibility
or Development Mode, while `BYPASS` can result from origin response headers alone.
The current read-only Rulesets API can also archive each relevant phase through
`GET /zones/{zone_id}/rulesets/phases/{ruleset_phase}/entrypoint`; do not use the
corresponding `PUT` operation during verification. See the
[Rulesets phase API](https://developers.cloudflare.com/api/resources/rulesets/subresources/phases/methods/get/)
and [cache-status troubleshooting](https://developers.cloudflare.com/cache/troubleshooting/investigating-uncached-responses/).

Verify the exact initial page through the public edge. Copy the expected hashes
from the signed release record, not from the HTTP response:

```sh
set -euo pipefail
UMI_DIRECTIVE_ACCOUNT=REPLACE_WITH_VALIDATOR_ACCOUNT_ID32
UMI_INITIAL_PAGE_SHA256=REPLACE_WITH_64_CHARACTER_INITIAL_PAGE_SHA256
UMI_INITIAL_HEAD_SHA256=REPLACE_WITH_64_CHARACTER_INITIAL_DIRECTIVE_SHA256
UMI_DIRECTIVE_PROBE="$(mktemp -d)"
cleanup_umi_directive_probe() {
  rm -f -- "${UMI_DIRECTIVE_PROBE}/headers" "${UMI_DIRECTIVE_PROBE}/body"
  rmdir -- "${UMI_DIRECTIVE_PROBE}"
}
trap cleanup_umi_directive_probe EXIT
UMI_INITIAL_URL="https://api.umi.vision/api/v1/validator-directives/${UMI_DIRECTIVE_ACCOUNT}/after/0/initial.json"
status="$(curl --silent --show-error --raw --max-redirs 0 --proto '=https' \
  --tlsv1.2 --header 'Accept-Encoding: identity' \
  --header 'Cache-Control: no-cache, no-store' \
  --dump-header "${UMI_DIRECTIVE_PROBE}/headers" \
  --output "${UMI_DIRECTIVE_PROBE}/body" \
  --write-out '%{http_code}' "${UMI_INITIAL_URL}")"
test "${status}" = 200
/opt/umi-observer/.venv/bin/python \
  /opt/umi-observer/deploy/first-public-result/check-directive-route.py \
  --headers "${UMI_DIRECTIVE_PROBE}/headers" \
  --body "${UMI_DIRECTIVE_PROBE}/body" \
  --expected-page-sha256 "${UMI_INITIAL_PAGE_SHA256}" \
  --expected-head-sha256 "${UMI_INITIAL_HEAD_SHA256}" \
  --expected-sequence 1 \
  --require-cloudflare-edge
curl --fail --silent --show-error --max-redirs 0 \
  https://api.umi.vision/readyz >/dev/null
```

The checker rejects redirects, a transformed body, a wrong body or declared hash,
compression, missing no-cache/no-store/no-transform controls, cached Cloudflare
responses, and mismatched head or sequence headers. An absent `Content-Encoding`
also means identity. Configure an external monitor to request `/readyz` at least
once per minute and alert on any non-200 response. Because readiness revalidates
the pinned config, all initial pages, and every cursor page needed to reach a
terminal signed head, later removal, permission drift, malformed JSON, signature
failure, unreachable configured head, hash mismatch, or read timeout becomes an
alert instead of remaining a route-only failure.
