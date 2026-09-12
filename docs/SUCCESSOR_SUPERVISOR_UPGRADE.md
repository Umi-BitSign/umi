# Successor supervisor upgrade requirements

Status: implementation requirements. No upgrade procedure or successor release
is approved by this document. Keep UID 0 and UID 54 on their existing bootstrap
policy until an authorized transition, subject to its hard sunset.

## Available read-only inspection

`competition_upgrade.inspect_successor_upgrade` checks installed configuration,
the exact retained signed directive and high-water binding, extracted release
bytes and an optional staged next directive under unchanged trust. It does not
read a wallet, open worker journals, stop a service or authorize an upgrade.

```sh
umi-competition --policy successor-policy.json inspect-host-upgrade \
  --config /ABSOLUTE/PRIVATE/supervisor.json \
  --accepted-directive accepted-signed-directive.json \
  --expected-hotkey PUBLIC_VALIDATOR_HOTKEY \
  --expected-platform linux/arm64 --service-uid NUMERIC_SERVICE_UID
```

Use the actual platform and service UID. Add
`--staged-directory /ABSOLUTE/PRIVATE/STAGED_RELEASE` for a staged artifact check.
The original signed configuration still determines the installed policy binding;
the command's successor policy does not replace it. The result always reports
`readiness: hold` and lists checks still requiring a real upgrade procedure.
Contract fixtures cover both architectures; they are not Linux sandbox rehearsals.

## Implemented components, not an installation procedure

The successor has separate signed v4 directives for `competition_replay` and
`competition_weights`. The first v4 record extends the exact retained v3 record;
it does not reset or reinterpret the existing high-water mark. The weight profile
also requires a separately signed generic authorization and a verified local
recovery checkpoint. These components do not activate a live policy.

The fixed `umi-competition-worker` command accepts only those two mode names.
Replay has no wallet or chain adapter. The weight path obtains owned finalized
observations before loading the named hotkey, persists exact signed transaction
bytes before broadcast, and holds uncertain effects across restart. The CLI's
fixed mount paths are enforced by `competition_container`. Its Podman adapter
checks the signed image identity, runs an inert resource/isolation probe, and
requires the exact container's kernel cgroup to be empty before stop or removal
completes. A completed container is not treated as proof that weights applied.

The isolated arm64 rehearsal has built this image and passed its signed-archive
loading and inert sandbox test with a development key. That test did not run a
settlement worker, use a wallet, or exercise the complete host upgrade.

`competition_host_artifacts` verifies a separately signed replacement host tree
at `/opt/umi-validator-supervisor-hosts/<revision>`. The manifest covers source,
dependencies, the regular copied interpreter and fixed entrypoint. It rejects
unsigned entries, symlinks, writable files and non-root ownership. Every parent
directory must also remain root-owned and not group/world-writable. This verifies
staged bytes only; it does not prove a sandbox rehearsal or authorize a service stop.

`competition_host_bundle` stages those bytes without executing them. Its bounded
format is a fixed magic header followed by each signed manifest file in order;
the signed manifest supplies every path, length, hash and mode. The stager
checks the complete tree before a no-replace rename into the fixed revision
directory. An exact existing tree is verified and reused. Failed stages remain
for inspection and consume one of eight staging slots. This component does not
download, build, sign, switch or start a release. The isolated arm64 root-file
rehearsal passed nine filesystem cases and seven metadata checks; amd64 was not
rehearsed there.

`competition_release` verifies the successor OCI bundle under a separate signature
domain. It binds the installed authority, allowed repository/origin, architecture,
source revision, fixed worker profile, state schema and exact archive bytes. It
extracts only into an empty private content-addressed stage; no tar entries are
interpreted and no existing file is replaced. Interrupted staging remains
unverified. The host adapter must enforce cache quotas and verify the loaded image
digest before execution.

The stopped-host lease and recovery checkpoint preserve the old process lock,
directive, journal, claims and supporting bytes. Incomplete or uncertain effects
remain on hold. Source authentication, stopped recovery, local operator consent,
fresh chain checks and actual sandbox execution are separate acceptance checks.
The production source switch and both-architecture rehearsal are still required.

`competition_upgrade_namespace` prepares the recovery observer's fixed helper
paths in a fresh root process's private Linux mount namespace. It disables mount
propagation before installing any overlay, checks the signed host tree again,
binds its helpers read-only, and binds a separate root-private finality cache.
The stopped observer still verifies consent, signatures and installation identity
before running a helper. Namespace setup alone grants no service-stop or signing
permission. It must run before threads start, once per process; after a partial
setup failure, exit that process. Existing host mount contents are preserved.
Only empty `/opt/umi` and `/var/lib/umi-competition` placeholders may be created
on the host if those directories did not exist. Never use this as a replacement
for the coordinator's separate RootDirectory service adapter.

The wallet-free arm64 test host passed nine real-mount cases, including
read-only helpers, writable private cache, invalid sources, partial setup failure
process death and a source replaced during namespace creation. The first run
caught descriptors still referring to mounts
in the old namespace. Setup now reopens them after unsharing and requires the
same inode and permissions before binding them. The operator's initial
prepare/stop/checkpoint/switch/start command is still incomplete.

The fixed `umi-competition-supervisor` entrypoint now connects the authenticated
root anchor, owned chain observer, bounded HTTPS delivery, atomic input selection
and durable runtime. Startup takes the original process lock before repairing an
interrupted input switch and passes that same descriptor to the runtime. The
runtime journal lives in `successor-v4/runtime`, separately from download and
input caches. It will not reinterpret a journal left at an older unshipped path.

`competition_host_service` renders the exact systemd override. The separate
`competition_host_switch` publisher writes it without replacement and reloads
the still-stopped unit while holding the old lock. Its first write consumes
legacy recovery authority. A failed or partial switch is retained for explicit
recovery; it does not restore the old executable or start either version.
Before any companion bytes are written, the publisher atomically installs the
main unit's drop-in directory containing a complete root-owned switch intent.
The intent binds the original unit, lock inode, config, recovery anchor and
signed replacement host. Legacy recovery rejects that directory even before
systemd has loaded a file. Failed staging directories are retained and bounded.

The development command can resume that recorded switch:

```sh
sudo umi-competition-host-upgrade resume-publication \
  --config /etc/umi/validator-supervisor.json \
  --unit umi-validator-supervisor.service
```

This completes exact file publication and reloads the still-stopped unit. It
retains incomplete files without interpreting them, rejects changed controls
or legacy history, and leaves existing v4 journals untouched. It does not
reconstruct a legacy lease or grant checkpoint authority. A missing intent is
a hold, not permission to guess or overwrite the old installation.

`resume-start` performs the same checks, releases the recovery process lock,
then starts only the recorded successor. It verifies the main process's kernel
flock on the original inode. Failed startup invokes the exact cleanup unit;
an error report leaves service state unconfirmed, requiring inspection. Both
commands reject a running service and unsupported filesystem namespaces.
Neither command grants weight authorization or creates missing launch inputs.

Both operator commands retain a separate root-owned, per-unit upgrade mutex
through publication, writer-lock handoff, startup verification and any failed
start cleanup. A concurrent command fails before touching the service. The
empty mutex inode remains after release so another process cannot acquire a
replacement lock. Initial preparation must use this same mutex; the lower-level
planning and capability functions are not independent operator commands.

These commands cover a retained generic systemd switch. Initial privileged
preparation and the coordinator's RootDirectory installations still require
integration and full service rehearsal before deployment approval.

The successor uses a dedicated user systemd manager for rootless Podman.
`umi-competition-supervisor-cleanup` acquires the original lock and stops only
the exact labelled successor container. Noninteractive startup and SIGKILL
cleanup passed on Linux after exposing only the service user's runtime
directory. The same test found that `ExecStopPost`, even with the `+` prefix,
cannot run when an explicit activation bind mount fails on systemd 255.
A separate, mount-free failure-cleanup unit passed that test with automatic
restart enabled; the publisher now seals and verifies both unit files. A cold
user-namespace check then exposed a Podman manager-detection difference. The
adapter now explicitly selects systemd. The actual cold-start service test
passed with this fixed command, kernel resource checks and the cleanup paths.
It used synthetic inputs and an inert launcher. The complete migration is not
ready for deployment.

## Why an image update is insufficient

The installed host enforces these contracts before starting a worker:

- `SupervisorOperatorInputTarget` accepts only the two bootstrap input profiles.
  `SupervisorDirective` rejects operator inputs for `translation_weights`.
- `SupervisorWorkerActivation` repeats that restriction. The durable
  `SupervisorDirectiveState` requires an input digest exactly for bootstrap mode.
- The adapter parses and stages only bootstrap bundles. Other modes receive
  the existing local operator-input directory, not a successor settlement.
- The checked-in worker CLI rejects non-bootstrap execution with
  `worker_mode_unimplemented`. A permitted mode name does not implement its worker.

See [host contracts](../src/umi/validator_supervisor.py),
[runtime](../src/umi/validator_supervisor_runtime.py),
[adapter](../src/umi/validator_supervisor_adapters.py), and
[worker](../src/umi/validator_supervisor_worker.py).

The [current installer](../deploy/linux-validator-supervisor/install.sh) refuses
an existing supervisor tree, config, service or loaded unit. It also refuses
`--legacy-unit umi-validator-supervisor.service`. Rerunning it is not a supported
upgrade. Do not delete those paths to bypass its checks.

## Required implementation

Define the signed successor input contract first. Bind the policy, immutable
settlement, authority, activation interval, target chain and release profile.
Retain the settlement's no-weight status; a separately verified authorization
must permit chain submission. Do not relabel successor data as bootstrap input.

Update the host schemas, activation validation, immutable input staging and
fixed worker dispatch together. Preserve parsing and exact hashes of historical
signed directives. If schemas or signing domains change, implement an explicit
versioned transition. Preserve sequence, predecessor digest, finalized-block
high-water and accepted input identity. Never reset state to sequence zero.

Implement the successor worker and its durable transaction recovery separately.
Preserve all bootstrap journals and reconcile uncertain prior submissions before
another write. A directory shared across versions is insufficient unless the
new worker understands the relevant outstanding-effect records.

The common bootstrap profile runs `umi-simple-bootstrap-validator` and retains
`SimpleBootstrapJournal` in `journal.json`, with `service.lock`, under the worker
state root. Its unknown phases cover both manifest anchors and weight calls.
The older explicit-hotkey worker uses `SupervisorWorkerJournal` under
`bootstrap-transactions/<directive>/` and global claims under
`bootstrap-authorizations/`. Migration must account for both layouts.

Both live recovery paths check authorization at the current block. The common
service also exits at hard sunset before reconciling its journal. Add a
historical recovery wrapper that validates the original bindings without
granting permission for new work under an expired authorization.

For the common journal, retain its anchor and weight phases and use fresh owned
finalized observations to classify any unfinished attempt. Validate the frozen
submission/mortality assumptions before accepting an absence classification.
For the explicit worker, a `prepared` record with a matching global claim means
an effect was intended. An `effect_intent` can recover to completion only when
the exact retained output artifacts pass the existing validation. Incomplete
inner journals, unmatched claims and ambiguous effects remain on hold; do not
call the old submit function to resolve them.

Require a versioned stopped-state recovery checkpoint before successor chain
activation. Bind the validator hotkey, directive high-water, original journal
and claim hashes, reconciled classifications and owned finalized block/hash.
Keep original bytes available for audit. The checkpoint establishes the prior
state; successor authorization and fresh chain preflight are separate checks.

The legacy host input bundle is capped at 16 MiB. Larger successor replay
artifacts need a separate versioned package with explicit per-object and total
limits. The current adapter also mounts the named hotkey for every worker mode.
A wallet-free rehearsal profile must omit that mount; a no-weight status field
alone does not isolate the wallet.

Add a dedicated operator-invoked host upgrade. It must:

1. Identify the existing installation and stage a reviewed, platform-matched
   host release without modifying the running source tree.
2. Verify signed artifacts, dependencies, configuration compatibility and the
   production sandbox before stopping the current service. Report the exact
   changes to locally delegated profiles or trust.
3. Stop the exact service and confirm its worker and delegated cgroup are empty.
   Take a consistent private backup of the state and configuration at this
   boundary. Do not request the coldkey or recopy wallet material.
4. Switch the verified host release while retaining the selected hotkey,
   service account, filesystem permissions, wallet binding, trust configuration,
   directive history, finality state and worker journals.
5. Verify the new process lock, restart reconciliation and bounded status before
   accepting successor work. Interrupted upgrades must have an explicit recovery
   path and must never start two writers for one hotkey.

Host rollback before any successor acceptance may resume the previous release
only if its directive and policy remain valid, state is compatible, and uncertain
transactions have been reconciled. After a newer directive is accepted or new
chain effects are possible, retain the high-water state and hold for an explicit
recovery transition. Never restore an old state backup to revive an old writer.

## Feed and platform coordination

An unsupported directive on the shared feed makes an older host fail closed.
The current runtime also stops its old worker when it accepts a newer directive,
even if the new directive's activation block is in the future. Publishing a
future directive therefore cannot be used as harmless pre-staging.

Stage artifacts first. Coordinate directive publication with the approved stop
and activation boundary. Any capability-specific feed needs an authenticated,
operator-consented transition that preserves history; changing a channel and
discarding its cursor is not sufficient.

Publish and verify separate `linux/amd64` and `linux/arm64` host artifacts and OCI
images. Both architectures need the same contract and migration tests. UID 0 and
UID 54 remain separate installations with separate hotkeys, state and service
lifecycles. Upgrade and verify one without stopping or changing the other.

## Acceptance checks

Rehearse with synthetic keys in isolated Linux installations before live use:

- Existing bootstrap directives and state reload unchanged; successor inputs
  cannot enter through a bootstrap profile or an unapproved local configuration.
- Wrong policy, settlement, authority, architecture, artifact digest or state
  version fails before activation; no arbitrary command or mount is introduced.
- A failed pre-stop check leaves the old service untouched. Failure after stop
  preserves recovery evidence and cannot silently restore an invalid writer.
- Kill or restart at each migration and submission boundary; verify journal
  recovery, monotonic history and at most one writer per hotkey.
- A stale or unsupported feed, insufficient activation headroom, lost permit,
  conflicting evidence or expired policy holds without writing.
- Exercise both supported architectures under the actual systemd/Podman sandbox,
  including resource enforcement and repeated restart cleanup.
- With two isolated installations, transition one and verify the other remains
  healthy with unchanged configuration, hotkey binding and journals.

These checks do not authorize activation. The complete
[successor release gates](../whitepaper/README.md#10-release-and-activation)
also require real evaluation evidence, finalized-chain preflight and an approved
signed transition. Bootstrap expiry still applies if successor work is delayed.
