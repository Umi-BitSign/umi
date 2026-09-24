[Documentation](../README.md) / Upgrade an installed validator

# Upgrade an installed validator

- [Successor supervisor upgrade requirements](#successor-supervisor-upgrade)

## Supervisor maintenance for an installed successor

A supervisor fix can retain the installed worker release, reward package,
signed directive history and original recovery journals. Stage the replacement
under its own revision and signed host manifest. A root-owned
`/etc/umi/validator-supervisor-maintenance.json` selects that host for the exact
configuration and installation receipt, using `umi-supervisor-host-maintenance/1`.
It contains their SHA-256 digests, the original host manifest digest and the new
signed host artifact. The replacement must satisfy the installed release authority.

After native stop/cleanup, select the new executable and read-only host mount in
the existing service. Startup verifies both the original activation controls and
the replacement's source/interpreter, and reports the effective host identity.
Retain the original host and controls while worker or recovery consumers use them.
Keep the maintenance approval while this executable is selected; remove it after
a later installed transition no longer depends on the original receipt.

The supervisor reuses immutable package verification within one process, checking
all file bytes and bounds on each load. Restart verifies the package again. Reward
authority and current chain state are checked separately for each execution.

<a id="successor-supervisor-upgrade"></a>

## Successor supervisor upgrade requirements

Status: implemented upgrade command with synthetic native Linux migration
coverage. This document does not approve production artifacts or a transition.
Keep UID 0 and UID 54 on their existing bridge policy until an authorized
transition, explicit replacement or revocation. The current ongoing bridge has
no scheduled sunset; historical finite bridge policies keep their original
cutoffs.

<a id="successor-supervisor-upgrade--available-read-only-inspection"></a>

### Available read-only inspection

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

<a id="successor-supervisor-upgrade--components-and-dedicated-upgrade-command"></a>

### Components and dedicated upgrade command

<a id="successor-supervisor-upgrade--rolling-directive-history"></a>

#### Rolling directive history

After installation, the runtime assembles the complete signed continuation from
its retained journal and the newly verified cursor page. Artifact delivery uses
those local bytes instead of fetching the selected directive's one-hop page.
The host still verifies every predecessor and signature against the original
root-sealed v4 installation anchor. No later directive can replace that anchor.

Network pages remain limited to 64 records and 1 MiB; the feed currently returns
batches of 16. Local continuations use `umi-validator-supervisor-directive-history/1`
when they exceed either network-page limit. They are bounded by 65,536 records
and 64 MiB, with the runtime's configured journal limits enforced separately.
Smaller continuations keep the existing page encoding. HTTP delivery cannot
substitute a different local continuation, including through its cache.

Thirteen focused tests passed on the Studio Linux VM, covering 68-update
catch-up, restart, host verification and HTTP delivery. They took 751.00 seconds.
The separate Linux exchange test exposed an old page parser in the anchor
reader. That reader and the target observer now accept the bounded local history;
their integrated rerun passed four cases in 357.99 seconds. The broader
adapter/materializer regression passed 102 tests in 3246.16 seconds before the
shared-registry change below. Synthetic test authority keys are reused within
each generated chain. No live validator was upgraded.

<a id="successor-supervisor-upgrade--shared-recovery-registry-history"></a>

#### Shared recovery-registry history

New `umi-successor-adapter-run/2` records keep a reference to content-addressed
signed history nodes in the same private SQLite registry. A later run reuses
identical prefixes. Its reference binds the original page schema, cursor,
selected head, count, byte length and hash. Registry loading checks every stored
node's checksum and predecessor links, including unreferenced nodes, and checks
each run's head and cursor without expanding all histories together. Accessing
one run reconstructs its exact original bytes and checks the page binding.
The existing authority and signature verification still applies before use.

Run metadata and new nodes are committed in one transaction. Both count toward
the configured byte budget. A full registry stops retention; it never deletes
evidence to make room. Existing inline `/1` records remain unchanged and readable.
Older binaries cannot read `/2` runs, so do not roll back a supervisor over a
registry written by this version.

Stopped recovery audits each retained run, then retains only authorization
identities between audits. It reconstructs the relevant history again when
reconciling an unsettled transaction. No attempt or recovery source is discarded.

The first shared-storage snapshot passed 11 focused tests in 245.98 seconds,
including lossless 68-record reconstruction, prefix storage growth, legacy
record preservation and atomic insertion failure. The expanded link-validation
suite passed 11 tests in 476.15 seconds, including missing nodes, broken links
with recomputed storage checksums, reference/head mismatches and depth bounds.
The recovery regression passed 45 tests in 1391.01 seconds. The registry still
has its configured byte and record limits. All 18 repository checks passed for
`1448bba`, including the complete Python suites and both Linux architectures.

<a id="successor-supervisor-upgrade--download-history-bindings"></a>

#### Download history bindings

Hosts co-located with a private delivery service can include
`artifacts/successor-delivery.json` in their signed host artifact. The canonical
file uses schema `umi-successor-cohost-delivery/1`, an exact `https://HOST` origin
matching the installed directive URL, a `loopback_port` from 1024 through 65535,
and a `timeout_seconds` bound no greater than 300. The operator consent pins
the host manifest, which pins this root-owned, read-only file. A host without
this signed file retains public HTTPS delivery. Worker inputs and observer
configuration schemas remain unchanged.

Only the selected origin connects to `127.0.0.1` over HTTP. Signed logical URLs,
object sizes, hashes, signatures, continuation checks and redirect rejection
remain enforced. Other origins still require public-address HTTPS. Bind the
private feed to loopback, including the exact selected release archive route;
do not publish protected evidence to a public bucket. This transport choice
does not extend a reward authorization or a round's validity.

When preparing initial history through the same local service, pass
`fetch-initial-successor-history --signed-host-artifact PATH`. The signed
manifest must match the consent, and its optional delivery file must match the
staged host. Omitting the option keeps public HTTPS. Initial-history collection
still does not authorize or perform a validator switch.

When the runtime supplies its retained continuation, delivery stores only
`history-binding.json`, a bounded hash/size/selected-head binding. The full signed
records remain in the runtime journal and recovery registry. Delivery verifies
the supplied history before fetching a package, and the host checks its exact
bytes against the original root-sealed anchor before activation. The binding
file cannot substitute for the history or grant authority.

An existing `history.json` from an earlier version is preserved and checked
against the supplied bytes on every refetch. A changed continuation for an
already cached head, corrupt binding or differing legacy file fails closed.
Older delivery binaries reject the new cache filename; rollback over these
cache entries is unsupported. The focused delivery regression passed five tests
in 264.03 seconds. Package/object capacity limits remain in effect.

<a id="successor-supervisor-upgrade--retiring-redundant-materialized-inputs"></a>

#### Retiring redundant materialized inputs

After stopping the worker and reconciling its transactions, the host retires
cached input trees only when their exact bytes are reconstructable from its
audited recovery registry and a separately retained, verified delivery package.
Current inputs, the original root anchor, signed histories, transaction journals
and delivery packages are preserved. Unstarted, unmatched and partial stages
are preserved too. An equivalent but byte-different history does not authorize
removal of the original copy.

A private `retiring-<directive digest>-<random id>` directory records the cleanup
intent. The host fsyncs that rename before unlinking. Following interruption, it
revalidates the retained source and every surviving cached file before resuming.
Missing recovery inputs, extra or changed files, links, and aliases of current
or recovery inputs stop cleanup. All traversal and accounting limits remain.
Only exact redundant cache copies are removed; they can be reconstructed from
the retained sources. Cleanup does not grant weight or activation authority.

The initial 11-test interruption and repeated-round suite passed on the Studio
in 346.11 seconds. Additional bounded-rescan and inode-alias checks, plus the
surrounding materializer/adapter regression, are running. Full checks must pass
before deployment. Older binaries do not recognize an interrupted `retiring-*`
entry; complete recovery with this version before attempting a rollback.

<a id="successor-supervisor-upgrade--initial-history-after-multiple-feed-pages"></a>

#### Initial history after multiple feed pages

An initial install can now retain the full signed v3-to-v4 history using the same
65,536-record and 64 MiB local-history bounds. The root receipt binds its exact
bytes and size. Both receipt loading and pre-stop checks verify every predecessor
and signature against the original v3 anchor. The current head must still pass
the stopped checkpoint's validity checks. A new history file does not reset an
installed validator's high-water state.

On Linux, collect an inert preparation file into an existing private directory
owned by the invoking user (mode `0700`):

```sh
umi-competition --policy successor-policy.json fetch-initial-successor-history \
  --config /ABSOLUTE/PRIVATE/supervisor.json \
  --accepted-directive /ABSOLUTE/PRIVATE/accepted-signed-directive.json \
  --consent /ABSOLUTE/PRIVATE/operator-consent.json \
  --current-block FINALIZED_PREPARATION_BLOCK \
  --output /ABSOLUTE/PRIVATE/initial-successor-directive-page.json
```

Use the consent and retained directive for that exact installed configuration.
The collector follows bounded HTTPS pages from the configured origin, rejects
changed cursors and bad signatures, and enforces a total timeout and byte/record
budgets. It writes a `0400` file through a no-replace rename. A failed publication
can leave a private `.partial` file for inspection; it never overwrites the
destination. The printed result includes the content hash and size.

The supplied block only bounds preparation. This command has no owned-finality
capability, cannot stop a service, and grants no upgrade or weight authority.
The root upgrade must still verify the sealed inputs, consent, recovery archive,
actual sandbox and fresh stopped-host observations.

Six Linux tests passed in 507.12 seconds, covering receipt sealing and restart,
anchor materialization, and initial pre-stop authentication with both one and 69
signed records. Their ownership/mount ports are synthetic; directory and signed
history operations execute on Linux. Eight collector tests passed in 427.93
seconds, covering five-page catch-up, wrong cursors, forged signatures, missing
pages, budgets, cancellation and wrong legacy binding. Four CLI publication and
total-deadline tests passed in 203.47 seconds. Production initial installation
remains unperformed.

<a id="successor-supervisor-upgrade--worker-and-host-components"></a>

#### Worker and host components

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

The release host tree must include the interpreter's standard library and
required runtime libraries, not only a copied virtual-environment executable.
A system-Python venv can pass on its Ubuntu build host while failing on Debian.
Bind `pyvenv.cfg`, entrypoint shebangs and package import paths to the final
revision directory, and include those bytes in the manifest. Verify imports and
both host CLI entrypoints as an unprivileged user on the supported platforms
before signing. Use a self-contained interpreter and verify it on both Ubuntu
and Debian for each supported architecture. Packaging checks do not authorize
installation or replace the signed host transition.

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
Both-architecture rooted preflight and lifecycle checks pass. The combined
signed initial-migration and interrupted-command rehearsal also passed on
amd64 and arm64 at `aaf7689`, with the fixture boundaries described below.

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
for the coordinator's separate RootDirectory service adapter. When that adapter
has established a verified private instance view, observer preparation reuses
its mount namespace once rather than discarding the existing aliases.

The wallet-free arm64 test host passed ten real-mount/filesystem cases, including
read-only helpers, writable private cache, invalid sources, partial setup failure,
process death and a source replaced during namespace creation. New placeholder
modes are explicit even under umask 077; existing directory modes stay unchanged.
The first run caught descriptors still referring to mounts in the old namespace.
Setup now reopens them after unsharing and requires the same inode and permissions
before binding them. CI uses dedicated root-owned fixture target paths and keeps
the production ownership checks enabled; the isolated VM tests the actual fixed
paths.

The development `umi-competition-host-upgrade upgrade` command now connects
generic host-namespace preparation, preflight, stop, checkpoint, publication
and start. It takes `--config`, `--unit`, `--controls`, `--host-bundle`,
`--oci-bundle`, `--recovery-root` and `--recovery-limits`; historical bootstrap
contexts can be supplied through `--historical-context`. All artifacts and
authorization controls must already be reviewed and signed. The command does
not fetch or create missing launch inputs.

An applied common-bootstrap journal requires its original signed manifest and
lease in that historical context, even when later bridge writes supersede its
weight row. The stopped observer requests the manifest commitment identified by
the authenticated retained effects and includes its proof in the final owned
chain observation. Missing context, absent or different commitments, and invalid
historical signatures keep recovery held. A snapshot requiring more than one
distinct historical manifest anchor is refused; the current observation format
proves one anchor. Historical authority never becomes current write permission.

Historical parsing can exceed the owned chain proof's freshness interval. The
upgrade therefore parses each locked snapshot before collecting its fresh proof,
once for archive preparation and again for verification. Within that snapshot
scope it reuses the authenticated bridge audit, checking original byte hashes,
file identities and parsed content before reuse. It still checks the current
installed policy, chain row and proof expiry on every acceptance. No historical
signature or current chain authority is inferred from a longer service timeout.

Its pre-stop child runs as the installed non-root account, verifies its complete
signed host tree and stages the signed OCI bundle before exercising the actual
Podman sandbox. The named wallet directory is inaccessible to that child.
Bounded progress records identify control, host, release and sandbox stages.
Wrong host resources, changed controls or a failed rehearsal leave the old
service running. If a failure happens after stop, the command preserves state
and does not restart the old writer.

Interrupted anchor writes are moved intact into root-private `retained-anchors`
beside `activation-source`, with eight retained slots and no overwrites.
Retrying requires fresh stopped-state reconciliation; a partial directory grants
no authorization. Unexpected entries or exhausted retention hold the operation.
Existing published anchors are checked before stopping the service and again
at the stopped acceptance boundary.

The signed-host/OCI preflight and root process-death retention test first passed
on the isolated arm64 VM. Native CI now also covers the combined initial migration
and interrupted-command recovery on both architectures. Production use still
requires reviewed release artifacts, approved activation inputs and a rehearsal
of the deployment-specific runtime and model. Do not use fixture keys, chain
observations or model bytes as those inputs.

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

Systemd can reload an inactive instance when queried, exposing the published
successor command before an explicit `daemon-reload`. At that boundary the
publisher accepts either the unchanged legacy snapshot or the exact published
successor, with no running processes and the original lock still held. It
verifies the published files and repeats the checks after the explicit reload.
Unexpected commands, identities or additional drop-ins remain errors.
The interrupted-publication recovery command applies the same check when it
finishes writing a previously missing drop-in.

After startup, systemd adds execution timestamps and a PID to `ExecStart`.
Startup verification compares the configured executable, arguments and
ignore-errors flag separately from those runtime fields. Unknown fields or
additional commands are rejected. The main PID, cgroup and ownership of the
original process lock are verified independently.

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

For the coordinator's exact `umi-validator@0.service` and
`umi-validator@54.service` names, these commands first prepare a process-private
view of that instance's preserved directories. Use the unchanged logical
`--config /etc/umi/validator-supervisor.json` path. Other template instances and
unreviewed RootDirectory layouts are rejected. The view neither stops a service
nor authorizes recovery. Running services still prevent stopped-state recovery.

The generated override retains the selected RootDirectory and slice, maps bind
sources to that instance's physical host directories, and mounts the signed
successor host tree inside the root at its original path. Cleanup uses the inner
`umi-validator` account while systemd retains the host-side instance account.
Its separate failure-cleanup unit has no activation-source bind dependency.
Neither operation changes the shared template or the other validator's roots.

Two real arm64 namespace tests passed with synthetic roots, including original
lock contention and cross-instance isolation. The extended tests prepare the
signed recovery observer in that same view. The CI-style arm64 batch passed
15 namespace and transient-service checks. The later
[native CI run at 8fe8483](https://github.com/Umi-BitSign/umi/actions/runs/34737773586)
passed the actual signed-host/OCI preflight in both roots and the two-instance
systemd/Podman lifecycle test on amd64 and arm64. The lifecycle test uses an
inert host launcher and synthetic capability issuers. It verifies kernel
resource limits, per-instance SIGKILL cleanup and restart, preservation of the
other instance, and teardown container absence. It does not execute the
complete signed initial migration or establish live chain authority.

The [combined migration run at aaf7689](https://github.com/Umi-BitSign/umi/actions/runs/34741778051)
passed on both architectures. It creates two distinct signed bridge installations,
performs the actual wallet-free signed-host/OCI preflight, archives and reconciles
their retained history, publishes their successor anchors and switches the units.
It interrupts the second command immediately after durable intent publication
and resumes in a fresh process. The first instance, both lock inodes, every
bridge-journal byte and both legacy high-water records remain intact.

The chain-observation port is synthetic. The started fixture entrypoint verifies
the real materialized anchor and holds the original process lock, but does not
run the production observation loop or submit weights. The separate lifecycle
test exercises actual Podman execution and cleanup. These results establish
the tested migration behavior; real model execution, independent evaluation and
production activation remain separate gates.

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
It used synthetic inputs and an inert launcher. No live deployment is authorized
by these test results.

<a id="successor-supervisor-upgrade--why-an-image-update-is-insufficient"></a>

### Why an image update is insufficient

The installed host enforces these contracts before starting a worker:

- `SupervisorOperatorInputTarget` accepts only the two bootstrap input profiles.
  `SupervisorDirective` rejects operator inputs for `translation_weights`.
- `SupervisorWorkerActivation` repeats that restriction. The durable
  `SupervisorDirectiveState` requires an input digest exactly for bootstrap mode.
- The adapter parses and stages only bootstrap bundles. Other modes receive
  the existing local operator-input directory, not a successor settlement.
- The checked-in worker CLI rejects non-bootstrap execution with
  `worker_mode_unimplemented`. A permitted mode name does not implement its worker.

See [host contracts](../../src/umi/validator_supervisor.py),
[runtime](../../src/umi/validator_supervisor_runtime.py),
[adapter](../../src/umi/validator_supervisor_adapters.py), and
[worker](../../src/umi/validator_supervisor_worker.py).

The [current installer](../../deploy/linux-validator-supervisor/install.sh) refuses
an existing supervisor tree, config, service or loaded unit. It also refuses
`--legacy-unit umi-validator-supervisor.service`. Rerunning it is not a supported
upgrade. Do not delete those paths to bypass its checks.

<a id="successor-supervisor-upgrade--required-implementation"></a>

### Required implementation

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

Both historical recovery paths check authorization at the current block. A
finite common-service policy also exits at its hard sunset before reconciling
its journal. Add a
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

<a id="successor-supervisor-upgrade--feed-and-platform-coordination"></a>

### Feed and platform coordination

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

### Authenticated RPC providers

Successor hosts can select an operational RPC route with the service environment
variable `UMI_RPC_TRANSPORT_CONFIG`, pointing to an absolute `transport.json` file.
This changes the connection destination without rewriting signed chain inputs or
retained transaction bindings. Native finality and storage proofs still decide
which returned values are accepted. The existing two backup providers remain in
the chain configuration and receive no primary-provider credentials.

```json
{
  "schema": "umi-rpc-transport/1",
  "routes": [{
    "source": "wss://archive.chain.opentensor.ai",
    "endpoint": "wss://api.taostats.io/api/v1/rpc/ws/finney_archive",
    "authorization_file": "taostats.key"
  }]
}
```

Store the key in the named file beside the configuration, with mode `0600` and
ownership by the service account. Use a dedicated directory containing only the
RPC configuration and its credentials. Neither URLs nor configuration JSON
contain the key. Keep both files outside Git and signed artifact trees. The host
mounts that directory read-only into each worker and passes only the configuration
path in its environment. Both proof reads and the pinned transaction transport
use the route; exact signed transaction bytes and recovery semantics are unchanged.

The provider receives an `Authorization` header. Authenticated connections do
not follow redirects or emit WebSocket debug logs. Route logs identify source,
destination and whether authentication is enabled, without credential contents.
An unavailable credential fails that provider's connection and permits the
existing transport fallback. An invalid route configuration requires correction.
Verify authenticated reads from the installed host and worker before claiming
the operational switch is complete.

<a id="successor-supervisor-upgrade--acceptance-checks"></a>

### Acceptance checks

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
[successor release gates](../../whitepaper/README.md#10-release-and-activation)
also require real evaluation evidence, finalized-chain preflight and an approved
signed transition. Historical finite bootstrap or policy expiry still applies
if successor work is delayed; this is separate from the current no-sunset
registration bridge.
