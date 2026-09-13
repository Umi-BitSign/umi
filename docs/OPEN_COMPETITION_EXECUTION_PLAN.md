# Open-competition execution plan

The approved launch runs both reward tracks together: 70% endpoint service and
30% for the current qualifying promoted model's contributor. The imported
baseline has no contributor attribution. Neither this plan nor local tests
activate rewards or extend the signed bootstrap sunset.

## Execution order and acceptance gates

1. Assignment scheduling and chain-bound endpoint checks.
   - Persist exact signed assignments and publication observations before work.
   - Retain late signed publications as expired coordinator evidence; refuse
     release or dispatch after the usable window. Never retime a signed case
     or assign coordinator expiry to miner fault.
   - Reconcile restart and uncertain dispatch without issuing duplicate work.
   - Verify the registered hotkey and announced public Axon from storage proofs
     under one owned finalized state root before connecting.
   - Integrate a bounded reference-free feed and evaluator dispatch. Independently
     witnessed publication timing and protected-suite reveal timing remain
     separate requirements from a local timestamp.
2. Signed cutoff and settlement publication.
   - Verify independent evaluator-group signatures and replay the complete
     retained evidence, roster, registration snapshot and promotion attribution.
   - Retain conflicting certificates across restart; local settlement alone
     must not grant chain-write permission.
   - Bind an explicit late-conflict recovery rule and publication observations.
3. Successor supervisor and host upgrade.
   - First run settlement replay through a fixed-command, wallet-free worker
     with bounded immutable inputs and durable receipts. Keep historical
     receipts separate from current conflict holds.
   - Define versioned successor input and activation contracts without changing
     historical signed bootstrap bytes or state high-water marks.
   - Implement the successor weight worker and reconcile uncertain bootstrap/successor
     transactions before any new chain write.
   - Add a dedicated verified host-upgrade path. Stage and verify before
     stopping the exact service; preserve its hotkey, state and journals.
   - Test failure, restart and recovery on Linux amd64 and arm64. An image update
     or rerun of the fresh installer is insufficient.
4. End-to-end rehearsal and deployment preparation.
   - Exercise intake, assignment publication, authenticated miner response,
     reference reveal, independent evaluation, promotion, settlement and upgrade
     using synthetic keys without live weights.
   - Rehearse the actual CPU image and sandbox with a real model, resource
     enforcement, timeouts and interruption cleanup.
   - Verify HTTPS ingress limits, evidence retention, filesystem quotas and
     archive backup/restore before exposing enrollment.
5. Reviewed inputs and independent evaluation.
   - Supply protected evaluation data and provenance, contribution terms,
     accepted licenses, the runtime image, numerical limits and validity blocks.
   - Enroll independently administered evaluators; UID 0 and UID 54 under the
     same administration do not form independent evaluator groups.
   - Preserve a qualifying improved model, reconstruction evidence and rights
     review. Publish the approved baseline artifact and verify restoration.
6. Activation and public handoff.
   - Approve and sign the complete 70/30 policy and successor transition after
     the prior gates pass. Do not fall back silently to endpoint-only rewards.
   - Verify fresh finalized chain state, retire superseded work at the agreed
     boundary, and activate each validator separately.
   - Confirm the exact finalized row, then positive consensus and incentive for
     eligible miners before announcing that open mining earns rewards.

## Work in this execution

The supplied community model now has a verified ZIP importer and a Linux CPU
adapter in [reference-model PR #1](https://github.com/Umi-BitSign/umi-reference-model/pull/1).
One real ARM64 invocation through the actual evaluator completed in 231,638 ms
on a synthetic two-second clip. It required explicit runtime v2 support for
bounded private shared memory. This is functional evidence only; protected ASL
quality, production throughput, independent evaluation and rights approval remain
open. The private object-store backup has been downloaded and reconstructed with
the exact original ZIP checksum. There is no public baseline download or promoted
contributor attribution yet.

- [x] Durable assignment publication/claim journal and expiry tests.
- [x] Owned-finality endpoint origin proof and adversarial tests.
- [x] Signed cutoff/settlement verification and conflict tests.
- [x] Read-only host-upgrade preflight with explicit unverified gates.
- [x] Integrate operator rehearsal commands and cross-component tests.
- [x] Run focused checks, independent review and the full regression suite.
- [x] Bounded immutable settlement package and wallet-free replay worker.
- [x] Replay-worker CLI, restart/conflict tests and independent review.
- [x] Separate signed v4 supervisor contracts and generic weight authorization.
- [x] Exact-byte weight signing, durable submission intent and uncertain-effect recovery.
- [x] Stopped legacy journal recovery with retained evidence and fail-closed checkpoints.
- [x] Signed replacement-host tree verification, including its parent directories.
- [x] Fixed replay/weight worker command and authenticated successor OCI extraction.
- [x] Durable v4 supervision with preserved v3 history and restart guards.
- [x] Fixed Podman lifecycle with inert rehearsal and kernel descendant checks.
- [x] Concrete owned host observer and per-target proof collection.
- [x] Bounded HTTPS input delivery and reuse of verified downloads.
- [x] Atomic current-input selection and crash-repair tests on Linux arm64.
- [x] Connect the authenticated installation receipt and durable successor runtime.
- [x] Per-round immutable input materialization after stopped-worker recovery.
- [x] Verify registration-bridge policy bundles and retained attempt history.
- [x] Start a committed generic systemd switch only after releasing the old lock.
- [x] Recover a retained generic source switch and start without reviving legacy authority.
- [x] Establish private fixed-path mounts for the stopped upgrade observer.
- [x] Wire generic initial privileged preparation into the operator command.
- [x] Adapt and rehearse signed preflight and lifecycle in both coordinator roots.
- [x] Rehearse per-instance interruption/restart on both Linux architectures.
- [x] Rehearse the complete signed initial migration and interrupted-command recovery together.
- [x] Publish a preparation checklist addressing source rights and preliminary review.
- [x] Connect bounded assignment discovery to a running no-weight miner and preserve transport ledgers.
- [x] Connect a continuous signed-inbox dispatcher, owned origin checks and durable transcript replay.
- [x] Pair retained endpoint responses with actual pre-reveal incumbent runs and independent-result preparation.
- [x] Connect continuous local execution, reference reveal and signed peer agreement for both tracks.
- [ ] Publish approved contribution terms, accepted licenses and the reviewer/contact route before intake.
- [ ] Wire deployed miner assignment discovery into ongoing authorized inference.
- [ ] Rehearse integrated protected-data scheduling, evaluator dispatch and evidence publication.
- [ ] Complete the real-model, independent-evaluation and signed-activation gates.

Publication also requires passing full-regression CI for the candidate revision.
That gate is tracked by the repository checks, separately from the activation
inputs above. A documentation merge does not activate the successor.

The [paired endpoint commands](OPEN_COMPETITION_ENDPOINT_EVALUATION.md) derive
baseline jobs from signed publications, execute the archived incumbent through
the existing CPU runner and journal, then replay retained endpoint transport
after reference reveal. Their unsigned output enters the same independent
result/run-record checks as model evaluation. Missing dispatches and
infrastructure failures cannot become scored miner failures. The
[continuous evaluator](OPEN_COMPETITION_EVALUATOR.md) now executes quorum-signed
orders and exchanges retained execution/vote files across successive rounds.
The production coordinator must still publish those orders and committed reveals,
deliver the private peer files, and publish complete settlement evidence on time.

The first batch passed 2,429 tests on 2026-09-12, with one Linux-only memory test
skipped and two dependency deprecation warnings. Ruff checks and formatting
passed. The cross-component test covers assignment discovery, authenticated
miner response, retained outcome and restart without duplicate dispatch. These
are local tests with synthetic keys and inert model fixtures.

The combined regression passed 2,469 tests on 2026-09-12, with the same one
Linux-only skip and two dependency warnings. Ruff checks and formatting passed
for all 47 competition source/test files. The replay batch adds immutable
packages, durable receipts with fresh conflict status, quota-corruption checks
and recovery of missing publication indexes. No wallet or chain-write adapter
is attached to the replay worker.

Run the full suite under the normal user-private temporary directory. A trial
using `/private/tmp` failed existing path-security and spool group checks;
the corrected run passed without changing those checks.

These items are implementation batches, not the entire launch. Track
completed code and remaining deployment gates in [OPEN_COMPETITION.md](OPEN_COMPETITION.md).
Keep both live validators running under their existing authorized policy while
implementing the remaining successor path. Production publication, host migration
and signed activation require their own verified release artifacts and acceptance
checks.

## Upgrade details to preserve

The live registration bridge runs `umi-registration-bridge`. Its effect record
is `registration-bridge-journal.json`, with per-attempt phase records under
`registration-bridge-history/`. It shares `service.lock` with the former common
bootstrap worker and retains that worker's `journal.json` unchanged, plus an
exact copy in `registration-bridge-legacy-journal.json`.
The older explicit-hotkey worker uses
`bootstrap-transactions/<directive>/` and `bootstrap-authorizations/`.
The upgrade must recognize all three layouts and reconcile uncertain anchor and
weight transactions. A new successor-only journal does not replace this step.

The development branch now includes the live bridge release. Read-only upgrade
inspection verifies its signed policy, release revision, bundle digest and exact
extracted files. Stopped-host identity records the bridge policy separately
from a frozen-pilot manifest. Recovery retains every history byte, checks
canonical signed attempts and phase ordering, and requires each later preflight
to name the prior receipt's LastUpdate. The latest row must match owned finalized
storage. Historical SDK receipts remain retained local claims; this is not a new
proof of every historical extrinsic. Uncertain attempts, missing records and
unexplained weight updates remain held.

The generic start routine consumes a committed switch once, waits for the main
process to hold the original lock inode, and verifies the systemd execution
identity. Startup failure stops that unit and invokes its sealed cleanup unit.
It preserves state and never restores the old executable. This routine alone
is not the complete upgrade command.

The coordinator uses `umi-validator@0.service` and `umi-validator@54.service`
with separate RootDirectory trees and a shared resource slice. The generic
host-namespace adapter rejects this layout unless the coordinator adapter has
prepared the selected instance's private filesystem view. The adapter is now
connected to initial upgrade, publication recovery and startup checks. Rooted
preflight, lifecycle and combined signed-migration rehearsals now pass. Either
live validator still requires reviewed production artifacts and authorized
activation inputs before it can be switched.

Read-only inspection confirmed that both instances load the shared
`umi-validator@.service` fragment, with no drop-ins, and use cgroups beneath
`/umi.slice/umi-validators.slice/`. Their passwd home directories include the
host-side RootDirectory prefix, while the running services use
`/var/lib/umi-validator-supervisor/home` inside that root. The adapter must
distinguish host paths from service paths, including bind-mount sources and
cleanup execution. Do not copy the generic account-home rendering into these
instances or edit the shared template to upgrade only one validator.

The stopped-host lease is now implemented in `competition_host_upgrade.py`.
It authenticates the retained v3 directive, installed config and release, checks
the exact systemd unit and descendant cgroups, and holds the existing supervisor
process lock without changing its bytes. The lease expires when its context
closes and cannot be reconstructed from a JSON status. Its 20 focused tests pass
with synthetic installations and mocked Linux OS observations. This has not been
run against either live validator and does not stop or start a service.

Historical recovery now retains both supported journal layouts and exact context
bytes. Its 62 focused tests cover incomplete claims, changed files, uncertain
effects, archive integrity and historical authorization without new write permission.
The signed v4 contract and weight path passed a combined 120-test run. The fixed
worker command passed 16 focused tests, including replay with wallet and network
ports denied. These tests use synthetic inputs and mocked OS or chain boundaries.

Replacement-host authentication checks every signed source and environment file,
its mode, owner and hash, and every ancestor's ownership and write permissions.
Host-source and stopped-lease tests passed 66 cases. The separate successor OCI
bundle verifier passed 39 cases: it checks the full signed bundle before writing,
uses an exclusive private staging directory, and rejects incomplete or changed
artifacts. It does not load or execute an image. These counts are focused runs,
not a full regression of the newly integrated successor. The runtime passed
32 focused cases, including future directives, incomplete feed pages, shutdown
failure and refusal to recreate deleted successor history from an old receipt.

The isolated Ubuntu 24.04 arm64 VM passed the same 105 host/artifact cases.
A newer snapshot passed 123 Linux cases for the Podman adapter, host API and
image recipe. Real Podman probes confirmed the required cgroup limits and
rootless mount ownership. The native image built, and the real signed-archive
loading and inert sandbox test passed with a development key. The earlier
snapshot's full Linux regression then passed 2,736 tests, with 24 skips for
unavailable Rust conformance binaries, Docker Compose and Pandoc. It does not
include every subsequent integration change. These results do not certify the host switch
or activate the successor. The rehearsal VM has no wallet and neither live
validator was changed.

The input materializer and runtime passed 75 focused Linux arm64 tests, including
real atomic directory exchange, interrupted permission repair, unchanged-input
reuse and fresh chain proofs after slow work. The concrete observer, adapter
and alternating-policy cache checks passed 65 focused tests locally. The fixed
host CLI passed its initial 25 tests; the non-mutating systemd override planner
passed 31. These suites are not counts of unique tests across the project.

Startup repair now retains the original process-lock descriptor through runtime
adoption. The lease and runtime passed 57 tests locally and on Linux arm64.
The CLI integration passed 131 focused tests locally, with one Linux-only skip.
The wallet-free crash-cleanup entrypoint passed 33 tests. These runs overlap.

The source-switch publisher installs an exact, root-owned systemd override and
its separate failure-cleanup unit, then reloads the stopped units while retaining
the original lock. It consumes legacy recovery authority before writing and
never starts or restores a service. Its combined switch, service-plan and
legacy-lease suite passed 78 tests locally. Eight opt-in root file-publication
tests passed on Linux arm64, including no-replace and changed-file checks.
Review then found a crash gap before the main drop-in existed. The fixed
directory is now fsynced before any companion bytes are written; fresh legacy
leases reject it after a process restart. The revised root-file suite passed ten
cases, and the local switch/lease/recovery suite passed 109.
Privileged preparation/start orchestration and interrupted-switch recovery are
not covered by that earlier test batch; the publisher is not an operator installation command.

The subsequent recovery command records an atomic root-owned intent before
publishing either service file. It can finish an interrupted publication or
start that exact stopped successor using a separate start-only handle. It never
recreates the legacy lease or modifies v3/v4 history. The focused local suite
passed 87 tests. Seventeen root-filesystem checks passed on arm64, including
actual process death before and after the intent's atomic rename. The startup
tests mock systemd; they do not replace the complete service rehearsal. Native
amd64/arm64 CI results for the later revision are recorded below.

The local full regression passed 3,561 tests with 25 platform/rehearsal skips.
Review then found an overlap between recovery commands during the writer-lock
handoff. A separate per-unit operator mutex now spans recovery, start and failed
start cleanup. The revised focused suite passed 95 tests, including overlapping
invocations and lock identity checks. The arm64 VM passed 18 root-filesystem
checks, including a crashed mutex owner and cross-process exclusion. A Linux
fixture also depended on umask 022; it now creates its required non-writable
staging parent explicitly without relaxing the production ownership checks.

[Native CI at revision 7e04d54](https://github.com/Umi-BitSign/umi/actions/runs/34725329272)
passed on both amd64 and arm64. Each architecture passed 191 state/startup/input
tests and 37 root-filesystem tests; 12 opposite-architecture fixture variants
were skipped on each runner. This includes the main-process kernel flock check,
atomic input repair and process-death publication tests. It does not exercise
the complete operator upgrade or the coordinator's RootDirectory service layout.

The private upgrade-observer namespace passed ten real-mount/filesystem checks
on the wallet-free arm64 host and 34 combined namespace/observer tests locally.
It preserves the parent namespace through normal exit, process death and partial
failure. CI uses dedicated root-owned fixture target paths, since a hosted
runner's directory permissions can fail the production ownership requirement.
The isolated VM uses the real fixed paths. Initial operator orchestration and
the coordinator adapter remain open items above.

At revision `91cfa07`, the full suite in a fixed normal clone passed 3,568 tests,
with 43 platform/rehearsal or unavailable-Rust skips. The separate worktree run
had eight failures because the historical hold helper requires a `.git`
directory. A normal clone exercises that requirement without changing it.
The subsequent placeholder-mode and CI-fixture changes passed 34 focused local
tests and ten real-mount/filesystem cases on the arm64 VM.

[Native CI at revision 9ce558d](https://github.com/Umi-BitSign/umi/actions/runs/34726994165)
passed 199 state/startup checks and 47 root-filesystem checks on each architecture,
with 12 opposite-architecture fixture skips per runner. Both runners reported
`/opt` mode 0777, which explains the earlier ownership rejection. CI now uses
root-owned fixture mount targets without weakening that production check.

The bounded host-bundle stager passed 71 combined artifact tests locally. In the
isolated arm64 VM, nine root-filesystem cases and seven metadata checks passed;
nine amd64 variants were skipped. It verifies all signed files before no-replace
publication, reuses exact installed trees and preserves failed stages. It does
not execute, sign, download or activate a release.

The real system-account rehearsal passed noninteractive container startup,
SIGKILL cleanup, busy-lock noninterference and separate cleanup after an
activation-mount failure with automatic restart enabled. A cold user-namespace
test exposed a Podman cgroup-manager detection difference. The fixed adapter
now explicitly selects systemd, and the actual cold-start service test passed
with kernel cgroup checks and all cleanup paths. The container/cleanup suite
passed 148 tests. The earlier interactive VM test did not cover these conditions.
The service test uses synthetic inputs and an inert launcher; no live upgrade
is approved until the complete migration and restart rehearsal pass.

The generic `upgrade` command now authenticates its controls, stages the signed
host, and rehearses the signed OCI image in a wallet-free systemd service before
stopping the old writer. After stop it requires owned finality reads, an immutable
recovery archive and a root-owned anchor before publication and start. Retried
anchor preparation retains unpublished partial directories outside the active
source; it never treats them as valid anchors or resets retained journals.

The initial driver and partial-retention suite passed 61 local tests. The
isolated arm64 VM passed the real signed-host/OCI preflight and three root/OS
tests, including process exit between atomic partial-retention moves. The
preflight initially exposed a root-only platform helper called by the non-root
child; that check is corrected. The signed test verifies that its own container
is removed and pre-existing unrelated fixtures remain unchanged. No legacy
service stop or complete migration is exercised by that preflight test.

The coordinator adapter preserves logical config paths and the original state
inodes through private bind mounts. Service files use physical bind sources,
retain the selected RootDirectory and resource slice, and write only an
instance-specific override. The inner runtime account is `umi-validator`; the
host accounts are `umi-validator-uid0` and `umi-validator-uid54`. The adapter
checks that the inner numeric UID matches the selected host service. It keeps
the explicit `/var/lib/umi-validator-supervisor/home` environment rather than
using the physical passwd home. Recovery requires the same private view.

The revised focused migration suite passed 233 tests. Two real arm64 Linux
namespace tests passed with both synthetic validator roots on a private tmpfs.
They verify same-inode lock contention, read-only aliases, preserved writable
state, cross-instance isolation and rejection of an inherited view after fork.
The extended cases also prepare the signed observer helpers inside the same
private view. The CI-style arm64 batch passed all 15 namespace and transient
service checks after fixing a missing directory in the new fixture. The
coordinator cases do not start a systemd service or run Podman. The combined
rooted initial source-switch/restart rehearsal and native amd64/arm64 CI remain
required. The subsequent local regression passed 3,737 tests with 42
platform/rehearsal skips. The combined coordinator/observer tests also passed
with the actual fixed mount targets on the arm64 VM. These results do not
approve a live upgrade.
The stopped lease alone does not authorize an upgrade or weights.

[Native CI at revision 082899e](https://github.com/Umi-BitSign/umi/actions/runs/34736960939)
passed 317 state/startup tests and 52 root-filesystem tests on each architecture,
with 12 opposite-architecture skips per runner. Both signed preflights also
passed on amd64 and arm64 using the built successor OCI image and the two
coordinator RootDirectory layouts. The subsequent lifecycle test failed in
fixture image loading because its `/var/tmp` was not writable. Revision
`c3533c8` fixed that fixture and its public code-directory access. Its lifecycle
body exercised both instances, but teardown cancelled fallback cleanup and
left a test container running, so that run failed too. The fixture now waits
for the sealed cleanup unit and checks container absence before releasing its
mounts. These preflights do not stop or upgrade a legacy service.

[Native CI at revision 8fe8483](https://github.com/Umi-BitSign/umi/actions/runs/34737773586)
passed all four jobs. Each architecture passed 317 state/startup tests, 52
root-filesystem tests, both signed rooted preflights and the two-instance
lifecycle test. That test starts both supervisors, kills and restarts each
main process, verifies the other instance is unchanged, and confirms container
absence before teardown. It uses an inert host launcher and synthetic capability
issuers; it does not replace the complete signed initial-migration rehearsal.

The local full regression before that fixture correction passed 3,740 tests,
with 45 platform/rehearsal skips and 34 warnings, mostly retained pytest
temporary-directory cleanup warnings. A subsequent distinct-identity fixture
check and the initial-upgrade suite passed 56 tests. Neither run establishes
the complete rooted migration, and neither live validator was changed.
The later fixture, service-plan, cleanup and weight-worker checks passed 118
tests, including an explicit assertion of the 70/30 allocation through the
signed-package and weight-submission path. Its chain and model inputs are
synthetic.

The combined native migration revealed two systemd behaviors absent from the
earlier unit mocks. Inactive services can load a new drop-in on a `show` request
before `daemon-reload`, and `ExecStart` reports acquire execution timestamps and
a PID after startup. Initial switch and recovery now accept only the exact
verified stopped successor at the first boundary. Startup compares configured
commands separately from execution metadata and still verifies the main PID,
cgroup and original exclusive process lock. Unexpected commands, fields,
identities and drop-ins remain errors.

[Native migration at aaf7689](https://github.com/Umi-BitSign/umi/actions/runs/34741778051)
passed on amd64 and arm64. Each architecture passed 359 state/startup checks,
52 root-filesystem checks, two signed rooted preflights, the two-instance lifecycle
test and the combined signed migration/interrupted-command test, with 12
opposite-architecture variants skipped. The migration uses real
service operations, signed archives and retained journals, with synthetic chain
observations and an anchor/lock startup probe. It does not establish live chain
authority or independent model execution.

The preceding full local regression at `3fcd345` passed 3,754 tests with 46
platform/opt-in skips and 34 warnings. The subsequent recovery change passed
155 focused tests. Full publication CI must include that later change. The
whitepaper rebuild produced the same tracked Markdown-derived LaTeX and PDF.

A read-only production check during this work found UID 0 and UID 54 active
with their unchanged start times of 2026-09-13 02:15:17 and 02:19:15 UTC.
No live service, wallet, signed directive or reward policy was changed. This
process-health check is not a fresh chain-incentive readback.

The old live workers enforce current authorization validity, and the common
service exits at sunset before reconciliation. They cannot simply be started
after expiry to resolve old effects. Validate historical bindings separately,
preserve exact journal/claim bytes, and hold incomplete or ambiguous effects
until the required evidence is available. See the detailed recovery requirements
in [SUCCESSOR_SUPERVISOR_UPGRADE.md](SUCCESSOR_SUPERVISOR_UPGRADE.md).

The historical supervisor input limit is 16 MiB. Successor replay evidence has
different bounds; use a separate versioned package with explicit per-object and
aggregate limits. Do not enlarge the legacy limit or reinterpret its profiles.
The current host mounts the hotkey into every worker mode, so an eventual
no-weight rehearsal profile needs a separate wallet-free mount configuration.

## Inputs still needed before activation

- A reproducible candidate model artifact and its contributor's public hotkey,
  followed by a qualifying preserved promotion. A demo video is insufficient.
- Protected evaluation data, rights/provenance review, accepted contribution
  terms and an independently administered evaluator cohort.
- Explicit numerical/resource limits, release artifacts, validity blocks and
  chain submission requirements in the signed launch policy.
- Reviewed late-conflict recovery rules and operator consent to the installed
  host upgrade and shared-feed transition timing.

The approved allocation remains 70/30 with both tracks launching together.
Missing launch inputs must not be replaced by fixture data or unsigned defaults.
