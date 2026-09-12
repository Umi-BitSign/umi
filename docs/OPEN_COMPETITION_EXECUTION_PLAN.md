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
- [ ] Wire privileged preparation and interrupted-switch recovery into the operator command.
- [ ] Adapt and rehearse the coordinator's two RootDirectory validator installations.
- [ ] Rehearse interruption/restart on both Linux architectures and rerun all tests.
- [ ] Complete the real-model, independent-evaluation and signed-activation gates.

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
host-namespace adapter rejects this layout. A namespace-aware path must preserve
the installed config and state bindings, verify files in the correct root, and
rehearse each service independently before either live validator is switched.

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
still required; the publisher is not an operator installation command.

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

The remaining upgrade work includes privileged staging/start orchestration,
interrupted-switch recovery and the actual source switch/restart rehearsal.
The stopped lease alone does not authorize an upgrade or weights.
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
