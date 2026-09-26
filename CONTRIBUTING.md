# Contributing to UMI

UMI is licensed under Apache-2.0. A local run, test result, or rehearsal bundle
does not authorize activation. Changes to chain-writing behavior require a
separately reviewed release and deployment.

## Set up the repository

Python 3.10 through 3.14 is supported. FFmpeg and FFprobe are required for policy
construction, shadow rehearsal, media inspection, and the full test suite.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install uv==0.12.9
uv sync --locked --extra dev
make check
```

`uv.lock` is the release dependency lock. Run `uv lock --check` before testing;
update and review the lock whenever `pyproject.toml` changes.

## Safety rules

- Keep `component_test_no_weight`, `shadow_rehearsal_no_weight`, and
  `calibration_no_weight` distinct.
- Do not add signing, submission, or broadcast behavior to an offline builder or
  replay command.
- Treat every chain snapshot as one block hash. Do not combine best-head and
  finalized reads.
- Reject missing proofs, incomplete block intervals, unsupported call or storage
  formats, unbounded network bodies, and noncanonical JSON. A runtime version
  increment alone is not evidence of incompatibility.
- Preserve exact rational arithmetic through scoring. Use the pinned Bittensor
  conversion only at chain encoding.
- Keep canary labels and reference text sealed until the declared reveal.
- Never commit contributor video, consent records, wallet secrets, or private
  object URLs.

## Pull requests

Each pull request should identify the whitepaper requirement it implements, add
adversarial tests, and state any stage it does not reach. Run `make check` before
requesting review. Changes to a digest formula, schema, normalization behavior,
runtime pin, or activation parameter need an explicit compatibility note.

## Documentation maintenance

Describe the current system and update one authoritative guide per topic. Remove
superseded instructions and expired schedules in the same change. Keep migration
steps only for a deployed consumer that still needs them, with a removal condition.
Use commits and PRs for implementation history. Preserve exact signed terms and
verification evidence; link a fixed older specification only at its replay or
recovery consumer. Check relative links and anchors with
`pytest tests/test_documentation_navigation.py`.

Include unused-code review with changes. Check imports, CLI entry points, service
configurations and replay/recovery consumers before deleting code. Keep those
checks distinct from whether its original campaign has ended.

## Code organization

| Responsibility | Location |
| --- | --- |
| Competition argument contract and named command handlers | `src/umi/competition_commands/` |
| Release schemas, artifact layout, source archives and wheel verification | `src/umi/releases/` |
| Signed bridge policy and pure eligibility/allocation decisions | `src/umi/bridge/` |
| Bridge chain client and worker lifecycle | `src/umi/registration_bridge.py` |
| Bridge private state and history validation | `src/umi/bridge/state.py`, `src/umi/bridge/journal_history.py` |
| Filesystem identity formats used by delivery and recovery | `src/umi/file_identity.py` |
| Cancellation-safe ownership of tasks and blocking operations | `src/umi/concurrency.py` |
| Private canonical files, publication and directory locks | `src/umi/private_files.py` |
| Round plans and cutoff proposal schemas | `src/umi/competition_round_plan.py` |
| Immutable round records, reservations and conflict holds | `src/umi/competition_round_journal.py` |
| Round preparation and cutoff endorsement transport | `src/umi/competition_rounds.py` |
| Pure dispatch timing bounds | `src/umi/competition_dispatch_capacity.py` |
| Scheduling transactions, reservations and single-use claims | `src/umi/competition_scheduling.py` |
| Private dispatcher profile and workload inventory | `src/umi/competition_scheduling_timing.py` |
| Transactional finality evidence usage index | `src/umi/grandpa_finality_accounting.py` |

The existing `competition_cli`, `shadow_release`, and `registration_bridge`
imports remain available. New code should import the module that owns the
operation. Lower layers must not import their command entry point. Put related
operations together; do not create a new module for every helper or add a
generic utility layer without an actual shared responsibility.

Keep side effects at named boundaries. A selection function should accept
observations and return a decision, not fetch chain state or submit weights.
Command handlers validate arguments and call domain code; they do not define
reward rules. Keep signature checks and bounded file/network reads explicit.

Historical release decoders and journal formats remain necessary while deployed
workers or retained evidence depend on them. Check imports, deployed entry points,
and recovery consumers before removing a superseded implementation. Do not rename
a signed field or change a tuple's identity ordering during a cleanup.

`tests/test_module_boundaries.py` checks command coverage, dependency direction,
compatibility exports, and pre-refactor JSON-schema/argument fingerprints.
Update those fingerprints only for an intentional, documented contract change.
Fixtures should patch the owning module and keep Git signing agents, hooks and
operator configuration out of test subprocesses.

Blocking work that owns a lock, subprocess, or publication boundary must finish
cleanup before its async caller releases ownership. Use `run_owned_thread` for
bounded blocking operations, with a cooperative stop callback for long-running
workers. Test cancellation during work and during cleanup, including a second
cancellation. Cancelling `asyncio.to_thread` alone does not stop its thread.
Use `await_owned_task` when cleanup already runs as an async task. Provider close
must drain active work before releasing its RPC connections or namespace lease;
collections queued before close must recheck the closed state after acquiring
their lock. Blocking database and filesystem work belongs off the HTTP event
loop. Bound lock acquisition. Cancellation may arrive after a durable write;
recover its retained result on retry instead of inferring rollback from a
cancelled await.

Use `kill_and_reap` to terminate an owned subprocess and drain its wait through
repeated cancellation. Reaping the Podman client does not establish container
exit; keep the separate container and cgroup absence checks.

A thread that waits for an async proof must not occupy the same executor needed
by that proof's blocking work. The work signer's single-use executor separates
those dependencies and drains before releasing its process lease. Recheck
finality after executor queueing and native receipt verification, immediately
before new signing. Cover delayed starts, proof timeouts and repeated cancellation.

Review resource limits across the complete round before deployment. Include
retained history, per-assignment outcome reservations, serialized proof requests,
per-miner inference time, and shared concurrency. A successful single-miner test
does not qualify a full roster. Record measured latency and memory when changing
a hot path; keep performance measurements separate from model-quality results.

Use `RoundJournal.put_many` when immutable records and their discovery indexes
must become visible together. Its index callback shares the transaction and must
not await or open a nested writer. Existing-byte conflicts commit only durable
holds; capacity, validation and callback failures leave no partial batch. Read
retained records with the supplied connection when repairing indexes. Keep
policy decisions and wire-format validation in the caller.

Keep timing calculations pure and bind them to actual runtime settings at the
claim boundary. Capacity reservations must include retained history and future
outcomes/proofs. Test exact-fit budgets, unrelated writers, partial migration,
crashes and expired work. A preflight over separate journals is not an atomic
reservation; state that limitation. Private schema migrations must fence older
writers without removing their retained evidence.

Native reservation APIs keep capacity enforcement with its writer:
`ExecutionJournal.reserve_jobs`, `EvaluatorJournal.reserve_orders`, and
`RoundJournal.reserve_records`. Reserve pending work separately from execution
status; an interrupted job must never become runnable through a capacity retry.
Matching writes consume their allowance in the same transaction as the retained
record. Unrelated writes count every pending obligation. Include receipt and
index metadata, and reject changed or missing obligations instead of repairing
them during an exact retry.

`WorkAdmission` connects the signing, execution, evaluator, scheduling and
configured settlement-review journals before a new work signature. Keep artifact
size calculations in `competition_evaluator_budget`, separate from journal I/O.
Authenticate the whole plan once, then derive each member's exact obligations.
Future publication signatures require a bounded envelope around the fixed order
identity. Reserve scored and void evidence, every peer copy and review storage.
Separate native commits can leave pending obligations after a crash; a durable
completion receipt and verified native receipts gate signing. Never turn a partial
commit into discoverable work or release its credit during an ordinary retry.

Hold the interprocess signer lease through final verification, signing and vote
persistence. Offloaded capacity work must drain on cancellation before that lease
is released. Test the original issue margin after expensive capacity work. These
logical reservations do not qualify filesystem space, compute or a deployment:
measure the full roster and retained-history migration in a connected rehearsal.
Do not invoke private migration methods on live journals as a workaround.

Derived database counters must change in the same transaction as their source
rows, including mutations from older open connections. Finality accounting uses
SQLite triggers for this purpose. Startup audits compare counters with full
history; an installed but damaged index must not be silently rebuilt. Preserve
read-only access to older evidence formats when adding a private writer schema.

## Remote test workspace cleanup

Use a task-scoped temporary root for remote tests, with separate checkout and
test-output subdirectories. Release tests intentionally reject installation
paths inside the source checkout. Retain bounded test results, then remove the
temporary checkout, build products and test outputs after verification.

Signed-release staging also checks every ancestor's ownership and permissions.
Use a private root below protected ancestors, such as the rehearsal user's
mode-0700 cache directory; `/tmp` and `/var/tmp` fail this check even when the
test directory itself is mode 0700. Set pytest's `--basetemp` to a dedicated
child of that root, separate from the checkout. Do not weaken the release
permission checks to accommodate a test workspace.

Build the synthetic OCI fixture from the checkout being tested. The signed
container rehearsal compares its image's Python source digest with that checkout
before staging. An older cached image can exercise a different sandbox contract
and does not qualify the current release. Full release qualification also needs
the current native binaries and dependency lock, not only matching Python files.

Before removing an older directory, check process arguments, service definitions,
configuration references, symlinks and Python environment paths. Never delete
wallets, private datasets, model archives or recovery journals as build debris.
Do not promote a temporary test environment into a service dependency; install
runtime dependencies in their documented persistent location instead.
