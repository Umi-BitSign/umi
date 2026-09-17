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

## Code organization

| Responsibility | Location |
| --- | --- |
| Competition argument contract and named command handlers | `src/umi/competition_commands/` |
| Release schemas, artifact layout, source archives and wheel verification | `src/umi/releases/` |
| Signed bridge policy and pure eligibility/allocation decisions | `src/umi/bridge/` |
| Bridge chain client, worker lifecycle and recovery journal | `src/umi/registration_bridge.py` |
| Filesystem identity formats used by delivery and recovery | `src/umi/file_identity.py` |

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

## Remote test workspace cleanup

Use a task-scoped temporary root for remote tests, with separate checkout and
test-output subdirectories. Release tests intentionally reject installation
paths inside the source checkout. Retain bounded test results, then remove the
temporary checkout, build products and test outputs after verification.

Before removing an older directory, check process arguments, service definitions,
configuration references, symlinks and Python environment paths. Never delete
wallets, private datasets, model archives or recovery journals as build debris.
Do not promote a temporary test environment into a service dependency; install
runtime dependencies in their documented persistent location instead.
