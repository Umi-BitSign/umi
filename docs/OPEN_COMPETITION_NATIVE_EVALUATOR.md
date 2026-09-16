# Native Mac Studio evaluator

The opt-in `umi-offline-mps-runtime/1` backend runs preserved Python model
bundles on macOS arm64. It does not change validator installation requirements
or activate a competition policy. Launch qualification is still in progress.

Select this runtime explicitly in a new signed competition policy. Its digest
differs from both Linux CPU profiles. Candidate and incumbent executions must
use the same runtime digest. Old rounds, cached authorizations and execution
journals keep their original bindings.

## Execution contract

The declared inference file receives one video path in `argv[1]` and writes
one UTF-8 English hypothesis to stdout. `UMI_EVALUATION_DEVICE=mps` identifies
the available accelerator. Models must include all their weights and required
files in the preserved bundle and use the reviewed installation's dependencies.
The runner downloads nothing and installs no submitted dependencies.

Each case starts a new Python process. Model loading and inference share the
policy deadline, including the launch profile's 120-second limit. There is no
warm-worker exception for the baseline. Scratch and Metal compiler-cache paths
are unique to each case. Reference labels and wallet paths are never supplied
to the model process.

Seatbelt denies network access, process forking, signaling other processes and
reading user data outside the declared model/dependency/input roots. A trusted
prelude chooses the multiprocessing `fork` context so import-time semaphore
locks do not start a resource-tracker process. Actual forks remain denied.
This backend does not support models that require child processes.

An independent watchdog owns the model process group. Closing its controller
pipe cancels the case; the wall-clock deadline also applies if the evaluator
exits. Tests exercise normal completion, deadlines and controller disconnects.
Cleanup uncertainty stops the operation and retains its namespace for review.

## Resource limits

This profile uses sampled RSS and aggregate scratch/compiler-cache ceilings,
checked about every 200 milliseconds. These are not Linux cgroup allocation
limits, and transient allocations can exceed them between observations. The
prelude also disables core dumps and bounds open descriptors and individual
file sizes. The operator must reserve host headroom for the miner and other
workloads. Do not describe this backend as equivalent to a container's hard
memory limit or as remote hardware attestation.

## Installation binding

`UMI_NATIVE_EVALUATOR_CONFIG` points to an owner-private canonical JSON file:

```json
{
  "schema": "umi-native-evaluator-paths/1",
  "roots": {
    "environment": "/ABSOLUTE/REVIEWED/ENVIRONMENT",
    "python": "/ABSOLUTE/REVIEWED/PYTHON",
    "overlay": "/ABSOLUTE/REVIEWED/NATIVE-OVERLAY"
  },
  "manifest": "/ABSOLUTE/PRIVATE/installation.json"
}
```

The example is formatted for reading; stored files must use canonical JSON.
The installation manifest has schema `umi-native-evaluator-installation/1`
and an `entries` array produced by `competition_native_inventory.inventory`.
The signed runtime binds the SHA-256 of its canonical bytes, the macOS build,
Python ABI, thread count, video bound and resource ceilings. Root paths are
local bindings; inventory entries use logical root names.

Verification hashes every installed file. It rejects links outside inventoried
roots, hardlinks, special files, writable group permissions and oversized trees.
The interpreter is `environment/bin/python`; it must resolve inside the
reviewed installation. The model and dependencies are read-only in the sandbox.
The native prelude currently supports CPython 3.10.

This mechanism verifies local files against approved hashes. It does not prove
that another operator ran those bytes. Evaluation evidence continues to rely
on the policy's evaluator identities and independent-control-group rules.

## Launch gate

Run inert sandbox and cancellation checks first, then the preserved baseline
through `execute_offline_case` on the six already-exposed qualification clips.
Do not use unused holdout cases for operational debugging. A standalone miner
or worker timing pass is insufficient: finish the connected execution, reveal,
settlement and replay before installing competition weights on validators.
