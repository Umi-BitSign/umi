"""Common runtime binding checks for online and offline reward proofs."""

from .runtime_metadata import ExecutedRuntimeContext
from .validator_chain import PinnedRuntimeContext


def validate_weight_runtime(runtime, ref, pin, executor_sha256):
    if not isinstance(runtime, PinnedRuntimeContext) or runtime.snapshot != ref:
        raise ValueError("weight runtime binding mismatch")
    if executor_sha256 is None:
        if isinstance(runtime, ExecutedRuntimeContext) or runtime.pin != pin:
            raise ValueError("weight runtime binding mismatch")
    elif (
        type(runtime) is not ExecutedRuntimeContext
        or runtime.executor_sha256 != executor_sha256
        or runtime.code_evidence.snapshot != ref
        or runtime.code_evidence.verified_state_root != ref.state_root
        or runtime.code_evidence.storage_key != b":code"
    ):
        raise ValueError("weight executed runtime binding mismatch")
