"""Fixed automatic translation worker under the supervisor's existing lease.

The authenticated directive selects a content-addressed approval, never a remote
command or trust root. Original bridge state stays in place under its original
mutex. This worker follows an approved native row; it does not certify a cohort.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import signal
import time
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

import bittensor as bt

from .bridge.native import read_image_artifacts
from .bridge.signing import BridgeSigningStateReader
from .concurrency import await_owned_task, run_owned_thread
from .mortal_receipts import MortalReceiptReader
from .protocol import canonical_json_bytes
from .runtime_metadata import RuntimeMetadataExecutor
from .signed_extrinsic import exact_signed_extrinsic
from .substrate_proof import SubprocessStorageProofVerifier
from .translation_reference_execution import run_reference_iteration
from .translation_reference_legacy_state import ReferenceLegacyState
from .translation_reference_policy import (
    MAX_REFERENCE_POLICY_BYTES,
    ApprovedTranslationReferencePolicy,
    verify_reference_policy,
)
from .translation_reference_state import TranslationReferenceError, TranslationReferenceStateReader
from .translation_reference_transactions import ReferenceWeightJournal
from .validator_chain import BittensorRawJsonRpc
from .validator_supervisor import COMMON_SUPERVISOR_AUTHORITY_HOTKEY
from .validator_supervisor_adapters import PinnedHTTPSClient

REFERENCE_POLICY_ORIGIN = "https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev"
REFERENCE_POLICY_PREFIX = "/validator-supervisor/translation-reference-policies/"
REFERENCE_VERIFIER_RULE = "umi-approved-reference-worker-native-verification/1"
# Local durable metadata only; model, evidence and block payloads do not belong
# here. Capacity exhaustion is explicit and never deletes an unresolved attempt.
REFERENCE_JOURNAL_MAXIMUM_BYTES = 256 * 1024**2
_LOG = logging.getLogger(__name__)
_RETRYABLE_NATIVE_REASONS = frozenset(
    {
        "proof_rpc_failed",
        "finalized_snapshot_rpc_failed",
        "runtime_metadata_rpc_failed",
        "storage_proof_rpc_failed",
        "reference_finality_advanced_during_capture",
        "reference_snapshot_stale",
        "reference_submission_freshness_headroom_insufficient",
        "reference_signing_era_headroom_insufficient",
        "reference_finalized_row_not_visible",
        "reference_validator_inactive",
        "reference_update_stale",
        "reference_cutover_not_reached",
        "reference_row_not_approved_by_release_authority",
    }
)


async def load_reference_policy(environment, *, http=None):
    """Only the already authenticated directive supplies the expected identity."""
    environment.validate()
    if environment.mode != "translation_weights":
        raise TranslationReferenceError("reference_worker_mode_invalid")
    payload = await (http or PinnedHTTPSClient()).fetch_bytes(
        f"{REFERENCE_POLICY_ORIGIN}{REFERENCE_POLICY_PREFIX}{environment.policy_sha256}.json",
        maximum_bytes=MAX_REFERENCE_POLICY_BYTES,
    )
    policy = verify_reference_policy(
        payload,
        expected_policy_sha256=environment.policy_sha256,
        expected_authority_hotkey=COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
    )
    if type(policy) is not ApprovedTranslationReferencePolicy:
        raise TranslationReferenceError("reference_authority_approved_row_required")
    return policy


class LeaseFinality:
    """Return the continuously owned head without waiting for another block.

    The lease's single owner advances the stream and rejects stale or expired
    heads. Multiple proof guards must not each add a new-block wait.
    """

    def __init__(self, lease):
        self.lease = lease

    async def read_finalized_identity(self):
        return self.lease.require_headroom(0)


def production_readers(*, client, finality, clock, progress):
    artifacts = read_image_artifacts()
    tools = dict(
        verifier=SubprocessStorageProofVerifier(
            binary_path="/opt/umi/bin/umi-substrate-proof-verifier",
            expected_sha256=artifacts.proof_sha256,
        ),
        runtime_executor=RuntimeMetadataExecutor(
            binary_path=Path("/opt/umi/bin/umi-runtime-metadata"),
            expected_sha256=artifacts.runtime_sha256,
        ),
    )
    semantics = hashlib.sha256(
        canonical_json_bytes(
            {"rule": REFERENCE_VERIFIER_RULE, "native": artifacts.model_dump(by_alias=True)}
        )
    ).hexdigest()
    rpc = BittensorRawJsonRpc(client)
    return (
        TranslationReferenceStateReader(
            finality=finality, rpc=rpc, clock=clock, progress=progress, **tools
        ),
        BridgeSigningStateReader(finality=finality, rpc=rpc, clock=clock, **tools),
        MortalReceiptReader(finality=finality, rpc=rpc, **tools),
        semantics,
    )


class ReferenceWorkerPorts:
    """Production resources stay owned until all cancellation has drained."""

    def __init__(
        self,
        *,
        environment,
        policy,
        lease,
        legacy,
        journal,
        client,
        readers,
        wallet_loader,
        progress,
        clock=None,
    ):
        self.environment, self.policy, self.lease = environment, policy, lease
        self.legacy, self.journal, self.client = legacy, journal, client
        self._state, self._signing, self._receipt, self.verifier_semantics_sha256 = readers
        self.expected_validator_hotkey = environment.expected_validator_hotkey
        self._wallet_loader, self._progress = wallet_loader, progress
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._started = time.monotonic()
        self._signer = None

    def clock(self):
        return self._clock()

    def elapsed_seconds(self):
        return time.monotonic() - self._started

    def progress(self, value):
        self._progress(value)

    def require_owner(self):
        self.legacy.require_owner()
        self.lease.require_headroom(0)

    async def state(self, policy):
        if policy != self.policy:
            raise TranslationReferenceError("reference_selected_policy_changed")
        return await self._state.read(self.expected_validator_hotkey, policy)

    async def signing_state(self):
        return await self._signing.read(self.expected_validator_hotkey)

    async def legacy_gate(self, state):
        await run_owned_thread(
            partial(
                self.legacy.approve,
                state,
                self.policy,
                self.journal,
                verifier_semantics_sha256=self.verifier_semantics_sha256,
                now=self.clock(),
            )
        )

    async def guard(self, intent):
        self.require_owner()
        await self.lease.require_snapshot(intent.block, intent.block_hash, intent.mortality_period)
        head = self.lease.require_headroom(intent.mortality_period)
        if head.number >= intent.block + intent.mortality_period - 2:
            raise TranslationReferenceError("reference_signing_era_headroom_insufficient")

    def signer(self):
        self.require_owner()
        if self._signer is None:
            self._signer = bt.resolve_signer(self._wallet_loader(self.environment), role="hotkey")
        return self._signer

    async def submit(self, encoded, signer, timeout_seconds):
        self.require_owner()
        task = asyncio.create_task(
            asyncio.wait_for(
                self.client._substrate.submit_signed(
                    exact_signed_extrinsic(encoded),
                    signer,
                    wait_for_inclusion=True,
                    wait_for_finalization=True,
                ),
                timeout=timeout_seconds,
            )
        )
        # The SDK does not compose/sign and excludes author methods from its
        # reconnect replay. Cancellation drains before releasing the mutex.
        await await_owned_task(task, on_cancel=task.cancel)

    async def receipt(self, query):
        return await self._receipt.find(query)


async def _under_lease(lease, operation):
    task = asyncio.create_task(operation)
    terminal = asyncio.create_task(lease.wait_terminal())
    try:
        done, _ = await asyncio.wait((task, terminal), return_when=asyncio.FIRST_COMPLETED)
        if terminal in done:
            raise TranslationReferenceError(terminal.result())
        return task.result()
    finally:

        async def drain():
            for owned in (task, terminal):
                if not owned.done():
                    owned.cancel()
            await asyncio.gather(task, terminal, return_exceptions=True)

        await await_owned_task(asyncio.create_task(drain()))


async def run_translation_worker(
    environment,
    *,
    state_root,
    lease,
    finality_reader,
    wallet_loader,
    http=None,
    client_factory=None,
    readers_factory=None,
    progress=None,
    clock=None,
):
    """Release/profile/revision must be authenticated by the fixed CLI first.

    No wallet opens until native selection, original legacy reconciliation,
    directive freshness and the durable first intent have all passed.
    """
    started = time.monotonic()
    clock = clock or (lambda: datetime.now(timezone.utc))

    def emit(value):
        _LOG.info("translation_reference_progress %s", value)
        if progress is not None:
            progress(value)

    def stage(name, completed, *, retrying=False, **extra):
        emit(
            {
                "stage": name,
                "completed": completed,
                "total": 1,
                "percent": 100 * completed,
                "elapsed_seconds": time.monotonic() - started,
                "eta_seconds": 0 if completed else None,
                "planning_seconds": None if completed or retrying else [1, 120],
                "eta_basis": "bounded startup stage planning range; external rollout separate",
                "stalled": retrying,
                "retrying": retrying,
                **extra,
            }
        )

    finality_task = asyncio.create_task(lease.run(), name="umi-reference-owned-finality")
    try:
        stage("reference_approved_policy", 0)
        policy = await _under_lease(lease, load_reference_policy(environment, http=http))
        stage("reference_approved_policy", 1)
        stage("reference_initial_owned_finality", 0)
        await lease.wait_ready()
        stage("reference_initial_owned_finality", 1)
        # Entering an unsupported original layout refuses before adding locks
        # or opening wallets. The original service.lock spans the whole session.
        with ReferenceLegacyState(state_root, progress=emit) as legacy:
            journal = await run_owned_thread(
                partial(
                    ReferenceWeightJournal,
                    legacy.follower_root,
                    validator_hotkey=environment.expected_validator_hotkey,
                    maximum_bytes=REFERENCE_JOURNAL_MAXIMUM_BYTES,
                    progress=emit,
                )
            )
            async with (client_factory or bt.Client)("finney") as client:
                readers = (readers_factory or production_readers)(
                    client=client,
                    finality=LeaseFinality(lease),
                    clock=clock,
                    progress=emit,
                )
                ports = ReferenceWorkerPorts(
                    environment=environment,
                    policy=policy,
                    lease=lease,
                    legacy=legacy,
                    journal=journal,
                    client=client,
                    readers=readers,
                    wallet_loader=wallet_loader,
                    progress=emit,
                    clock=clock,
                )
                while True:
                    try:
                        result = await _under_lease(
                            lease, run_reference_iteration(policy, journal=journal, ports=ports)
                        )
                    except Exception as error:
                        reason = getattr(error, "reason_code", None)
                        if isinstance(error, (TimeoutError, asyncio.TimeoutError)):
                            reason = "native_capture_timeout"
                        elif reason not in _RETRYABLE_NATIVE_REASONS:
                            raise
                        # Only read/capture/selection failures retry here. The
                        # kernel retains every uncertain signed effect before
                        # attempting another signature or transmission.
                        stage(
                            "reference_native_retry",
                            0,
                            retrying=True,
                            reason_code=reason,
                            retry_seconds=12,
                        )
                    else:
                        stage("reference_iteration", 1, result=result)
                    await _under_lease(lease, asyncio.sleep(12))
    finally:

        async def stop_owned_finality():
            finality_task.cancel()
            await asyncio.gather(finality_task, return_exceptions=True)
            await finality_reader.stop()

        await await_owned_task(asyncio.create_task(stop_owned_finality()))


async def run_translation_service(environment, **options):
    """Podman SIGTERM cooperatively drains before the original lock is released."""
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(run_translation_worker(environment, **options))
    stopping = False

    def stop():
        nonlocal stopping
        if stopping:
            return
        stopping = True
        task.cancel()

    loop.add_signal_handler(signal.SIGTERM, stop)
    try:
        await await_owned_task(task, on_cancel=task.cancel)
    except asyncio.CancelledError:
        if not stopping:
            raise
    finally:
        loop.remove_signal_handler(signal.SIGTERM)
