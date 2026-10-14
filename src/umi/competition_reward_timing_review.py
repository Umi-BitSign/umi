"""Native, checkpointed chain-age evidence for a new signed reward adoption.

Only the cohort-start timestamp needs a new scoped historical proof. The fresh
observation already proves Timestamp.Now. Existing block-history checkpoints and
their ABI remain unchanged. This module never signs or publishes an adoption.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import AsyncExitStack
from pathlib import Path

from .competition_chain_state import _cache_usage
from .competition_reward_control import validate_owned_reward_control
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_control_evidence import _Archive
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_history_verifier import verify_slot_archive
from .competition_reward_timing import RewardActivationAge
from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import VerificationReuse, metadata_completion
from .concurrency import run_owned_thread
from .open_competition import digest


async def review_activation_age(
    provider: HistoricalRewardControlProvider,
    *,
    series,
    plan,
    observation,
    receipt_directory: Path,
    history: RewardControlHistoryReader | None = None,
    start_evidence: bytes | None = None,
    start_metadata: bytes | None = None,
) -> RewardActivationAge:
    """Produce facts for quorum signing from native proofs, never RPC timestamps.

    Call during adoption preparation for every cohort. The rule automatically
    waives the activation delay when this proved age is strictly over 72 hours.
    A younger observation grants no waiver; refresh before signing if preparation
    crosses the threshold. Never rewrite a previously signed adoption.
    """
    if not isinstance(provider, HistoricalRewardControlProvider):
        raise ValueError("activation age requires an owned historical provider")
    if digest(plan) not in {digest(p) for p in series.cohorts}:
        raise ValueError("activation age plan is outside the selected series")
    config_sha = digest(provider.config)

    def current():
        validate_owned_reward_control(
            observation,
            expected_control_hotkey=series.control_hotkey,
            expected_chain_config_sha256=config_sha,
        )

    current()
    reuse = VerificationReuse(
        receipt_directory,
        owner={
            "schema": "umi-native-cohort-start-time/1",
            "series": digest(series),
            "policy": series.policy_sha256,
            "chain": config_sha,
        },
    )
    async with AsyncExitStack() as ownership:
        archive = None
        if history is not None:
            if (
                type(history) is not RewardControlHistoryReader
                or history.config_sha256 != config_sha
                or history.hotkey != series.control_hotkey
                or start_evidence is not None
                or start_metadata is not None
            ):
                raise ValueError("activation age history differs from selected native owner")
            await ownership.enter_async_context(history._lock)

            def source_anchor():
                with history.journal.read_transaction() as db:
                    return history.checkpoints.sources(
                        (("control_history_block", str(plan.not_before_block)),), db
                    )

            source = {
                "owner": history.checkpoints.owner,
                "semantics": history.checkpoints.semantics,
                "anchor": await run_owned_thread(source_anchor),
            }
            block = plan.not_before_block
            block_hash = evidence_sha = None
        else:
            archive = await run_owned_thread(_Archive, start_evidence, start_metadata)
            block, block_hash = (
                archive.snapshot.block_number,
                archive.snapshot.block_hash.removeprefix("0x"),
            )
            evidence_sha = archive.evidence_sha256
            source = {
                "evidence": evidence_sha,
                "metadata": hashlib.sha256(start_metadata).hexdigest(),
            }
        if block != plan.not_before_block:
            raise ValueError("activation age archive differs from its signed cohort start")
        key = digest(
            {
                "owner": reuse.owner,
                "semantics": reuse.runtime,
                "plan": digest(plan),
                "source": source,
            }
        )
        with TransferProgress(
            "reward_activation_age", 2, unit="chain_timestamps", planning_unit_seconds=(0.01, 30)
        ) as progress:
            async with provider._lock:
                if provider._closed:
                    raise ValueError("activation age provider is closed")
                with reuse.exclusive():
                    directories = (reuse.directory,) + (
                        () if reuse.legacy_directory is None else (reuse.legacy_directory,)
                    )
                    known = any(
                        (d / (key + ".json")).exists()
                        or metadata_completion(d / (key + ".json")).exists()
                        for d in directories
                    )
                    receipt = reuse.load(key)
                    if receipt is None and known:
                        progress.emit("repair_required", reason="retained_age_receipt_damaged")
                        raise ValueError("retained activation age requires explicit receipt repair")
                    if receipt is None:
                        if history is not None:
                            try:
                                fields = await run_owned_thread(
                                    history._load, plan.not_before_block
                                )
                                sources = history._source_tokens.get(plan.not_before_block)
                            finally:
                                history._prepared_encodings.pop(plan.not_before_block, None)
                                history._source_tokens.pop(plan.not_before_block, None)
                            if fields is None:
                                raise HistoryCheckpointRepairRequired(
                                    "cohort start lost its retained proof source"
                                )
                            archive = await run_owned_thread(
                                _Archive, fields["slot_evidence"], fields["slot_metadata"]
                            )
                        if (
                            archive.hotkey != series.control_hotkey
                            or archive.body["finality"].get("genesis_hash")
                            != "0x" + provider.config.chain_pin.genesis_block_hash
                            or archive.snapshot.block_number != block
                            or (
                                block_hash is not None
                                and archive.snapshot.block_hash.removeprefix("0x") != block_hash
                            )
                        ):
                            raise ValueError(
                                "activation age archive differs from its signed cohort start"
                            )
                        _cache_usage(provider._cache_root, provider.config.maximum_cache_bytes)
                        timestamp, ceiling = await provider._resolve_control_header(
                            archive.snapshot, archive.encoded
                        )
                        _, actual_time, _, _ = await verify_slot_archive(
                            archive,
                            provider._history_proof_tools(),
                            timestamp=timestamp,
                            ceiling=ceiling,
                        )
                        facts = {
                            "block": archive.snapshot.block_number,
                            "hash": archive.snapshot.block_hash.removeprefix("0x"),
                            "timestamp_ms": actual_time,
                            "evidence_sha256": archive.evidence_sha256,
                            "metadata_sha256": archive.body["runtime_metadata_sha256"],
                            "sources": None if history is None else sources,
                        }
                        reuse.remember(key, (), json.dumps(facts, sort_keys=True))
                    else:
                        facts = json.loads(receipt.result_json)
                    if (
                        set(facts)
                        != {
                            "block",
                            "hash",
                            "timestamp_ms",
                            "evidence_sha256",
                            "metadata_sha256",
                            "sources",
                        }
                        or facts["block"] != block
                        or (block_hash is not None and facts["hash"] != block_hash)
                        or (evidence_sha is not None and facts["evidence_sha256"] != evidence_sha)
                        or type(facts["timestamp_ms"]) is not int
                    ):
                        raise ValueError("retained activation age facts changed")
                    progress.advance(1, restored=receipt is not None)
            if history is not None:

                def check_sources():
                    with history.journal.read_transaction() as db:
                        if not facts["sources"]:
                            raise HistoryCheckpointRepairRequired(
                                "cohort timestamp lost its source identities"
                            )
                        history.checkpoints.check_sources(facts["sources"], db)
                        history.checkpoints.check_sources(source["anchor"], db)

                await run_owned_thread(check_sources)
            current()
            result = RewardActivationAge(
                schema="umi-reward-activation-age/1",
                rule="skip_activation_delay_if_older_than_three_days",
                cohort_start_block=facts["block"],
                cohort_start_hash=facts["hash"],
                cohort_start_timestamp_ms=facts["timestamp_ms"],
                start_evidence_sha256=facts["evidence_sha256"],
                observed_at_block=observation.snapshot.block_number,
                observed_block_hash=observation.snapshot.block_hash.removeprefix("0x"),
                observed_timestamp_ms=observation.timestamp_ms,
                observation_evidence_sha256=observation.evidence_sha256,
            )
            progress.advance(1)
            return result
