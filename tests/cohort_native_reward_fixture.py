"""Connect actual settlement output to native reward discovery and review.

Linked headers, RPC, trie verification and SCALE storage are explicit fixture
ports. Their predetermined control writes simulate inclusion, not a transaction
or installed-host qualification. Package replay, history review, journals,
signatures, decision delivery and validator preparation are native consumers.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_chain import FinalizedRegistrationProvider
from umi.competition_reward_control_journal import RewardControlTransactionJournal
from umi.competition_reward_control_publisher import StandingControlPublisher
from umi.competition_reward_coordinator import (
    StandingRewardCoordinator,
    StandingRewardDecisionReviewer,
)
from umi.competition_reward_coverage_journal import RewardCoverageJournal
from umi.competition_reward_decisions import (
    RewardActivation,
    RewardControlDecision,
    StandingRewardControlReader,
)
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
from umi.competition_reward_offers import StandingRewardOffers
from umi.competition_reward_opportunity import opportunity_rule
from umi.competition_reward_preparation import StandingRewardPreparation
from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from umi.historical_header_recovery import HistoricalHeaderRecoveryPending
from umi.open_competition import digest, sign_object
from umi.private_files import ensure_private_directory, publish_private_model
from umi.protocol import canonical_json_bytes
from umi.validator_chain import FinalizedProofCollector

from .test_competition_chain import _NOW, _Finality, _Rpc, _Runtime, _Verifier
from .test_competition_reward_control_archive import make_historical
from .test_competition_reward_history import make_history_case
from .test_competition_reward_preparation import current_control_finality
from .test_open_competition import wallet


async def run_activation(owner, settled, root, monkeypatch, signatures):
    ensure_private_directory(root)
    series, manifest = owner.config.series, owner.config.manifest
    package, policy = settled.package, owner.h.intake.policy
    cohort = digest(package.inputs.history.plan)
    first = series.recovery.authority.issued_at_block
    # This is the original proposal after settlement, before its delayed retry.
    activation_block = package.inputs.history.transitions[-1].transition.observed_at_block + 2
    end = (
        activation_block
        + 1
        + (series.maximum_proof_lag_blocks + series.maximum_transaction_lifetime_blocks)
    )
    config = owner.config.dispatch.origins.model_copy(
        update={
            "state_directory": str(root / "chain"),
            "minimum_finalized_block": first,
            "finality_pin": owner.config.dispatch.origins.finality_pin.model_copy(
                update={"bootstrap_block_number": first - 1}
            ),
        }
    )
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", _Runtime)
    finality = _Finality(config, policy)
    finality.ref = replace(finality.ref, block_number=first)
    rpc = _Rpc(finality)
    verifier = _Verifier(finality, rpc.values)
    proofs = FinalizedProofCollector(rpc, finality=finality, verifier=verifier)
    item = SimpleNamespace(
        config=config,
        policy=policy,
        finality=finality,
        rpc=rpc,
        verifier=verifier,
        proofs=proofs,
        clock=SimpleNamespace(now=_NOW),
        hotkey=series.control_hotkey,
        spec=("Commitments", "CommitmentOf", (78, series.control_hotkey)),
    )
    item.provider = FinalizedRegistrationProvider(
        config, policy, finality=finality, proofs=proofs, now_ms=lambda: item.clock.now
    )
    rpc.values[("System", "Account", (series.control_hotkey,))] = {"nonce": 7}
    handoff = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(series),
        cohort_sha256=cohort,
        legacy_policy_sha256="11" * 32,
        legacy_round_sha256="22" * 32,
        legacy_package_sha256="33" * 32,
    )
    genesis_body = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(series),
        sequence=0,
        predecessor_sha256=None,
        kind="admit_series",
        observed_at_block=first,
        activation=None,
    )
    activation = RewardActivation(
        cohort_sha256=cohort,
        allocation_sha256=digest(package.allocation),
        package_sha256=digest(package),
        recovery_tip_sha256=digest(package.inputs.history.transitions[-1].transition),
        prior_opportunity_sha256=digest(handoff),
    )
    activation_body = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(series),
        sequence=1,
        predecessor_sha256=digest(genesis_body),
        kind="activate",
        observed_at_block=activation_block,
        activation=activation,
    )

    def reader(name):
        return StandingRewardControlReader(
            root / name,
            series,
            policy,
            expected_series_sha256=digest(series),
            expected_chain_config_sha256=digest(config),
            maximum_bytes=32 * 1024**2,
        )

    # Only the RPC simulator uses these expected control digests. The actual
    # coordinator starts empty and must derive, review and sign both decisions.
    writes = {block: () for block in range(first, end + 1)}
    writes[first + 1] = (digest(genesis_body),)
    writes[activation_block + 1] = (digest(activation_body),)
    case = SimpleNamespace(
        control=item,
        series=series,
        reader=reader("coordinator"),
        reopen=lambda: reader("coordinator"),
        genesis=SimpleNamespace(decision=genesis_body),
        control_writes=writes,
        additional_state=dict(rpc.values),
    )
    history = await make_historical(case, "exact_runtime", monkeypatch, root)
    history = await make_history_case(history, monkeypatch, root, distance=end - first + 1)
    history.reader = history.new_reader(maximum_bytes=128 * 1024**2)
    files, readback = (
        StandingRewardFiles(
            root / name, maximum_package_bytes=64 * 1024**2, maximum_witness_bytes=64 * 1024**2
        )
        for name in ("delivery", "readback")
    )
    rule = opportunity_rule(manifest, series, policy)
    coverage = RewardCoverageJournal(root / "coverage", rule, expected_rule_sha256=digest(rule))
    offers = StandingRewardOffers(
        series=series,
        policy=policy,
        manifest=manifest,
        handoff=handoff,
        settlements=settled.output.parent,
        files=files,
        coverage=coverage,
    )
    unavailable = True

    async def no_opportunity(_):
        pytest.fail("first activation requires the legacy fence, not predecessor coverage")

    def build():
        def signer(name):
            async def sign(body):
                signatures[(name, digest(body))] += 1
                return sign_object(body, wallet(name))

            return RewardDecisionSigner(
                RewardDecisionJournal(
                    root / ("signer-" + name),
                    series,
                    policy,
                    wallet(name).hotkey.ss58_address,
                    expected_chain_config_sha256=digest(config),
                    maximum_bytes=32 * 1024**2,
                ),
                sign,
            )

        reviewers = {
            name: StandingRewardDecisionReviewer(
                reader=case.reader if name == "Charlie" else reader("peer"),
                provider=item.provider,
                history=history.reader,
                files=files,
                manifest=manifest,
                promotion_store=settled.nodes[name].promotion,
                handoff=handoff,
                opportunity=no_opportunity,
                maximum_promotion_bytes=1024**2,
                maximum_history_blocks=4096,
            )
            for name in ("Charlie", "Dave")
        }
        peer = signer("Dave")

        async def vote(body, prefix):
            if unavailable:
                raise ConnectionError("independent reviewer offline")
            review = await reviewers["Dave"].review(body, prefix)
            return await peer.attest(review)

        publisher = StandingControlPublisher(
            reader=case.reader,
            provider=item.provider,
            history=history.reader,
            journal=RewardControlTransactionJournal(
                root / "transactions",
                series,
                config_sha256=digest(config),
                maximum_bytes=32 * 1024**2,
            ),
            files=files,
            signer=wallet("Ferdie").hotkey,
            mortality_period=8,
            maximum_history_blocks=4096,
        )
        return StandingRewardCoordinator(
            reviewer=reviewers["Charlie"],
            publisher=publisher,
            signer=signer("Charlie"),
            readback=readback,
            offers=offers,
            voters=(vote,),
        )

    async def converge(coordinator):
        with coordinator.publisher.hold_writer():
            for _ in range(100):
                try:
                    result = await coordinator.step()
                except HistoricalHeaderRecoveryPending:
                    continue
                if result.status not in {"history_pending", "review_pending"}:
                    return result
        pytest.fail("native reward control did not converge")

    try:
        current_control_finality(history, first)
        coordinator = build()
        assert (await converge(coordinator)).status == "quorum_pending"
        assert coordinator.signer.journal.load(0).decision == genesis_body
        unavailable = False
        assert (await converge(coordinator)).status == "certified_delivery_pending"
        admission = coordinator.signer.journal.prefix(1)[0]
        assert admission.decision == genesis_body
        assert (await converge(coordinator)).status == "delivery_pending"
        readback.retain_decision(admission)
        # The RPC port now proves the admission, before any activation is signed.
        current_control_finality(history, activation_block)
        unavailable = True
        assert (await converge(coordinator)).status == "quorum_pending"
        intent = coordinator.signer.journal.load(1)
        assert intent.decision == activation_body
        assert files.package(activation.package_sha256) == package
        assert readback.root != files.root

        # Restart with the original reviewed intent; no manual activation file.
        counts = dict(signatures)
        case.reader, history.reader = case.reopen(), history.new_reader(maximum_bytes=128 * 1024**2)
        coordinator = build()
        unavailable = False
        assert (await converge(coordinator)).status == "certified_delivery_pending"
        assert coordinator.signer.journal.load(1) == intent
        assert (
            signatures[("Charlie", digest(activation_body))]
            == counts[("Charlie", digest(activation_body))]
        )
        certified = coordinator.signer.journal.prefix(2)[1]
        assert certified.decision == activation_body
        assert (await converge(coordinator)).status == "delivery_pending"
        readback.retain_decision(certified)
        assert (await converge(coordinator)).status == "delivery_pending"
        readback.retain_package(package)
        current_control_finality(history, end)
        assert (await converge(coordinator)).status == "series_control_published"
        assert coordinator.publisher.journal.pending() is None

        # Cold validator preparation from the delivered originals is independent
        # of the coordinator and of wall-clock renewal or policy expiry.
        assert end > policy.valid_through_block
        prepared = StandingRewardPreparation(
            reader("validator"),
            settled.nodes["Dave"].promotion,
            manifest,
            maximum_promotion_bytes=1024**2,
            maximum_package_bytes=64 * 1024**2,
        )
        native_history = await history.reader.verified_prefix(end)
        control = await history.reader.review_control(item.provider, end)
        result = await prepared.prepare_initial(
            readback.package(activation.package_sha256),
            control=control,
            history=native_history,
            source=readback.decision,
        )
        assert result.activation == activation and result.allocation == package.allocation
        assert not result.chain_submission_authorized
        assert max(signatures.values()) == 1
        assert not any(method.startswith("author_") for method in history.rpc_calls)
        publish_private_model(
            root / "result.json",
            {
                "schema": "umi-native-reward-pipeline-test/1",
                "package_sha256": digest(package),
                "allocation_sha256": digest(result.allocation),
                "activation_sha256": digest(activation),
                "control_decision_sha256": digest(certified.decision),
                "package_bytes": len(canonical_json_bytes(package)),
                "coordinator_status": "series_control_published",
                "validator_preparation": "native_initial_package_replayed",
                "service_budget": package.service.statement.allocation.service_budget,
                "model_budget": package.service.statement.allocation.model_budget,
                "minimum_validator_ms": manifest.opportunity.minimum_validator_ms,
                "policy_valid_through_block": policy.valid_through_block,
                "reviewed_at_block": result.reviewed_at_block,
                "maximum_signatures_per_evaluator_object": max(signatures.values()),
                "chain_inclusion": "synthetic_rpc_fixture",
                "transaction_submitted": False,
                "installed_host_qualified": False,
            },
        )
    finally:
        await item.provider.aclose()
