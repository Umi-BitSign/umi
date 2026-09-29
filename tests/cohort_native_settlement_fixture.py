"""Recurring settlement of native intake/request outputs, with fixture finality.

No completed package, scoring vote, phase signature or allocation is supplied.
File delivery copies immutable native exports between separate owner stores.
"""

import asyncio
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_coordinator import CohortProgressIntent
from umi.competition_cohort_reward_package import CohortRewardPackage
from umi.competition_cohort_settlement_boot import settlement_store
from umi.competition_cohort_settlement_config import SettlementServiceConfig
from umi.competition_cohort_settlement_proofs import SettlementRegistrationFiles
from umi.competition_cohort_settlement_service import CohortSettlementService
from umi.competition_store import CompetitionStore
from umi.open_competition import digest, sign_object
from umi.private_files import ensure_private_directory

from .test_open_competition import wallet


def copy_originals(origin, target):
    for path in origin.rglob("*.json"):
        destination = target / path.relative_to(origin)
        ensure_private_directory(destination.parent)
        if destination.exists():
            assert destination.read_bytes() == path.read_bytes()
        else:
            destination.write_bytes(path.read_bytes())
            destination.chmod(0o600)


async def run_settlement(o, evaluators, root, signatures, interrupt, *, mixed=False):
    h, series = o.h, o.config.series
    plan = next(plan for plan in series.cohorts if digest(plan) == h.cohort)
    nodes, stacks, configs = {}, {}, {}

    def start(name):
        base = root / name
        config = configs.setdefault(
            name,
            SettlementServiceConfig(
                schema="umi-cohort-settlement-config/2"
                if name == "Charlie"
                else "umi-cohort-settlement-config/1",
                role="coordinator" if name == "Charlie" else "reviewer",
                original_sources=o.config.lifecycle.sources if name == "Charlie" else None,
                series=series,
                policy=h.intake.policy,
                manifest=o.config.manifest,
                chain=o.config.dispatch.origins.model_copy(
                    update={"state_directory": str(base / "chain")}
                ),
                signer_hotkey=wallet(name).hotkey.ss58_address,
                proposer_hotkey=wallet("Charlie").hotkey.ss58_address,
                signer_key_file=str(base / "key"),
                executions=(evaluators[name].config.execution,),
                state_directory=str(base / "state"),
                inputs_directory=str(base / "inputs"),
                history_directory=o.config.lifecycle.settlement_history_directory
                if name == "Charlie"
                else str(base / "history"),
                promotion_directory=str(base / "promotion"),
                settlement_directory=str(base / "settled"),
                proof_import_directory=str(base / "proof-in"),
                proof_export_directory=str(base / "proof-out"),
                exchange_inbox=str(base / "exchange-in"),
                exchange_outbox=str(base / "exchange-out"),
                maximum_package_bytes=64 * 1024**2,
                maximum_promotion_bytes=1024**2,
                maximum_state_bytes=128 * 1024**2,
                poll_seconds=1,
            ),
        )
        if name in stacks:
            stacks.pop(name).close()
        stack = stacks[name] = ExitStack()
        store = stack.enter_context(
            settlement_store(
                Path(config.state_directory) / digest(series) / h.cohort, config.maximum_state_bytes
            )
        )
        proofs = SettlementRegistrationFiles(
            h.provider,
            inbox=Path(config.proof_import_directory),
            outbox=Path(config.proof_export_directory),
        )
        promotion = CompetitionStore(Path(config.promotion_directory), h.intake.policy)
        if not (promotion.directory / "model-reward-artifacts" / digest(h.model)).exists():
            archive = base / "model-archive"
            preserve_bundle(
                h.model,
                Path(h.intake.config.directory).parent / "model-submission",
                archive,
                h.intake.policy,
            )
            promotion.initialize_baseline(h.model, archive)
            preserve_bundle(
                h.model,
                o.service.models.owner.archive / digest(h.model) / "model",
                promotion.directory / "model-reward-artifacts",
                h.intake.policy,
            )

        async def sign(body):
            signatures[(name, digest(body))] += 1
            return sign_object(body, wallet(name))

        node = CohortSettlementService(
            config,
            plan,
            store=store,
            provider=h.provider,
            proofs=proofs,
            promotion=promotion,
            executions=(evaluators[name].execution,),
            sign=sign,
        )
        nodes[name] = node
        return node

    def deliver():
        for config in configs.values():
            copy_originals(
                Path(o.config.lifecycle.proof_export_directory), Path(config.proof_import_directory)
            )
            for folder in ("objects", "model-reward-acceptances"):
                copy_originals(
                    o.h.owner.promotion.directory / folder,
                    Path(config.promotion_directory) / folder,
                )
        for sender, receiver in (("Charlie", "Dave"), ("Dave", "Charlie")):
            a, z = configs[sender], configs[receiver]
            copy_originals(Path(a.proof_export_directory), Path(a.proof_import_directory))
            copy_originals(Path(a.proof_export_directory), Path(z.proof_import_directory))
            copy_originals(Path(a.exchange_outbox), Path(z.exchange_inbox))
            if a.role == "coordinator":
                copy_originals(Path(a.history_directory), Path(z.history_directory))
                copy_originals(Path(a.exchange_outbox) / "inputs", Path(z.inputs_directory))

    async def run_until(selected, done, *, timeout=600):
        stop = asyncio.Event()
        tasks = [asyncio.create_task(n.run(stop)) for n in selected]

        async def wait():
            while not done():
                deliver()
                for task in tasks:
                    if task.done():
                        task.result()
                        raise AssertionError("settlement exited before completion")
                await asyncio.sleep(0.1)

        try:
            await asyncio.wait_for(wait(), timeout)
        except TimeoutError as error:
            raise AssertionError({name: n.last_report for name, n in nodes.items()}) from error
        finally:
            stop.set()
            await asyncio.gather(*tasks)

    try:
        a, z = start("Charlie"), start("Dave")
        deliver()
        # References cannot be published at the request-closure block itself.
        with pytest.raises(ValueError, match="reference publication must follow"):
            await a.tick()
        h.block += 1
        if interrupt:

            def intent_retained():
                if not a.store.has_published_history(h.cohort):
                    return False
                state, _ = a.store.status(h.cohort)
                return (
                    a.store.progress_intent(h.cohort, state.tip_sha256, CohortProgressIntent)
                    is not None
                )

            await run_until((a,), intent_retained)
            before = dict(signatures)
            h.block += 3000
            a = start("Charlie")
            assert dict(signatures) == before
        output = Path(a.config.settlement_directory) / (h.cohort + ".json")
        assert not output.exists()
        await run_until((a, z), output.exists)
        assert a.last_report == "package_published"
        original = output.read_bytes()
        package = CohortRewardPackage.model_validate_json(original)
        service, allocation = package.service.statement.allocation, package.allocation
        assert (service.service_budget, service.model_budget) == (32767, 32768)
        assert bool(service.recipients) == mixed
        assert allocation.burn_weight == (25205 if mixed else 32767)
        expected = {wallet("Alice").hotkey.ss58_address: 32768}
        if mixed:
            expected[wallet("Bob").hotkey.ss58_address] = 7562
        assert {r.hotkey: r.raw_weight for r in allocation.recipients} == expected
        award = allocation.model_award
        assert award is not None and len(award.candidates) == 1
        candidate = award.candidates[0]
        assert candidate.eligible and candidate.aggregate == candidate.baseline_aggregate
        assert award.credits[0].submission_sha256 == candidate.submission_sha256
        objects = {item.sha256 for item in package.objects}
        for receipt in award.acceptances:
            assert receipt.acceptance.rights_evidence_sha256 in objects
            assert receipt.acceptance.reconstruction_evidence_sha256 in objects
        assert not package.chain_submission_authorized
        # Publication survives a delayed restart without issuing new signatures.
        before = dict(signatures)
        h.block += 3000
        a = start("Charlie")
        await a.tick()
        assert output.read_bytes() == original
        assert dict(signatures) == before
        assert max(signatures.values()) == 1
        return SimpleNamespace(package=package, nodes=nodes, output=output)
    finally:
        for stack in stacks.values():
            stack.close()
