"""Original signed baseline exports, partial timelines and durable source reuse."""

import pytest

from umi import competition_cohort_request_terminal as terminal_module
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_order_queue import SignedOrderDeliveryReceipt, delivery_receipt
from umi.competition_cohort_orders import recoverable_order_job
from umi.competition_cohort_request_files import RequestCompletionFiles
from umi.competition_cohort_request_partial import (
    PartialRequestManifest,
    SharedPartialRequestManifest,
    parse_partial_request_manifest,
    review_partial_request,
)
from umi.competition_cohort_request_terminal import (
    RequestExecutionArchive,
    SharedRequestExecutionArchive,
    parse_request_execution_archive,
    read_request_terminal,
    seal_request_terminal,
)
from umi.competition_cohort_reward_package import ReplayObjectCollector
from umi.competition_verification_reuse import VerificationReuse
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_executor import scenario as scenario
from .test_competition_cohort_incumbent_reuse import other_assignment
from .test_competition_cohort_paired_incumbent_reuse import finish, paired
from .test_competition_cohort_paired_incumbent_reuse import harness as harness
from .test_competition_cohort_paired_incumbent_reuse import original_harness as original_harness
from .test_competition_cohort_recovery import signatures
from .test_open_competition import wallet


async def seal(e, slot):
    async def sign(body):
        return sign_object(body, wallet(e.r.names[identity(e.cfg.signer)]))

    return await seal_request_terminal(e.journal(), slot, sign)


def original_order_assignment(e, assignment):
    """A fully valid historical order does not authorize new sampling semantics."""
    order = assignment.certificate.order.model_copy(
        update={
            "schema_": "umi-recoverable-evaluation-order/1",
            "incumbent_observation_mode": None,
        }
    )
    certificate = assignment.certificate.model_copy(
        update={"order": order, "signatures": signatures(order)}
    )
    receipt = delivery_receipt(certificate, assignment.delivery.receipt.evaluator_hotkey)
    return assignment.model_copy(
        update={
            "certificate": certificate,
            "delivery": SignedOrderDeliveryReceipt(
                receipt=receipt,
                signature=sign_object(receipt, wallet(e.r.names[identity(e.cfg.signer)])),
            ),
        }
    )


def replace_terminal_assignment(e, signed, assignment, values):
    def put(value):
        values[digest(value)] = canonical_json_bytes(value)
        return digest(value)

    archive = parse_request_execution_archive(values[signed.terminal.execution_archive_sha256])
    archive = archive.model_copy(update={"assignment_sha256": put(assignment)})
    body = signed.terminal.model_copy(
        update={
            "assignment_sha256": digest(assignment),
            "execution_archive_sha256": put(archive),
        }
    )
    changed = signed.model_copy(
        update={
            "terminal": body,
            "signature": sign_object(body, wallet(e.r.names[identity(e.cfg.signer)])),
        }
    )
    put(changed)
    return changed


@pytest.fixture
async def shared_archive(execution):
    e = execution
    paired(e)
    e.source_evidence = await finish(e, e.assignment)
    e.source_terminal = await seal(e, e.r.slot)
    assignment, e.consumer_slot, _scenario = await other_assignment(e)
    e.consumer_assignment = assignment
    e.consumer_evidence = await finish(e, assignment)
    e.consumer_terminal = await seal(e, e.consumer_slot)
    e.objects = JournalEndpointObjects(e.journal().journal)
    e.archive = parse_request_execution_archive(
        e.objects(e.consumer_terminal.terminal.execution_archive_sha256)
    )
    return e


async def test_shared_archive_keeps_source_originals_and_reuses_after_restart(
    shared_archive, tmp_path, monkeypatch
):
    e = shared_archive
    assert isinstance(e.archive, SharedRequestExecutionArchive)
    source_raw = e.objects(e.source_terminal.terminal.execution_archive_sha256)
    assert (
        canonical_json_bytes(RequestExecutionArchive.model_validate_json(source_raw)) == source_raw
    )
    with pytest.raises(ValueError):
        RequestExecutionArchive.model_validate_json(canonical_json_bytes(e.archive))
    source = ReplayObjectCollector(e.objects, 64 * 1024**2)
    params = dict(opened_at_block=0, completed_by_block=e.r.h.block)
    root = tmp_path / "verification"
    with VerificationReuse(root, owner="shared-reader").selected():
        assert (
            read_request_terminal(e.consumer_terminal, source, e.journal().policy, **params)
            == e.consumer_assignment
        )
    assert digest(e.source_terminal) in source.values
    source_archive = parse_request_execution_archive(source_raw)
    assert set(source_archive.steps) <= set(source.values)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("completed original replay must be reused after restart")

    monkeypatch.setattr(terminal_module, "replay_execution_steps", forbidden)
    monkeypatch.setattr(terminal_module, "replay_shared_incumbent_steps", forbidden)
    restored = ReplayObjectCollector(e.objects, 64 * 1024**2)
    with VerificationReuse(root, owner="shared-reader").selected():
        assert (
            read_request_terminal(e.consumer_terminal, restored, e.journal().policy, **params)
            == e.consumer_assignment
        )
    assert dict(restored.values) == dict(source.values)
    assert len(e.calls) == 3 * len(e.job.cases)


@pytest.mark.parametrize("unauthorized", ["source", "consumer"])
async def test_shared_archive_requires_both_prospective_signed_capabilities(
    shared_archive, unauthorized
):
    e = shared_archive
    source = ReplayObjectCollector(e.objects, 64 * 1024**2)
    params = dict(opened_at_block=0, completed_by_block=e.r.h.block)
    read_request_terminal(e.consumer_terminal, source, e.journal().policy, **params)
    values = dict(source.values)
    if unauthorized == "consumer":
        signed = replace_terminal_assignment(
            e,
            e.consumer_terminal,
            original_order_assignment(e, e.consumer_assignment),
            values,
        )
    else:
        source_terminal = replace_terminal_assignment(
            e, e.source_terminal, original_order_assignment(e, e.assignment), values
        )
        archive = e.archive.model_copy(
            update={
                "incumbent_source": e.archive.incumbent_source.model_copy(
                    update={"terminal_sha256": digest(source_terminal)}
                )
            }
        )
        values[digest(archive)] = canonical_json_bytes(archive)
        body = e.consumer_terminal.terminal.model_copy(
            update={"execution_archive_sha256": digest(archive)}
        )
        signed = e.consumer_terminal.model_copy(
            update={
                "terminal": body,
                "signature": sign_object(body, wallet(e.r.names[identity(e.cfg.signer)])),
            }
        )
    with pytest.raises(ValueError, match="prospective signed order capability"):
        read_request_terminal(signed, values.__getitem__, e.journal().policy, **params)


@pytest.mark.parametrize(
    "damage", ["signature", "quorum", "source_archive", "borrowed_step", "timing"]
)
async def test_shared_archive_refuses_changed_source_or_originals(shared_archive, damage):
    e = shared_archive
    source = ReplayObjectCollector(e.objects, 64 * 1024**2)
    read_request_terminal(
        e.consumer_terminal,
        source,
        e.journal().policy,
        opened_at_block=0,
        completed_by_block=e.r.h.block,
    )
    values = dict(source.values)

    def put(value):
        key = digest(value)
        values[key] = canonical_json_bytes(value)
        return key

    archive = e.archive
    if damage in {"signature", "quorum", "source_archive"}:
        signed = e.source_terminal
        if damage == "signature":
            signed = signed.model_copy(
                update={
                    "signature": signed.signature.model_copy(update={"signature": "0x" + "00" * 64})
                }
            )
        elif damage == "quorum":
            assignment = e.assignment.model_copy(
                update={
                    "certificate": e.assignment.certificate.model_copy(
                        update={"signatures": e.assignment.certificate.signatures[:1]}
                    )
                }
            )
            original = parse_request_execution_archive(
                values[signed.terminal.execution_archive_sha256]
            )
            changed = original.model_copy(update={"assignment_sha256": put(assignment)})
            body = signed.terminal.model_copy(
                update={
                    "assignment_sha256": digest(assignment),
                    "execution_archive_sha256": put(changed),
                }
            )
            signed = signed.model_copy(
                update={
                    "terminal": body,
                    "signature": sign_object(body, wallet(e.r.names[identity(e.cfg.signer)])),
                }
            )
        else:
            body = signed.terminal.model_copy(update={"execution_archive_sha256": put(archive)})
            signed = signed.model_copy(
                update={
                    "terminal": body,
                    "signature": sign_object(body, wallet(e.r.names[identity(e.cfg.signer)])),
                }
            )
        archive = archive.model_copy(
            update={
                "incumbent_source": archive.incumbent_source.model_copy(
                    update={"terminal_sha256": put(signed)}
                )
            }
        )
    elif damage == "borrowed_step":
        from umi.competition_execution import ExecutionStep

        keys = list(archive.steps)
        step = ExecutionStep.model_validate_json(values[keys[1]])
        keys[1] = put(
            step.model_copy(
                update={"finished": step.finished.model_copy(update={"block": e.r.h.block})}
            )
        )
        archive = archive.model_copy(update={"steps": tuple(keys)})
    else:
        archive = archive.model_copy(
            update={
                "incumbent_source": archive.incumbent_source.model_copy(
                    update={"reuse_observed_at": e.source_evidence.steps[0].started}
                )
            }
        )
    body = e.consumer_terminal.terminal.model_copy(
        update={"execution_archive_sha256": put(archive)}
    )
    signed = e.consumer_terminal.model_copy(
        update={
            "terminal": body,
            "signature": sign_object(body, wallet(e.r.names[identity(e.cfg.signer)])),
        }
    )
    with pytest.raises(ValueError):
        read_request_terminal(
            signed,
            values.__getitem__,
            e.journal().policy,
            opened_at_block=0,
            completed_by_block=e.r.h.block,
        )


@pytest.mark.parametrize("unauthorized", ["source", "consumer"])
async def test_partial_shared_export_keeps_old_times_and_all_source_objects(
    execution, tmp_path, unauthorized
):
    e = execution
    executor = paired(e)
    await finish(e, e.assignment)
    source_terminal = await seal(e, e.r.slot)
    assignment, slot, _scenario = await other_assignment(e)
    e.r.h.block += 1
    assert await executor.advance(assignment) is None
    owner = e.journal()
    files = RequestCompletionFiles(tmp_path / "published")
    key = files.publish_partial(owner, slot, completed_by_block=e.r.h.block)
    manifest = parse_partial_request_manifest(files.objects(key))
    assert isinstance(manifest, SharedPartialRequestManifest)
    assert manifest.incumbent_source.terminal_sha256 == digest(source_terminal)
    assert len(manifest.steps) == len(e.job.cases) + 1
    with pytest.raises(ValueError):
        PartialRequestManifest.model_validate_json(canonical_json_bytes(manifest))
    assert (
        review_partial_request(
            key,
            files.objects,
            owner.policy,
            assignment.certificate,
            opened_at_block=0,
            completed_by_block=e.r.h.block,
        )
        == assignment
    )
    assert files.current_model_partial(owner, slot, completed_by_block=e.r.h.block) == key
    source_archive = parse_request_execution_archive(
        files.objects(source_terminal.terminal.execution_archive_sha256)
    )
    assert all(files.objects(sha) for sha in source_archive.steps)
    assert len(e.calls) == 2 * len(e.job.cases) + 1
    job = recoverable_order_job(assignment.certificate.order, owner.config.signer)
    assert all(owner.head(job, n) is None for n in range(1, 2 * len(e.job.cases), 2))
    source = ReplayObjectCollector(files.objects, 64 * 1024**2)
    params = dict(opened_at_block=0, completed_by_block=e.r.h.block)
    review_partial_request(key, source, owner.policy, assignment.certificate, **params)
    values = dict(source.values)
    expected = assignment.certificate
    if unauthorized == "consumer":
        original = original_order_assignment(e, assignment)
        values[digest(original)] = canonical_json_bytes(original)
        manifest = manifest.model_copy(update={"assignment_sha256": digest(original)})
        expected = original.certificate
    else:
        changed = replace_terminal_assignment(
            e, source_terminal, original_order_assignment(e, e.assignment), values
        )
        manifest = manifest.model_copy(
            update={
                "incumbent_source": manifest.incumbent_source.model_copy(
                    update={"terminal_sha256": digest(changed)}
                )
            }
        )
    values[digest(manifest)] = canonical_json_bytes(manifest)
    with pytest.raises(ValueError, match="prospective signed order capability"):
        review_partial_request(
            digest(manifest), values.__getitem__, owner.policy, expected, **params
        )
