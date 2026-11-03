"""Durable publication completion, separate from native verification authority.

The native closure receipt remains authoritative for completed semantic work.
This owner-private projection binds that exact receipt to delivered outputs and
proof observations. Reuse checks current authority and cheap selected-file facts;
damage repairs delivery without replaying the completed native evidence graph.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_intake import history_tip
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_request_closure import CohortRequestClosure
from .competition_cohort_request_inventory import request_inventory_observations
from .competition_cohort_request_progress import certified_request_prefix, request_closure_progress
from .competition_cohort_service_closure import (
    CohortServiceRequestClosure,
    review_service_request_closure,
)
from .competition_cohort_service_partial import paid_partial_observations
from .competition_execution import ExecutionBoundary
from .competition_verification_reuse import VerificationReceiptUnavailable, _event, _identity
from .competition_verification_snapshot import SnapshotObject, Stamp, _stamp
from .competition_work_progress import WorkProgress, check_work_cancelled
from .host_memory_request_bounds import stage_bounds
from .open_competition import digest
from .private_files import read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class PublicationOutput(StrictProtocolModel):
    key: Hex32
    stamp: Stamp
    descriptor: SnapshotObject | None = None
    metadata_stamp: Stamp | None = None


class PublicationCompletion(StrictProtocolModel):
    schema_: Literal["umi-private-cohort-publication-completion/1"] = Field(alias="schema")
    native_identity: Hex32
    native_checksum: Hex32
    context: Hex32
    intake_bytes: Annotated[int, Field(ge=0)]
    history: CohortOrderHistory
    closure: CohortServiceRequestClosure
    benchmark: CohortRequestClosure
    observations: Annotated[tuple[ExecutionBoundary, ...], Field(max_length=65536)]
    outputs: Annotated[tuple[PublicationOutput, ...], Field(max_length=65536)]
    history_stamp: Stamp | None = None


class RequestPublicationCompletion:
    def __init__(self, publisher):
        self.publisher = publisher
        self.slot = digest(["request_publication_completion/1", publisher.source.cohort])

    @property
    def store(self):
        return self.publisher.verification_reuse

    @property
    def path(self):
        publisher = self.publisher
        return publisher.history_directory / (publisher.source.cohort + ".json")

    def context(self, captured, native_identity, native_checksum):
        publisher, owner = self.publisher, self.publisher.source
        _history, prefix, _decisions, record, _index, _state, seals, _records, intake = captured
        return digest(
            _identity(
                dict(
                    version="request_publication_completion/1",
                    native_identity=native_identity,
                    native_checksum=native_checksum,
                    owner=self.store.owner,
                    runtime=self.store.runtime,
                    bounds=stage_bounds(),
                    policy=owner.intake.policy,
                    roster=owner.roster,
                    transport=owner.transport,
                    catalogs=owner.catalogs,
                    prefix=prefix,
                    record=record,
                    seals=seals,
                    intake=intake,
                    history_directory=str(publisher.history_directory),
                )
            )
        )

    def native_receipt(self, captured, closure):
        owner = self.publisher.source
        _history, prefix, decisions, record, _index, _state, seals, records, _intake = captured
        key, receipt = review_service_request_closure.retained_receipt(
            closure,
            owner.roster,
            self.publisher.objects,
            owner.intake.policy,
            prefix,
            owner.transport,
            expected_catalogs=owner.catalogs,
            expected_seals=seals,
            decision_source=decisions.__getitem__,
            intake_records=records,
            expected_tip_sha256=history_tip(prefix),
            current_block=record.progress.observed_at_block,
        )
        if receipt is None:
            self.repair_required("original_native_closure_receipt_missing_or_damaged")
        if CohortServiceRequestClosure.model_validate_json(receipt.result_json) != closure:
            self.repair_required("original_native_closure_receipt_changed")
        return key, receipt

    def draft(self, captured, closure, benchmark, history, observations):
        key, receipt = self.native_receipt(captured, closure)
        return PublicationCompletion(
            schema="umi-private-cohort-publication-completion/1",
            native_identity=key,
            native_checksum=receipt.checksum,
            context=self.context(captured, key, receipt.checksum),
            intake_bytes=sum(len(raw) for _, raw in captured[7]),
            history=history,
            closure=closure,
            benchmark=benchmark,
            observations=observations,
            outputs=(),
        )

    @staticmethod
    def repair_required(reason):
        _event(
            "request_publication_completion",
            "repair_required",
            planning_range=(0, 30),
            planning_basis=reason,
            planning_scope="retained_publication_metadata_only_no_native_replay",
        )
        raise VerificationReceiptUnavailable("request publication completion: " + reason)

    def load(self, current_block=None):
        with self.store.exclusive():
            receipt = self.store.load(self.slot)
            if receipt is not None:
                try:
                    if receipt.dependencies:
                        raise ValueError("completion has unexpected dependency wrapper")
                    return PublicationCompletion.model_validate_json(receipt.result_json)
                except ValueError:
                    self.repair_required("completion_metadata_damaged")
            if any(
                (directory / (self.slot + suffix)).exists()
                for directory in (self.store.directory, self.store.legacy_directory)
                if directory is not None
                for suffix in (".json", ".complete")
            ):
                self.repair_required("completion_metadata_missing_or_damaged")
            return None

    def _migrate(self, current_block):
        publisher = self.publisher
        with WorkProgress(
            "request_publication_completion_migration", 1, unit="handoffs"
        ) as progress:
            captured = publisher._capture(current_block)
            if captured is None:
                self.repair_required("retained_handoff_has_no_current_closure")
            history, _prefix, decisions, record, index, _state, seals, _records, _intake = captured
            history_stamp = _stamp(self.path)
            retained = read_private_model(self.path, CohortOrderHistory, maximum_bytes=8 * 1024**2)
            if _stamp(self.path) != history_stamp:
                self.repair_required("retained_handoff_changed_during_read")
            expected = publisher._handoff(history, decisions, index)
            if retained != expected:
                self.repair_required("retained_handoff_changed_its_certified_history")
            closure = CohortServiceRequestClosure.model_validate_json(
                publisher.objects(record.progress.phase_result_sha256)
            )
            benchmark = CohortRequestClosure.model_validate_json(
                publisher.objects(closure.benchmark_closure_sha256)
            )
            key, native = self.native_receipt(captured, closure)
            selected = {}
            for dependency in native.dependencies:
                if dependency.kind == "objects":
                    selected[dependency.key] = dependency.sha256
                elif dependency.kind == "decision_source":
                    if (
                        hashlib.sha256(canonical_json_bytes(decisions[dependency.key])).hexdigest()
                        != dependency.sha256
                    ):
                        self.repair_required("retained_closure_decision_changed")
                else:
                    self.repair_required("retained_closure_dependency_kind_unsupported")
            selected.setdefault(
                record.progress.phase_result_sha256,
                hashlib.sha256(canonical_json_bytes(closure)).hexdigest(),
            )
            _expected, evidence = request_closure_progress(
                closure, record.service, _state, tail=benchmark.tail
            )
            selected.setdefault(
                record.progress.evidence_sha256,
                hashlib.sha256(canonical_json_bytes(evidence)).hexdigest(),
            )
            observations = publisher._observations(
                retained,
                benchmark,
                (
                    *request_inventory_observations(benchmark, publisher.objects),
                    *paid_partial_observations(closure, publisher.objects),
                ),
            )
            completion = PublicationCompletion(
                schema="umi-private-cohort-publication-completion/1",
                native_identity=key,
                native_checksum=native.checksum,
                context=self.context(captured, key, native.checksum),
                intake_bytes=sum(len(raw) for _, raw in captured[7]),
                history=retained,
                closure=closure,
                benchmark=benchmark,
                observations=observations,
                outputs=self.snapshot(selected, seals),
                history_stamp=history_stamp,
            )
            # The genuine final handoff is only a migration prerequisite. The
            # caller still checks every proof's own durable completion before
            # treating this projection as an unchanged published result.
            progress.advance()
            return completion

    def snapshot(self, keys, seals):
        publisher = self.publisher
        derived = {digest(seal): seal for seal in seals}
        originals = tuple(sorted(set(keys) - derived.keys()))
        outputs = []
        with (
            publisher.objects.verification_batch(originals),
            WorkProgress(
                "request_publication_delivery", len(originals) + len(derived), unit="objects"
            ) as progress,
        ):
            for key in originals:
                publisher.objects.ensure(key, publisher.files)
                descriptor, metadata_stamp = publisher.objects.descriptor_snapshot(key)
                wanted = keys.get(key) if isinstance(keys, dict) else None
                if wanted is not None and descriptor.sha256 != wanted:
                    self.repair_required("retained_descriptor_differs_from_native_receipt")
                outputs.append(
                    PublicationOutput(
                        key=key,
                        stamp=descriptor.stamp,
                        descriptor=descriptor,
                        metadata_stamp=metadata_stamp,
                    )
                )
                progress.advance()
            for key in sorted(derived):
                publisher.objects.ensure(
                    key, lambda selected: canonical_json_bytes(derived[selected]), derived=True
                )
                outputs.append(PublicationOutput(key=key, stamp=_stamp(publisher.files._path(key))))
                progress.advance()
        return tuple(sorted(outputs, key=lambda value: value.key))

    def repair_outputs(self, completion, changed):
        _event(
            "request_publication_completion",
            "repair_required",
            len(changed),
            planning_range=(0, max(30, len(changed))),
            planning_basis="changed_output_metadata_or_restore_only",
            planning_scope="affected_publication_outputs_no_native_replay",
        )
        selected = {
            value.key: value.descriptor.sha256
            for value in completion.outputs
            if value.key in changed and value.descriptor is not None
        }
        seals = tuple(
            seal
            for seal in (queue.retained_seal() for queue in self.publisher.source.queues)
            if digest(seal) in changed
        )
        repaired = {value.key: value for value in self.snapshot(selected, seals)}
        return completion.model_copy(
            update={
                "outputs": tuple(repaired.get(value.key, value) for value in completion.outputs)
            }
        )

    def check(self, completion, current_block):
        publisher = self.publisher
        captured = publisher._capture(current_block, include_records=False)
        if captured is None:
            self.repair_required("completed_publication_lost_its_closure")
        native = self.native_current(completion)
        output_bytes = sum(
            value.descriptor.size for value in completion.outputs if value.descriptor is not None
        ) + sum(len(canonical_json_bytes(seal)) for seal in captured[6])
        if max(output_bytes, completion.intake_bytes) > publisher.source.replay_bytes:
            raise ValueError("request publication export exceeds its active byte bound")
        if self.context(captured, native.identity, native.checksum) != completion.context:
            self.repair_required("completed_publication_context_changed")
        history, prefix, decisions, record, index, state, _seals, _records, _intake = captured
        if publisher._handoff(history, decisions, index) != completion.history:
            self.repair_required("completed_publication_history_changed")
        expected, evidence = request_closure_progress(
            completion.closure, record.service, state, tail=completion.benchmark.tail
        )
        if expected != record.progress:
            self.repair_required("completed_publication_progress_changed")

        def evidence_source(key):
            if key != digest(evidence):
                raise ValueError("completion requested an unbound progress object")
            return canonical_json_bytes(evidence)

        if (
            certified_request_prefix(
                completion.closure,
                evidence_source,
                publisher.source.intake.policy,
                history,
                decision_source=decisions.__getitem__,
                expected_tip_sha256=history_tip(history),
                current_block=current_block,
                tail=completion.benchmark.tail,
            )
            != prefix
        ):
            self.repair_required("completed_publication_certified_prefix_changed")
        return self.output_fences(completion)

    def native_current(self, completion):
        native = self.store.load(completion.native_identity)
        if native is None or native.checksum != completion.native_checksum:
            self.repair_required("original_native_closure_receipt_missing_or_changed")
        return native

    def output_fences(self, completion):
        publisher = self.publisher
        originals = tuple(value.key for value in completion.outputs if value.descriptor is not None)
        publisher.objects._batch_fence(originals)
        changed = []
        with WorkProgress(
            "request_publication_output_fences", len(completion.outputs), unit="objects"
        ) as progress:
            for value in completion.outputs:
                check_work_cancelled()
                try:
                    unchanged = _stamp(publisher.files._path(value.key)) == value.stamp and (
                        value.descriptor is None
                        or _stamp(publisher.objects.directory / (value.key + ".json"))
                        == value.metadata_stamp
                    )
                except (OSError, ValueError):
                    unchanged = False
                if not unchanged:
                    changed.append(value.key)
                progress.advance()
        publisher.objects._batch_fence(originals)
        try:
            history_current = _stamp(self.path) == completion.history_stamp
        except (OSError, ValueError):
            history_current = False
        return tuple(changed), history_current

    def remember(self, completion):
        self.store.remember(self.slot, (), canonical_json_bytes(completion).decode())
        _event("request_publication_completion", "retained", len(completion.outputs))
