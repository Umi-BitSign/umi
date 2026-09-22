"""Wallet-free collection and delivery of independently signed settlements."""

from __future__ import annotations

import asyncio
from pathlib import Path

from .competition_execution import execution_boundary
from .competition_package import (
    CompetitionReleaseIdentity,
    competition_release_identity_digest,
    prepare_competition_package,
)
from .competition_publication import (
    SignedSettlementPublication,
    settlement_publication_digest,
    settlement_signer_eligible,
    verify_settlement_endorsement,
    verify_settlement_publication,
)
from .competition_round_journal import RoundJournal
from .competition_settlement_capacity import settlement_capacity
from .competition_settlement_preparation import MAX_BYTES, validate_preparation
from .competition_settlement_signing import SettlementEndorsement
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import ensure_private_directory as _private
from .private_files import publish_private_model as _publish
from .private_files import read_private_model
from .protocol import canonical_json_bytes


class SettlementQueue:
    def __init__(self, config, store, provider, *, limits, maximum_rounds, maximum_bytes):
        self.config, self.store, self.provider = config, store, provider
        self.policy, self.limits = store.policy, limits
        self.capacity = settlement_capacity(limits)
        for name in ("state_directory", "certificate_directory", "package_directory"):
            _private(Path(getattr(config, name)))
        self.journal = RoundJournal(
            Path(config.state_directory),
            {
                "schema": "umi-settlement-queue/1",
                "policy": digest(store.policy),
                "store": str(store.path),
                "config": config.model_dump(mode="json"),
                "limits": limits.model_dump(mode="json"),
            },
            maximum_rounds=maximum_rounds,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=self.capacity.preparation_bytes,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS settlement_index ("
                "sequence INTEGER PRIMARY KEY, publication TEXT UNIQUE NOT NULL, "
                "opens INTEGER NOT NULL, closes INTEGER NOT NULL)"
            )
        self.serial = asyncio.Lock()

    async def _head(self):
        block = execution_boundary(await self.provider.collect()).block
        await run_owned_thread(self.journal.observe, block)
        if not self.policy.valid_from_block <= block <= self.policy.valid_through_block:
            raise ValueError("settlement delivery policy is not current")
        return block

    def _window(self, prepared):
        settlement = prepared.publication.settlement
        return (
            max(settlement.observed_block, settlement.registration_snapshot.block),
            min(
                prepared.publication.round.valid_through_block,
                settlement.registration_snapshot.block + self.policy.maximum_snapshot_age_blocks,
            ),
        )

    def _source(self, prepared):
        """Recheck the live local intake journal, including its conflict holds."""
        publication = prepared.publication
        material = self.store.settlement_material(publication.round, limits=self.limits)
        if (
            material["retained_settlement"] != publication.settlement
            or material["submissions"] != prepared.roster.submissions
            or material["evidence"]
            != tuple((e.submission, e.evidence) for e in prepared.evidence.entries)
            or material["cutoff_schedule"] != prepared.cutoff.publication.cutoff_schedule
            or self.store.reviewed_promotion_head(publication.round_sha256, maximum_bytes=MAX_BYTES)
            != publication.settlement.promotion_head
        ):
            raise ValueError("settlement delivery differs from retained reviewed material")

    def _prepared(self, sequence):
        prepared = validate_preparation(
            self.journal.get("intent", str(sequence)), self.policy, self.limits
        )
        if prepared.publication.round.sequence != sequence or self.journal.get(
            "suite", prepared.publication.round.suite_sha256
        ) != {"publication": settlement_publication_digest(prepared.publication)}:
            raise ValueError("settlement delivery reservation mismatch")
        self._source(prepared)
        return prepared

    async def prepare(self, prepared):
        async with self.serial:
            return await self._prepare_owned(prepared)

    async def _prepare_owned(self, prepared):
        """Prepare under the caller's existing queue ownership.

        The coordinator holds this same lock across retained settlement formation
        so background and HTTP replay cannot allocate two full cohorts at once.
        """
        prepared = await run_owned_thread(self._prepare_input, prepared)
        block = await self._head()
        opens, closes = self._window(prepared)
        if not opens <= block <= closes:
            raise ValueError("settlement delivery window elapsed")
        await run_owned_thread(self._reserve, prepared, opens, closes)
        return await self._publish(prepared)

    def _prepare_input(self, prepared):
        prepared = validate_preparation(prepared, self.policy, self.limits)
        self._source(prepared)
        return prepared

    def _reserve(self, prepared, opens, closes):
        self._source(prepared)
        publication = prepared.publication
        sequence, publication_id = (
            publication.round.sequence,
            settlement_publication_digest(publication),
        )
        self.journal.put("intent", str(sequence), prepared)
        self.journal.put("suite", publication.round.suite_sha256, {"publication": publication_id})
        metadata = (publication_id, opens, closes)
        with self.journal.transaction() as db:
            prior = db.execute(
                "SELECT publication,opens,closes FROM settlement_index WHERE sequence=?",
                (sequence,),
            ).fetchone()
            if prior is not None and tuple(prior) != metadata:
                raise ValueError("settlement discovery index differs")
            db.execute(
                "INSERT OR IGNORE INTO settlement_index VALUES (?,?,?,?)", (sequence, *metadata)
            )

    def _verify_certificate(self, certificate, prepared):
        publication = verify_settlement_publication(
            certificate,
            cutoff_certificate=prepared.cutoff,
            policy=self.policy,
            submissions=prepared.roster.submissions,
            evidence=tuple((e.submission, e.evidence) for e in prepared.evidence.entries),
            retained_settlement=prepared.publication.settlement,
            limits=self.limits,
        )
        if publication != prepared.publication:
            raise ValueError("settlement certificate differs from its reserved proposal")

    async def _publish(self, prepared):
        certificate = await run_owned_thread(self._certificate, prepared)
        if certificate is None:
            return None
        opens, closes = self._window(prepared)
        if not opens <= await self._head() <= closes:
            return None
        package = await run_owned_thread(self._package, prepared, certificate)
        if not opens <= await self._head() <= closes:
            return None
        return await run_owned_thread(self._deliver, prepared, certificate, package)

    def _certificate(self, prepared):
        slot = str(prepared.publication.round.sequence)
        raw = self.journal.get("certificate", slot)
        if raw is None:
            signatures, groups = [], set()
            for evaluator in sorted(self.policy.evaluators, key=lambda e: identity(e.hotkey)):
                raw_vote = self.journal.get("vote", slot + ":" + identity(evaluator.hotkey))
                if raw_vote is None:
                    continue
                vote = SettlementEndorsement.model_validate_json(canonical_json_bytes(raw_vote))
                self._verify_vote(vote, prepared)
                if evaluator.control_group not in groups:
                    groups.add(evaluator.control_group)
                    signatures.append(vote.signature)
            if len(groups) < self.policy.required_evaluator_groups:
                return None
            certificate = SignedSettlementPublication(
                publication=prepared.publication, signatures=tuple(signatures)
            )
        else:
            certificate = SignedSettlementPublication.model_validate_json(canonical_json_bytes(raw))
        self._verify_certificate(certificate, prepared)
        self._source(prepared)
        return certificate

    def _release_identity(self, prepared):
        """Keep the original journal binding; require a signed scoped transition."""
        from .competition_dispatch_repair import EndpointUnavailableEvidence
        from .competition_void import VoidEvaluationEvidence

        repairs = []
        for entry in prepared.evidence.entries:
            if isinstance(entry.evidence, VoidEvaluationEvidence):
                repairs.extend(
                    o.announcement.evidence.repair.amendment
                    for o in entry.evidence.certificate.void.observations
                    if isinstance(o.announcement.evidence, EndpointUnavailableEvidence)
                )
        if not repairs:
            return self.config.release_identity
        prior = competition_release_identity_digest(self.config.release_identity)
        if any(r.predecessor_release_identity_sha256 != prior for r in repairs):
            raise ValueError("repair changes the original delivery release binding")
        path = (
            Path(self.config.state_directory)
            / "repair-releases"
            / (prepared.publication.round_sha256 + ".json")
        )
        successor = read_private_model(path, CompetitionReleaseIdentity, maximum_bytes=4096)
        target = competition_release_identity_digest(successor)
        if any(r.successor_release_identity_sha256 != target for r in repairs):
            raise ValueError("repair successor differs from its signed release authorization")
        return successor

    def _package(self, prepared, certificate):
        slot = str(prepared.publication.round.sequence)
        self._source(prepared)
        # Freeze the first quorum before filesystem delivery. Later votes cannot
        # change a package's certificate or its content-addressed identity.
        self.journal.put("certificate", slot, certificate)
        package = prepare_competition_package(
            policy=self.policy,
            cutoff_certificate=prepared.cutoff,
            settlement_certificate=certificate,
            retained_settlement=prepared.publication.settlement,
            roster=prepared.roster.submissions,
            evidence=tuple((e.submission, e.evidence) for e in prepared.evidence.entries),
            replay_limits=self.limits,
            release_identity=self._release_identity(prepared),
            destination_root=Path(self.config.package_directory),
            limits=self.config.package_limits,
        )
        self._source(prepared)
        return package

    def _deliver(self, prepared, certificate, package):
        slot = str(prepared.publication.round.sequence)
        self._source(prepared)
        self.journal.put("package", slot, package)
        base = Path(self.config.certificate_directory)
        publication_id = settlement_publication_digest(prepared.publication)
        _publish(base / (publication_id + ".certificate.json"), certificate)
        _publish(base / (publication_id + ".package.json"), package)
        return package

    def _verify_vote(self, vote, prepared):
        if vote.publication_sha256 != settlement_publication_digest(prepared.publication):
            raise ValueError("settlement endorsement publication differs")
        verify_settlement_endorsement(
            vote.signature, prepared.publication, self.policy, prepared.roster.submissions
        )

    async def accept(self, vote):
        async with self.serial:
            vote, prepared, key = await run_owned_thread(self._accept_input, vote)
            opens, closes = self._window(prepared)
            block = await self._head()
            await run_owned_thread(self._retain_vote, vote, key, block, opens, closes)
            await self._publish(prepared)
            return vote.publication_sha256

    def _accept_input(self, vote):
        vote = SettlementEndorsement.model_validate_json(canonical_json_bytes(vote))
        with self.journal.transaction() as db:
            row = db.execute(
                "SELECT sequence FROM settlement_index WHERE publication=?",
                (vote.publication_sha256,),
            ).fetchone()
        if row is None:
            raise ValueError("unknown settlement publication")
        prepared = self._prepared(row[0])
        self._verify_vote(vote, prepared)
        key = str(row[0]) + ":" + identity(vote.signature.hotkey)
        return vote, prepared, key

    def _retain_vote(self, vote, key, block, opens, closes):
        if self.journal.get("vote", key) is None and not opens <= block <= closes:
            raise ValueError("new settlement endorsement arrived outside its original window")
        self.journal.put("vote", key, vote)

    async def pending(self, hotkey, *, after=0):
        async with self.serial:
            if type(after) is not int or not 0 <= after <= 2**53 - 1:
                raise ValueError("settlement discovery cursor is invalid")
            if identity(hotkey) not in {identity(e.hotkey) for e in self.policy.evaluators}:
                raise ValueError("settlement discovery requires a policy evaluator")
            block = await self._head()
            cursor, result = await run_owned_thread(self._pending_page, hotkey, after, block)
            # Replaying a page can take time; preserve the fresh head and local
            # source checks after that work, with async ownership on this loop.
            current = await self._head()
            return await run_owned_thread(self._checked_page, cursor, result, current)

    def _pending_page(self, hotkey, after, block):
        with self.journal.transaction() as db:
            rows = db.execute(
                "SELECT sequence,publication,opens,closes FROM settlement_index "
                "WHERE sequence>? AND opens<=? AND closes>=? ORDER BY sequence LIMIT ?",
                (after, block, block, self.capacity.page_size),
            ).fetchall()
        result, cursor = [], after
        for sequence, publication_id, opens, closes in rows:
            cursor = sequence
            try:
                prepared = self._prepared(sequence)
                if (
                    settlement_publication_digest(prepared.publication),
                    *self._window(prepared),
                ) != (publication_id, opens, closes):
                    raise ValueError("settlement discovery index binding mismatch")
                if settlement_signer_eligible(
                    hotkey, prepared.publication, self.policy, prepared.roster.submissions
                ) and (
                    self.journal.get("certificate", str(sequence)) is None
                    and self.journal.get("vote", str(sequence) + ":" + identity(hotkey)) is None
                ):
                    result.append(prepared)
            except ValueError:
                continue
        return cursor, result

    def _checked_page(self, cursor, result, current):
        checked = []
        for prepared in result:
            try:
                self._source(prepared)
                if self._window(prepared)[0] <= current <= self._window(prepared)[1]:
                    checked.append(prepared)
            except ValueError:
                continue
        return cursor, tuple(checked)
