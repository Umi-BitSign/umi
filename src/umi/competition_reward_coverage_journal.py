"""Durable original coverage proofs and idempotent adjacent-interval accounting.

Portable summaries never substitute for native replay. Private completed native
results survive restart and restore after source, policy, owner and history checks.
Capacity exhaustion holds without loss.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from pathlib import Path

from .chain_evidence import FinalizedSnapshotRef
from .competition_cohort_reward_package import CohortRewardPackage
from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_METADATA_BYTES,
    MAX_RECIPE_BYTES,
    checked_digest,
    checked_size,
    decode_evidence,
    encode_evidence,
)
from .competition_history_source_externalization import (
    JournalSourceExternalizer,
    source_journal_version,
)
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coverage import review_reward_coverage
from .competition_reward_coverage_checkpoint import (
    KINDS,
    CoverageCheckpointRepairRequired,
    CoverageCheckpoints,
)
from .competition_reward_coverage_intervals import (
    CoverageEndpoint,
    CoveragePoint,
    OwnedRetainedCoverageEndpoint,
    RewardCoverageInterval,
    RewardCoverageRule,
    _issue_retained_coverage,
    coverage_interval,
    coverage_point,
)
from .competition_reward_coverage_models import (
    CoverageModelDependencyRepairRequired,
    restore_coverage_model_dependencies,
)
from .competition_reward_coverage_prepared import RetainedCoveragePackage, retained_package_sha256
from .competition_reward_decisions import DecisionSource
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_eligibility_archive import review_reward_eligibility
from .competition_reward_history import OwnedRewardControlHistory, validate_control_history
from .competition_reward_opportunity import (
    RewardOpportunityContribution,
    RewardOpportunityWitness,
)
from .competition_reward_preparation import StandingRewardPreparation
from .competition_reward_proof_archive import RewardProofArchive
from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .competition_verification_snapshot import verified_package_digest
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

_FIELDS = {"control": "proof", "metadata": "metadata", "chain": "proof", "eligibility": "proof"}


class _CoverageJournal(RoundJournal):
    def __init__(self, *args, remote=None, **kwargs):
        self.remote_store = remote
        super().__init__(*args, **kwargs)

    def _version(self, db):
        return source_journal_version(
            db,
            marker_table="round_generation_coverage_remote",
            alias_kind="coverage_remote_source",
            remote_namespace=None
            if self.remote_store is None
            else self.remote_store.namespace_sha256,
        )

    def _enable_reservations(self, db):
        if db.execute("PRAGMA user_version").fetchone()[0] == 3:
            raise ValueError("remote coverage cannot transition to reservation generation")
        return super()._enable_reservations(db)


class RewardCoverageJournal:
    """One bounded private owner; explicit rule parameters have no defaults.

    Packages, promotion assets and complete control history use their existing
    independent stores. This journal retains the endpoint's original control,
    metadata, weight and eligibility bytes. Restore requires all native inputs.
    """

    def __init__(
        self,
        root: Path,
        rule: RewardCoverageRule,
        *,
        expected_rule_sha256: str,
        maximum_bytes: int = 4 * 1024**3,
        archive: RewardProofArchive | None = None,
        export_archive: RewardProofArchive | None = None,
    ):
        self.rule = RewardCoverageRule.model_validate_json(canonical_json_bytes(rule))
        self.rule_sha256 = checked_digest(expected_rule_sha256)
        self.archive = archive
        self.export_archive = export_archive
        self._check_rule()
        self.remote_store = None if export_archive is None else export_archive.remote
        self.journal = _CoverageJournal(
            root,
            self.rule,
            maximum_rounds=65536,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=2 * MAX_EVIDENCE_BYTES + 1024,
            remote=self.remote_store,
        )
        self._lock = asyncio.Lock()
        self._verified: dict[str, RewardCoverageInterval] = {}
        self._verified_through: dict[str, int] = {}
        self.checkpoints = CoverageCheckpoints(self.journal, self.rule)
        self.externalized = JournalSourceExternalizer(
            self.journal,
            self.checkpoints,
            self.remote_store,
            source_table="coverage_source_identity",
            source_kinds=KINDS,
            alias_kind="coverage_remote_source",
            marker_table="round_generation_coverage_remote",
            repair_error=CoverageCheckpointRepairRequired,
        )
        self.checkpoints.externalized = self.externalized
        self._reading_sources = []
        self._pending_sources = {}
        self._pending_tokens = {}
        self._source_db = None
        self._repair_reason = None

    @contextmanager
    def _repairing(self, reason):
        if reason is not None and (
            type(reason) is not str or not reason.strip() or len(reason) > 1024
        ):
            raise ValueError("coverage repair requires an explicit bounded reason")
        self._repair_reason = reason
        try:
            with TransferProgress(
                "coverage_native_repair" if reason else "coverage_native_review",
                1,
                unit="endpoints",
            ) as progress:
                yield
                progress.advance(1)
        finally:
            self._repair_reason = None

    def _source(self, kind, key):
        if self._source_db is not None:
            return self.externalized.get(kind, key, db=self._source_db)
        with self.journal.read_transaction() as db:
            return self.externalized.get(kind, key, db=db)

    def _check_rule(self):
        if digest(self.rule) != self.rule_sha256:
            raise ValueError("coverage rule differs from independently selected parameters")

    def _object(self, sha: str, size: int) -> bytes:
        self._reading_sources.append(("coverage_object", sha))
        value = self._source("coverage_object", sha)
        if (
            type(value) is not dict
            or set(value) != {"hex"}
            or type(value["hex"]) is not str
            or len(value["hex"]) != 2 * size
        ):
            raise ValueError("coverage evidence object is missing or oversized")
        raw = bytes.fromhex(value["hex"])
        if raw.hex() != value["hex"]:
            raise ValueError("coverage evidence object is not canonical")
        return raw

    def _blob(self, sha: str, kind: str) -> bytes:
        checked_digest(sha)
        self._reading_sources.append(("coverage_blob_" + kind, sha))
        blob = self._source("coverage_blob_" + kind, sha)
        if (
            type(blob) is not dict
            or set(blob) != {"length", "recipe_hex"}
            or type(blob["recipe_hex"]) is not str
            or not 0 < len(blob["recipe_hex"]) <= 2 * MAX_RECIPE_BYTES
        ):
            raise ValueError("coverage evidence recipe is missing or malformed")
        recipe = bytes.fromhex(blob["recipe_hex"])
        if recipe.hex() != blob["recipe_hex"]:
            raise ValueError("coverage evidence recipe is not canonical")
        return decode_evidence(
            recipe, sha256=sha, expanded_bytes=blob["length"], kind=kind, resolve=self._object
        )

    def _load(self, key: str):
        with self.journal.read_transaction() as db:
            self._source_db = db
            try:
                result = self._load_frame(key)
                if result is not None:
                    self._pending_tokens[key] = self.checkpoints.sources(self._reading_sources, db)
                return result
            finally:
                self._source_db = None

    def _load_frame(self, key: str):
        checked_digest(key)
        self._check_rule()
        self._reading_sources = [("coverage_endpoint", key)]
        frame = self._source("coverage_endpoint", key)
        if frame is None:
            return None
        if type(frame) is not dict or set(frame) != {
            "point",
            "validator_hotkey",
            "package",
            "blobs",
        }:
            raise ValueError("coverage endpoint frame is malformed")
        point = CoveragePoint.model_validate_json(canonical_json_bytes(frame["point"]))
        if (
            point.key() != key
            or point.series_sha256 != self.rule.series_sha256
            or point.runtime_profile_sha256 != self.rule.runtime_profile_sha256
            or identity(frame["validator_hotkey"]) != point.validator_account_id
            or type(frame["blobs"]) is not dict
            or set(frame["blobs"]) != set(_FIELDS)
        ):
            raise ValueError("coverage endpoint frame has changed identity")
        checked_digest(frame["package"])
        blobs = {name: self._blob(frame["blobs"][name], kind) for name, kind in _FIELDS.items()}
        return point, frame, blobs

    def _records(self, endpoint: CoverageEndpoint):
        point = coverage_point(endpoint, self.rule)
        key = point.key()
        if type(endpoint) is OwnedRetainedCoverageEndpoint:
            self._validate_retained(endpoint)
            return key, []
        package = endpoint.prepared.activation.package_sha256
        prior = self.checkpoints.load(key) if self._repair_reason is None else None
        if prior is not None:
            if (
                CoveragePoint.model_validate(prior["point"]) != point
                or prior["package_sha256"] != package
            ):
                raise ValueError("coverage endpoint conflicts with retained native identity")
            self._pending_sources[key] = [(v[0], v[1]) for v in prior["sources"]]
            self._pending_tokens[key] = prior["sources"]
            return key, []
        e = endpoint.eligibility
        raw_fields = {
            "control": e.control.evidence,
            "metadata": e.control.metadata,
            "chain": e.chain_evidence,
            "eligibility": e.eligibility_evidence,
        }
        old = self._load(key)
        if old is not None:
            if old[0] != point or old[1]["package"] != package:
                raise ValueError("coverage endpoint conflicts with retained identity")
            # Keep the first complete evidence, even when a later native review
            # has a different finality receipt for the same state. No new bytes
            # or interval identities accrue merely because an RPC was retried.
            if old[2] == raw_fields:
                self._pending_sources[key] = list(self._reading_sources)
            return key, []
        refs, records = {}, []
        for name, raw in raw_fields.items():
            kind = _FIELDS[name]
            encoded = encode_evidence(raw, kind=kind)
            records.extend(
                ("coverage_object", sha, {"hex": value.hex()})
                for sha, value in encoded.objects.items()
            )
            records.append(
                (
                    "coverage_blob_" + kind,
                    encoded.sha256,
                    {"length": encoded.expanded_bytes, "recipe_hex": encoded.recipe.hex()},
                )
            )
            refs[name] = encoded.sha256
        records.append(
            (
                "coverage_endpoint",
                key,
                {
                    "point": point.model_dump(mode="json"),
                    "validator_hotkey": e.subject.registrations[e.subject.validator_uid].hotkey,
                    "package": package,
                    "blobs": refs,
                },
            )
        )
        self._pending_sources[key] = [(kind, identity) for kind, identity, _ in records]
        return key, self.externalized.filter_records(records)

    def _validate_retained(self, endpoint):
        point = coverage_point(endpoint, self.rule)
        value = self.checkpoints.load(point.key())
        if value is None or digest(value) != endpoint.receipt_sha256:
            raise CoverageCheckpointRepairRequired("restored coverage lost its native result")

    def _remember_endpoint(self, endpoint):
        if type(endpoint) is OwnedRetainedCoverageEndpoint:
            self._validate_retained(endpoint)
            return
        key = coverage_point(endpoint, self.rule).key()
        keys = self._pending_sources.pop(key, None)
        if keys is not None:
            tokens = self._pending_tokens.pop(key, None)
            self.checkpoints.remember(
                endpoint, keys, expected_sources=tokens, repair_reason=self._repair_reason
            )

    def _commit_records(self, records):
        def capture(db):
            for key, keys in self._pending_sources.items():
                tokens = self.checkpoints.sources(keys, db)
                prior = self._pending_tokens.get(key)
                if prior is not None and prior != tokens:
                    raise CoverageCheckpointRepairRequired(
                        "coverage input changed before native retention"
                    )
                self._pending_tokens[key] = tokens

        self.journal.put_many(records, index=capture)

    def _externalize_completed(self, key):
        if self.remote_store is not None:
            value = self.checkpoints.load(key)
            if value is not None:
                self.externalized.externalize_many((v[0], v[1]) for v in value["sources"])

    def _import(self, key):
        if self.archive is None:
            raise FileNotFoundError("coverage endpoint is not retained")
        frame, blobs = self.archive.read(
            "endpoint",
            key,
            bounds={
                name: MAX_METADATA_BYTES if kind == "metadata" else MAX_EVIDENCE_BYTES
                for name, kind in _FIELDS.items()
            },
        )
        if set(frame) != {"point", "validator_hotkey", "package"}:
            raise ValueError("imported coverage frame has invalid fields")
        point = CoveragePoint.model_validate(frame["point"])
        if (
            point.key() != key
            or point.series_sha256 != self.rule.series_sha256
            or point.runtime_profile_sha256 != self.rule.runtime_profile_sha256
            or identity(frame["validator_hotkey"]) != point.validator_account_id
        ):
            raise ValueError("imported coverage frame changes its requested domain")
        checked_digest(frame["package"])
        return point, frame, blobs

    def _export(self, key: str, archive: RewardProofArchive) -> None:
        remote = archive.remote
        native = None if remote is None else self.checkpoints.load(key)
        export_key = (
            None if native is None else digest([key, digest(native), remote.namespace_sha256])
        )
        if export_key is not None:
            receipt = self.journal.get("coverage_remote_export", export_key)
            if receipt is not None:
                remote.validate_reference(receipt)
                return
        point, frame, blobs = self._load(key)
        archive.write(
            "endpoint",
            key,
            context={
                "point": point.model_dump(mode="json"),
                "package": frame["package"],
                "validator_hotkey": frame["validator_hotkey"],
            },
            fields=blobs,
        )
        if export_key is not None:
            receipt = remote.reference_for_path("frames/endpoint/" + key)
            if receipt is None:
                raise ValueError("coverage export lost its durable R2 acknowledgement")
            self.journal.put("coverage_remote_export", export_key, receipt)

    async def retain_endpoint(self, endpoint: CoverageEndpoint) -> str:
        async with self._lock:
            return await run_owned_thread(self._retain, endpoint)

    def _retain(self, endpoint):
        with self.journal.locked():
            self._pending_sources.clear()
            self._pending_tokens.clear()
            self._check_rule()
            key, records = self._records(endpoint)
            self._commit_records(records)
            self._remember_endpoint(endpoint)
            if self.export_archive is not None:
                self._export(key, self.export_archive)
            self._externalize_completed(key)
            return key

    async def credit(
        self, left: CoverageEndpoint, right: CoverageEndpoint
    ) -> RewardCoverageInterval | None:
        async with self._lock:
            return await run_owned_thread(self._credit, left, right)

    def _credit(self, left, right):
        with self.journal.locked():
            self._pending_sources.clear()
            self._pending_tokens.clear()
            self._check_rule()
            interval = coverage_interval(left, right, self.rule)
            records = self._records(left)[1] + self._records(right)[1]
            if interval is not None:
                records.append(("coverage_interval", interval.key(), interval))
            # Both endpoint frames, all proof objects and the interval commit
            # together. Update verified totals only after durable acknowledgement.
            self._commit_records(records)
            for endpoint in (left, right):
                self._remember_endpoint(endpoint)
            if self.export_archive is not None:
                for endpoint in (left, right):
                    self._export(coverage_point(endpoint, self.rule).key(), self.export_archive)
                if interval is not None:
                    self.export_archive.retain_interval(interval.key(), interval)
            for endpoint in (left, right):
                self._externalize_completed(coverage_point(endpoint, self.rule).key())
            if interval is not None:
                self._verified[interval.key()] = interval
                self._verified_through[interval.key()] = coverage_point(right, self.rule).block
            return interval

    async def verified_witness(
        self, *, activation_sha256: str, validator_hotkey: str
    ) -> tuple[RewardOpportunityWitness, RewardOpportunityContribution]:
        """Export already reviewed intervals; exported bytes still require replay.

        Reopening starts empty. Reading retained hints cannot populate this set.
        One interval identity appears once, regardless of capture/retry count.
        """
        async with self._lock:
            self._check_rule()
            checked_digest(activation_sha256)
            account = identity(validator_hotkey)
            values = sorted(
                (
                    v
                    for v in self._verified.values()
                    if v.activation_sha256 == activation_sha256
                    and v.validator_account_id == account
                ),
                key=lambda v: (self._verified_through[v.key()], v.key()),
            )
            if not values:
                raise ValueError("designated validator has no natively verified coverage")
            witness = RewardOpportunityWitness(
                schema="umi-reward-opportunity-witness/1",
                rule_sha256=self.rule_sha256,
                activation_sha256=activation_sha256,
                validator_account_id=account,
                interval_keys=tuple(v.key() for v in values),
            )
            return witness, RewardOpportunityContribution(
                validator_account_id=account,
                witness_sha256=digest(witness),
                credited_ms=sum(v.credited_ms for v in values),
                through_block=max(self._verified_through[v.key()] for v in values),
            )

    async def verified_ms(self, *, activation_sha256: str, validator_hotkey: str) -> int:
        async with self._lock:
            self._check_rule()
            checked_digest(activation_sha256)
            account = identity(validator_hotkey)
            return sum(
                v.credited_ms
                for v in self._verified.values()
                if v.activation_sha256 == activation_sha256 and v.validator_account_id == account
            )

    async def interval_keys(self, *, after: str | None = None, limit: int = 256) -> tuple[str, ...]:
        """Bounded discovery only. Each returned record still requires replay."""
        if after is not None:
            checked_digest(after)
        checked_size(limit, 4096)
        async with self._lock:
            self._check_rule()
            return await run_owned_thread(self._keys, after or "", limit)

    def _keys(self, after, limit):
        with self.journal.transaction() as db:
            return tuple(
                row[0]
                for row in db.execute(
                    "SELECT id FROM records WHERE kind='coverage_interval' AND id>? "
                    "ORDER BY id LIMIT ?",
                    (after, limit),
                )
            )

    async def retained_interval(self, key: str) -> RewardCoverageInterval:
        """An untrusted discovery record; this never populates verified totals."""
        checked_digest(key)
        async with self._lock:
            self._check_rule()
            raw = await run_owned_thread(self.journal.get, "coverage_interval", key)
            if raw is None and self.archive is not None:
                raw = await run_owned_thread(self.archive.interval, key)
            if raw is None:
                raise FileNotFoundError("coverage interval is not retained")
            value = RewardCoverageInterval.model_validate_json(canonical_json_bytes(raw))
            if value.key() != key or value.rule_sha256 != self.rule_sha256:
                raise ValueError("retained coverage interval has changed identity")
            return value

    async def retained_point(self, key: str) -> CoveragePoint:
        """A bounded discovery hint; callers still replay the original proofs."""
        checked_digest(key)
        async with self._lock:
            self._check_rule()
            frame = await run_owned_thread(self._source, "coverage_endpoint", key)
            if frame is None:
                # An imported summary is a hint only. replay_endpoint must
                # establish its native coverage before anything is retained.
                return (await run_owned_thread(self._import, key))[0]
            point = CoveragePoint.model_validate_json(canonical_json_bytes(frame["point"]))
            if point.key() != key or point.series_sha256 != self.rule.series_sha256:
                raise ValueError("coverage endpoint hint has changed identity")
            return point

    async def review_endpoint(
        self,
        key: str,
        *,
        provider: HistoricalRewardControlProvider,
        preparation: StandingRewardPreparation,
        package: CohortRewardPackage | RetainedCoveragePackage,
        history: OwnedRewardControlHistory | None,
        source: DecisionSource,
        profile: RewardEligibilityRuntime,
        history_source: Callable[[int], Awaitable[OwnedRewardControlHistory]] | None = None,
        repair_reason: str | None = None,
    ) -> CoverageEndpoint:
        async with self._lock:
            with self.journal.locked(), self._repairing(repair_reason):
                self._pending_sources.clear()
                self._pending_tokens.clear()
                package_sha256 = (
                    retained_package_sha256(preparation, package)
                    if type(package) is RetainedCoveragePackage
                    else await run_owned_thread(verified_package_digest, package)
                )
                restored = (
                    None
                    if repair_reason is not None
                    else await self._restore_endpoint(
                        key,
                        provider=provider,
                        preparation=preparation,
                        expected_package_sha256=package_sha256,
                        history=history,
                        history_source=history_source,
                        profile=profile,
                    )
                )
                if restored is not None:
                    return restored
                saved = await run_owned_thread(self._load, key)
                imported = saved is None
                if saved is None:
                    saved = await run_owned_thread(self._import, key)
                point, frame, blobs = saved
                if package_sha256 != frame["package"]:
                    raise ValueError("coverage endpoint requires its original package")
                eligibility = await review_reward_eligibility(
                    provider,
                    **blobs,
                    validator_hotkey=frame["validator_hotkey"],
                    control_hotkey=preparation.reader.series.control_hotkey,
                    profile=profile,
                    expected_runtime_profile_sha256=self.rule.runtime_profile_sha256,
                )
                if history is None:
                    if history_source is None:
                        raise ValueError("coverage replay requires native control history")
                    # Imported summaries cannot choose an arbitrary history
                    # target. Native original proofs establish this height.
                    history = await history_source(eligibility.control.snapshot.block_number)
                endpoint = await review_reward_coverage(
                    preparation,
                    package,
                    eligibility=eligibility,
                    history=history,
                    source=source,
                    expected_runtime_profile_sha256=self.rule.runtime_profile_sha256,
                    model_dependency_repair_reason=repair_reason,
                )
                self._check_rule()
                if coverage_point(endpoint, self.rule) != point:
                    raise ValueError("native coverage replay differs from retained summary")
                if imported:
                    # Only native replay may populate the live journal. An
                    # invalid remote frame cannot reserve an immutable key.
                    records = await run_owned_thread(self._records, endpoint)
                    await run_owned_thread(self._commit_records, records[1])
                else:
                    await run_owned_thread(self._records, endpoint)
                await run_owned_thread(self._remember_endpoint, endpoint)
                if self.export_archive is not None:
                    await run_owned_thread(self._export, key, self.export_archive)
                await run_owned_thread(self._externalize_completed, key)
                return endpoint

    async def restore_endpoint(self, key, **context):
        """Restore completed native work before loading any package/proof payload."""
        async with self._lock:
            with self.journal.locked():
                return await self._restore_endpoint(key, **context)

    async def _restore_endpoint(
        self,
        key,
        *,
        provider,
        preparation,
        expected_package_sha256,
        history,
        history_source,
        profile,
    ):
        value = await run_owned_thread(self.checkpoints.load, key)
        if value is None:
            return None
        if type(preparation) is not StandingRewardPreparation or not isinstance(
            provider, HistoricalRewardControlProvider
        ):
            raise ValueError("coverage restore requires selected native owners")
        preparation._authority()
        point = CoveragePoint.model_validate(value["point"])
        if (
            expected_package_sha256 != value["package_sha256"]
            or preparation.policy_sha256 != value["policy_sha256"]
            or digest(provider.policy) != value["policy_sha256"]
            or digest(provider.config) != point.chain_config_sha256
            or digest(profile) != point.runtime_profile_sha256
            or preparation.series_sha256 != point.series_sha256
            or digest(preparation.manifest.requirement(value["cohort_sha256"]))
            != value["requirement_sha256"]
        ):
            raise CoverageCheckpointRepairRequired("coverage verification context changed")
        if history is None:
            if history_source is None:
                raise ValueError("coverage restore requires native control history")
            history = await history_source(point.block)
        validate_control_history(
            history,
            first_block=preparation.reader.series.recovery.authority.issued_at_block,
            tip=FinalizedSnapshotRef(
                point.block, point.block_hash, point.parent_hash, point.state_root
            ),
            control_hotkey=preparation.reader.series.control_hotkey,
            chain_config_sha256=point.chain_config_sha256,
        )
        if history.unresolved_blocks or not history.writes:
            raise CoverageCheckpointRepairRequired(
                "coverage history has unresolved effects or lacks chain admission"
            )
        try:
            model_dependencies_ready = await restore_coverage_model_dependencies(
                preparation, value.get("model_dependencies")
            )
        except CoverageModelDependencyRepairRequired as error:
            raise CoverageCheckpointRepairRequired(str(error)) from error
        if not model_dependencies_ready:
            return None
        if await run_owned_thread(self.checkpoints.load, key) != value:
            raise CoverageCheckpointRepairRequired("coverage result changed during history restore")
        return _issue_retained_coverage(point, value["package_sha256"], digest(value))
