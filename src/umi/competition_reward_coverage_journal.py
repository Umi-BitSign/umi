"""Durable original coverage proofs and idempotent adjacent-interval accounting.

Stored summaries and totals never substitute for native replay. A new process
starts with no verified total, retains every interval obligation, and rebuilds
its verified set from original evidence. Capacity exhaustion holds without loss.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_RECIPE_BYTES,
    checked_digest,
    checked_size,
    decode_evidence,
    encode_evidence,
)
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coverage import OwnedRewardCoverageEndpoint, review_reward_coverage
from .competition_reward_coverage_intervals import (
    CoveragePoint,
    RewardCoverageInterval,
    RewardCoverageRule,
    coverage_interval,
    coverage_point,
)
from .competition_reward_decisions import DecisionSource
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_eligibility_archive import review_reward_eligibility
from .competition_reward_history import OwnedRewardControlHistory
from .competition_reward_opportunity import (
    RewardOpportunityContribution,
    RewardOpportunityWitness,
)
from .competition_reward_preparation import StandingRewardPreparation
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

_FIELDS = {"control": "proof", "metadata": "metadata", "chain": "proof", "eligibility": "proof"}


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
    ):
        self.rule = RewardCoverageRule.model_validate_json(canonical_json_bytes(rule))
        self.rule_sha256 = checked_digest(expected_rule_sha256)
        self._check_rule()
        self.journal = RoundJournal(
            root,
            self.rule,
            maximum_rounds=65536,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=2 * MAX_EVIDENCE_BYTES + 1024,
        )
        self._lock = asyncio.Lock()
        self._verified: dict[str, RewardCoverageInterval] = {}
        self._verified_through: dict[str, int] = {}

    def _check_rule(self):
        if digest(self.rule) != self.rule_sha256:
            raise ValueError("coverage rule differs from independently selected parameters")

    def _object(self, sha: str, size: int) -> bytes:
        value = self.journal.get("coverage_object", sha)
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
        blob = self.journal.get("coverage_blob_" + kind, sha)
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
        checked_digest(key)
        self._check_rule()
        frame = self.journal.get("coverage_endpoint", key)
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

    def _records(self, endpoint: OwnedRewardCoverageEndpoint):
        point = coverage_point(endpoint, self.rule)
        key = point.key()
        old = self._load(key)
        package = endpoint.prepared.activation.package_sha256
        if old is not None:
            if old[0] != point or old[1]["package"] != package:
                raise ValueError("coverage endpoint conflicts with retained identity")
            # Keep the first complete evidence, even when a later native review
            # has a different finality receipt for the same state. No new bytes
            # or interval identities accrue merely because an RPC was retried.
            return key, []
        e = endpoint.eligibility
        refs, records = {}, []
        raw_fields = {
            "control": e.control.evidence,
            "metadata": e.control.metadata,
            "chain": e.chain_evidence,
            "eligibility": e.eligibility_evidence,
        }
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
        return key, records

    async def retain_endpoint(self, endpoint: OwnedRewardCoverageEndpoint) -> str:
        async with self._lock:
            return await run_owned_thread(self._retain, endpoint)

    def _retain(self, endpoint):
        with self.journal.locked():
            self._check_rule()
            key, records = self._records(endpoint)
            self.journal.put_many(records)
            return key

    async def credit(
        self, left: OwnedRewardCoverageEndpoint, right: OwnedRewardCoverageEndpoint
    ) -> RewardCoverageInterval | None:
        async with self._lock:
            return await run_owned_thread(self._credit, left, right)

    def _credit(self, left, right):
        with self.journal.locked():
            self._check_rule()
            interval = coverage_interval(left, right, self.rule)
            records = self._records(left)[1] + self._records(right)[1]
            if interval is not None:
                records.append(("coverage_interval", interval.key(), interval))
            # Both endpoint frames, all proof objects and the interval commit
            # together. Update verified totals only after durable acknowledgement.
            self.journal.put_many(records)
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
            frame = await run_owned_thread(self.journal.get, "coverage_endpoint", key)
            if frame is None:
                raise FileNotFoundError("coverage endpoint is not retained")
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
        package: CohortRewardPackage,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        profile: RewardEligibilityRuntime,
    ) -> OwnedRewardCoverageEndpoint:
        async with self._lock:
            with self.journal.locked():
                saved = await run_owned_thread(self._load, key)
                if saved is None:
                    raise FileNotFoundError("coverage endpoint is not retained")
                point, frame, blobs = saved
                if await run_owned_thread(digest, package) != frame["package"]:
                    raise ValueError("coverage endpoint requires its original package")
                eligibility = await review_reward_eligibility(
                    provider,
                    **blobs,
                    validator_hotkey=frame["validator_hotkey"],
                    control_hotkey=preparation.reader.series.control_hotkey,
                    profile=profile,
                    expected_runtime_profile_sha256=self.rule.runtime_profile_sha256,
                )
                endpoint = await review_reward_coverage(
                    preparation,
                    package,
                    eligibility=eligibility,
                    history=history,
                    source=source,
                    expected_runtime_profile_sha256=self.rule.runtime_profile_sha256,
                )
                self._check_rule()
                if coverage_point(endpoint, self.rule) != point:
                    raise ValueError("native coverage replay differs from retained summary")
                return endpoint
