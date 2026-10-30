"""Background public projection of the reward owner's selected signed adoption.

This consumes compact authenticated reward metadata only. It neither creates a
native verification verdict nor infers that an allocation has gone live.
"""

import stat
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_cohort_model_scores import (
    MAX_PUBLIC_BYTES,
    PublicModelScores,
    _stamp,
    project_adopted_model_scores,
)
from .competition_cohort_reward_allocation import (
    MAX_REWARD_ALLOCATION_BYTES,
    CohortRewardAllocation,
)
from .competition_geometric_rewards import cohort_reward_parameters
from .competition_public_results_directory import atomic_write, owned_directory, read_owned_file
from .competition_reward_adoption_consumer import open_reward_adoption_feed
from .competition_reward_coordinator_boot import load_reward_coordinator_config
from .competition_verification_snapshot import _Checksummed
from .open_competition import digest
from .protocol import Hex32, canonical_json_bytes
from .translation_reference_config import read_input


def _selection_stamp(path):
    info = path.lstat()
    return tuple(
        getattr(info, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


class AdoptedScoreCompletion(_Checksummed):
    schema_: Literal["umi-native-adopted-model-score-completion/1"] = Field(alias="schema")
    original_projection_sha256: Hex32
    adoption_sha256: Hex32
    allocation_sha256: Hex32
    projection: PublicModelScores


class SelectedModelScoreAdoptions:
    def __init__(self, config_path: Path, *, policy, state: Path):
        self.path = Path(config_path)
        before = _selection_stamp(self.path)
        self.config = load_reward_coordinator_config(self.path)
        if _selection_stamp(self.path) != before:
            raise ValueError("selected reward boot changed while opening public score adoption")
        if self.config.role != "coordinator" or self.config.policy != policy:
            raise ValueError("public score adoption differs from its selected reward owner/policy")
        self.stamp = before
        self.cohorts = {
            digest(plan): (plan, selected)
            for series, selected in (
                (self.config.predecessor_series, self.config.predecessor_reward_adoptions),
                (self.config.series, self.config.reward_adoptions),
            )
            if series is not None
            for plan in series.cohorts
        }
        self.root = state / "reward-adoptions"
        owned_directory(self.root, create=True)
        self.completed = {}
        self.feed = open_reward_adoption_feed(
            self.root / "feed",
            source=self.config.reward_adoption_feed,
            series=self.config.series,
            policy=policy,
            initial=self.config.reward_adoptions,
            deferred=True,
        )
        self.current_cohorts = {digest(plan) for plan in self.config.series.cohorts}

    def project(self, original, *, output=None):
        # Config handoff is deliberate and restarts this consumer. Never keep
        # silently publishing an old selection after its configured bytes change.
        if _selection_stamp(self.path) != self.stamp:
            raise ValueError("public score reward selection changed; restart with selected boot")
        selected_cohort = self.cohorts.get(original.cohort_sha256)
        if selected_cohort is None:
            # A later standing series does not erase archived public results.
            # Reuse the prior owner-checked signed adoption, not a bare output.
            path = self.root / ("retained-" + original.cohort_sha256 + ".json")
            try:
                receipt = self._read_completed(path)
            except FileNotFoundError:
                return original
            self._check_original(receipt, original)
            return receipt.projection
        cohort, lineage = selected_cohort
        if self.feed is not None and original.cohort_sha256 in self.current_cohorts:
            # poll_once already holds this publisher's state lease. The feed
            # retains its own frontier and unchanged metadata requires no parse.
            lineage = self.feed.refresh()
        # C6's existing correction overlay and retained publications stay exact.
        if cohort.sequence < 7:
            return original
        selected = None if lineage is None else lineage.latest(original.cohort_sha256)
        if selected is None:
            if original.reward_parameters == cohort_reward_parameters(cohort.sequence):
                return original
            raise ValueError("public model results await the announced signed reward adoption")
        body = selected.adoption
        if body.parameters != cohort_reward_parameters(cohort.sequence):
            raise ValueError("selected public reward adoption differs from announced cohort terms")
        original_sha, adoption_sha = digest(original), digest(body)
        key = digest({"original": original_sha, "adoption": adoption_sha})
        path = self.root / (key + ".json")
        try:
            receipt = self._read_completed(path)
        except FileNotFoundError:
            if str(path) in self.completed:
                raise ValueError(
                    "completed adopted score metadata missing; explicit repair required"
                ) from None
            if output is not None and output.exists():
                published = PublicModelScores.model_validate_json(
                    read_owned_file(output, MAX_PUBLIC_BYTES)
                )
                if published.reward_adoption_sha256 == adoption_sha:
                    raise ValueError(
                        "published adopted score completion missing; explicit repair required"
                    ) from None
            source = Path(self.config.files_directory)
            producer = source.lstat()
            if (
                not stat.S_ISDIR(producer.st_mode)
                or producer.st_mode & 0o022
                or source.is_symlink()
            ):
                raise ValueError("selected reward allocation producer must be protected") from None
            raw = read_input(
                source / "allocations" / (body.effective_allocation_sha256 + ".json"),
                MAX_REWARD_ALLOCATION_BYTES,
                producer_uid=producer.st_uid,
            )
            effective = CohortRewardAllocation.model_validate_json(raw)
            if digest(effective) != body.effective_allocation_sha256:
                raise ValueError(
                    "public allocation differs from selected signed adoption"
                ) from None
            projected = project_adopted_model_scores(original, body, effective)
            receipt = AdoptedScoreCompletion(
                schema="umi-native-adopted-model-score-completion/1",
                original_projection_sha256=original_sha,
                adoption_sha256=adoption_sha,
                allocation_sha256=body.effective_allocation_sha256,
                projection=projected,
            ).sealed()
            atomic_write(path, canonical_json_bytes(receipt))
        if (
            receipt.adoption_sha256 != adoption_sha
            or receipt.allocation_sha256 != body.effective_allocation_sha256
        ):
            raise ValueError("completed adopted score binding differs; explicit repair required")
        self._check_original(receipt, original)
        self.completed[str(path)] = (tuple(_stamp(path)), receipt)
        retained = self.root / ("retained-" + original.cohort_sha256 + ".json")
        try:
            previous = self._read_completed(retained)
        except FileNotFoundError:
            previous = None
        if previous != receipt:
            atomic_write(retained, canonical_json_bytes(receipt), immutable=False)
            self.completed[str(retained)] = (tuple(_stamp(retained)), receipt)
        return receipt.projection

    def _read_completed(self, path):
        stamp = tuple(_stamp(path))
        cached = self.completed.get(str(path))
        if cached is not None and cached[0] == stamp:
            return cached[1]
        receipt = AdoptedScoreCompletion.model_validate_json(
            read_owned_file(path, 2 * MAX_PUBLIC_BYTES)
        ).checked()
        self.completed[str(path)] = (stamp, receipt)
        return receipt

    @staticmethod
    def _check_original(receipt, original):
        if (
            receipt.original_projection_sha256 != digest(original)
            or receipt.projection.cohort_sha256 != original.cohort_sha256
            or receipt.projection.policy_sha256 != original.policy_sha256
            or receipt.projection.round_sha256 != original.round_sha256
            or receipt.projection.original_allocation_sha256 != original.allocation_sha256
            or receipt.projection.original_source_metadata_sha256 != original.source_metadata_sha256
            or receipt.projection.allocation_sha256 != receipt.allocation_sha256
            or receipt.projection.reward_adoption_sha256 != receipt.adoption_sha256
            or receipt.projection.cpu_efficiency_adoption_sha256
            != original.cpu_efficiency_adoption_sha256
        ):
            raise ValueError("retained adopted score differs from its original native result")
