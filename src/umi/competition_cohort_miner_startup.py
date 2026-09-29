"""Explicit miner selection of recoverable cohort authority and public history."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator

from .competition_client import validate_intake_origin
from .competition_cohort_history_http import CohortHistoryReader
from .competition_cohort_miner import (
    CohortMinerAuthorizationAuthority,
    CohortMinerConfig,
    CohortServiceMinerConfig,
)
from .competition_cohort_public_history import PublicCohortHistoryClient
from .open_competition import CompetitionPolicy, Hotkey, digest, identity
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import StrictProtocolModel
from .validator_plans import VerifiedFinalizedAnnouncementPort


class CohortMinerStartupConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-miner-startup/1"] = Field(alias="schema")
    authority: Annotated[
        CohortMinerConfig | CohortServiceMinerConfig, Field(discriminator="schema_")
    ]
    history_origin: str
    history_owner_hotkey: Hotkey

    _origin = field_validator("history_origin")(validate_intake_origin)

    def check(
        self,
        *,
        policy: CompetitionPolicy,
        transport: ScoringPolicy,
        miner_hotkey: str,
        model_revision: str,
        serving_origin: str,
        state_files: Sequence[str | Path],
    ) -> None:
        c = self.authority
        if (
            c.policy_sha256 != digest(policy)
            or c.transport_policy_sha256 != scoring_policy_hash(transport)
            or identity(c.miner_hotkey) != identity(miner_hotkey)
            or c.model_revision != model_revision
            or c.serving_origin != serving_origin
            or identity(self.history_owner_hotkey)
            not in {identity(e.hotkey) for e in policy.evaluators}
        ):
            raise ValueError(
                "cohort startup differs from miner policy, identity or serving configuration"
            )
        directory = Path(c.directory).resolve()
        for value in state_files:
            path = Path(value).expanduser().resolve()
            if path == directory or directory in path.parents or path in directory.parents:
                raise ValueError("cohort grants require a separate durable directory")


def cohort_miner_authority(
    config: CohortMinerStartupConfig,
    *,
    policy: CompetitionPolicy,
    transport: ScoringPolicy,
    finalized_blocks: VerifiedFinalizedAnnouncementPort,
) -> CohortMinerAuthorizationAuthority:
    return CohortMinerAuthorizationAuthority(
        config.authority,
        policy,
        transport,
        finalized_blocks,
        CohortHistoryReader(
            config.history_owner_hotkey,
            PublicCohortHistoryClient(
                config.history_origin, timeout_seconds=config.authority.read_timeout_seconds
            ),
            timeout_seconds=config.authority.read_timeout_seconds,
        ),
    )
