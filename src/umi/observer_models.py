"""Public, read-only schemas for the SN78 observer API."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

OBSERVER_API_VERSION = "v1"
OBSERVER_SNAPSHOT_SCHEMA = "umi-observer-snapshot/1"
STATUS_RESPONSE_SCHEMA = "umi-observer-status/1"
NETWORK_RESPONSE_SCHEMA = "umi-observer-network/1"
PARTICIPANTS_RESPONSE_SCHEMA = "umi-observer-participants/1"
LEADERBOARD_RESPONSE_SCHEMA = "umi-observer-leaderboard/1"
WINDOWS_RESPONSE_SCHEMA = "umi-observer-windows/1"
WINDOW_RESPONSE_SCHEMA = "umi-observer-window/1"
ACTIVATION_GATES_RESPONSE_SCHEMA = "umi-observer-activation-gates/1"
BENCHMARKS_RESPONSE_SCHEMA = "umi-observer-benchmarks/1"
INCIDENTS_RESPONSE_SCHEMA = "umi-observer-incidents/1"
ERROR_RESPONSE_SCHEMA = "umi-observer-error/1"

PROTOCOL_VERSION = "umi-asl/0.1"
SPECIFICATION_VERSION = "0.1"
SN78_NETUID = 78
UMI_MECHANISM_ID = 0

ProtocolPhase = Literal[
    "pre_public_calibration",
    "shadow_calibration",
    "activation_probation",
    "active",
    "paused",
]
Freshness = Literal["fresh", "stale"]
ParticipantRole = Literal["miner", "validator"]
ParticipantRoleFilter = Literal["all", "miner", "validator"]

_BLOCK_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_UNSIGNED_INTEGER_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_PLAIN_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")


def _validate_block_hash(value: str) -> str:
    if not _BLOCK_HASH_RE.fullmatch(value):
        raise ValueError("must be a lowercase 0x-prefixed 32-byte block hash")
    return value


def _validate_hex_32(value: str) -> str:
    if not _HEX_32_RE.fullmatch(value):
        raise ValueError("must be exactly 32 bytes encoded as lowercase hexadecimal")
    return value


def _validate_nonempty_text(value: str) -> str:
    if not value or value.isspace():
        raise ValueError("must not be empty or whitespace-only")
    return value


def _validate_unsigned_integer_text(value: str) -> str:
    if not _UNSIGNED_INTEGER_RE.fullmatch(value):
        raise ValueError("must be a canonical unsigned base-10 integer string")
    return value


def _validate_plain_decimal_text(value: str) -> str:
    if not _PLAIN_DECIMAL_RE.fullmatch(value):
        raise ValueError("must be a non-negative plain decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("must be a finite decimal string") from error
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("must be a finite non-negative decimal string")
    return value


def _ratio_decimal(numerator: int, denominator: int) -> str:
    with localcontext() as context:
        context.prec = 50
        rendered = format(Decimal(numerator) / Decimal(denominator), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


BlockHash = Annotated[str, AfterValidator(_validate_block_hash)]
Hex32 = Annotated[str, AfterValidator(_validate_hex_32)]
NonEmptyText = Annotated[str, AfterValidator(_validate_nonempty_text)]
UnsignedIntegerText = Annotated[str, AfterValidator(_validate_unsigned_integer_text)]
PlainDecimalText = Annotated[str, AfterValidator(_validate_plain_decimal_text)]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]


class ObserverModel(BaseModel):
    """Base class for immutable observer API values."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ExactNormalizedMetric(ObserverModel):
    """A normalized chain metric with its authoritative raw PerU16 value."""

    raw_numerator: UnsignedIntegerText
    raw_denominator: Literal["65535"] = "65535"
    display_decimal: PlainDecimalText | None = None
    unit: Literal["per_u16"] = "per_u16"

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        if int(self.raw_numerator) > int(self.raw_denominator):
            raise ValueError("a PerU16 numerator cannot exceed its denominator")
        if self.display_decimal is not None and self.display_decimal != _ratio_decimal(
            int(self.raw_numerator), int(self.raw_denominator)
        ):
            raise ValueError("display_decimal must match the raw PerU16 fraction")
        return self


class ExactTokenAmount(ObserverModel):
    """A token quantity in the chain's smallest indivisible unit."""

    raw: UnsignedIntegerText
    decimals: Literal[9] = 9
    unit: Literal["rao"] = "rao"
    asset: Literal["tao", "subnet_alpha"]


class ExactExchangeRate(ObserverModel):
    """The observed pool reserves and their derived exchange-rate display."""

    tao_reserve_rao: UnsignedIntegerText
    subnet_alpha_reserve_rao: Annotated[UnsignedIntegerText, Field(pattern=r"^[1-9][0-9]*$")]
    display_decimal: PlainDecimalText
    unit: Literal["tao_per_subnet_alpha"] = "tao_per_subnet_alpha"

    @model_validator(mode="after")
    def validate_display(self) -> Self:
        if self.display_decimal != _ratio_decimal(
            int(self.tao_reserve_rao), int(self.subnet_alpha_reserve_rao)
        ):
            raise ValueError("display_decimal must match the observed pool reserves")
        return self


class ExactRational(ObserverModel):
    """Exact protocol arithmetic for a future released UMI score."""

    numerator: UnsignedIntegerText
    denominator: Annotated[UnsignedIntegerText, Field(pattern=r"^[1-9][0-9]*$")]

    @model_validator(mode="after")
    def validate_unit_interval(self) -> Self:
        if int(self.numerator) > int(self.denominator):
            raise ValueError("an observer score cannot exceed one")
        return self


class FinalizedBlock(ObserverModel):
    number: UnsignedIntegerText
    hash: BlockHash
    parent_hash: BlockHash
    state_root: BlockHash
    timestamp: datetime
    finalized: Literal[True] = True
    storage_proofs_verified: Literal[False] = False

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("timestamp must use UTC")
        return value


class SourceProvenance(ObserverModel):
    source_id: NonEmptyText
    source_kind: Literal["chain_finalized", "dashboard_static", "released_audit_bundle"]
    verification_status: Literal["finalized_read", "repository_static", "bundle_verified"]
    block: FinalizedBlock | None
    policy_hash: Hex32 | None = None
    artifact_sha256: Hex32 | None = None
    validator_input_eligible: Literal[False] = False

    @model_validator(mode="after")
    def validate_source_binding(self) -> Self:
        expected_status = {
            "chain_finalized": "finalized_read",
            "dashboard_static": "repository_static",
            "released_audit_bundle": "bundle_verified",
        }[self.source_kind]
        if self.verification_status != expected_status:
            raise ValueError("verification_status does not match source_kind")
        if self.source_kind == "chain_finalized" and self.block is None:
            raise ValueError("a finalized-chain source requires a block")
        if self.source_kind == "dashboard_static" and self.block is not None:
            raise ValueError("a static source must not claim a chain block")
        if self.source_kind == "released_audit_bundle" and self.artifact_sha256 is None:
            raise ValueError("an audit-bundle source requires its artifact hash")
        return self


class ProtocolState(ObserverModel):
    protocol: Literal[PROTOCOL_VERSION] = PROTOCOL_VERSION
    specification_version: Literal[SPECIFICATION_VERSION] = SPECIFICATION_VERSION
    phase: ProtocolPhase
    netuid: Literal[SN78_NETUID] = SN78_NETUID
    mechanism_id: Literal[UMI_MECHANISM_ID] = UMI_MECHANISM_ID
    translation_weights_active: bool
    scoring_policy_hash: Hex32 | None
    conformance_evidence_available: bool
    activation_evidence_available: bool
    economic_era: Literal["unverified", "legacy_bootstrap", "umi_translation"]
    chain_result_classification: Literal["unverified", "legacy_or_bootstrap", "umi_translation"]
    expected_chain_name: Literal["UMI"] = "UMI"
    chain_identity_matches_expected: bool | None
    validator_input_eligible: Literal[False] = False

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        if self.phase in {"activation_probation", "active"}:
            if not self.translation_weights_active:
                raise ValueError("an activated phase requires translation_weights_active")
            if self.scoring_policy_hash is None:
                raise ValueError("an activated phase requires a scoring policy hash")
            if self.economic_era != "umi_translation":
                raise ValueError("an activated phase requires the UMI translation economic era")
            if self.chain_result_classification != "umi_translation":
                raise ValueError("an activated phase requires UMI result classification")
        elif self.phase in {"pre_public_calibration", "shadow_calibration"}:
            if self.translation_weights_active:
                raise ValueError("inactive phases cannot claim active translation weights")
            if self.economic_era == "umi_translation":
                raise ValueError("inactive phases cannot claim the UMI translation economic era")
            expected_result = {
                "unverified": "unverified",
                "legacy_bootstrap": "legacy_or_bootstrap",
            }[self.economic_era]
            if self.chain_result_classification != expected_result:
                raise ValueError("inactive economic-era and result classifications must agree")
        return self


class EpochState(ObserverModel):
    epoch_index: UnsignedIntegerText
    tempo_blocks: UnsignedIntegerText
    last_epoch_block: UnsignedIntegerText
    next_epoch_start_block: UnsignedIntegerText
    pending_epoch_at: UnsignedIntegerText | None
    blocks_since_last_step: UnsignedIntegerText
    blocks_remaining: UnsignedIntegerText
    seconds_remaining: UnsignedIntegerText | None


class NetworkCounts(ObserverModel):
    registered: NonNegativeInt
    chain_active: NonNegativeInt
    miners: NonNegativeInt
    validators: NonNegativeInt
    serving_announced: NonNegativeInt
    maximum_uids: PositiveInt | None

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.chain_active > self.registered:
            raise ValueError("active participant count cannot exceed registered count")
        if self.miners + self.validators != self.registered:
            raise ValueError("miner and validator counts must equal the registered count")
        if self.serving_announced > self.registered:
            raise ValueError("serving count cannot exceed registered count")
        if self.maximum_uids is not None and self.registered > self.maximum_uids:
            raise ValueError("registered count cannot exceed maximum_uids")
        return self


class NetworkHyperparameters(ObserverModel):
    min_allowed_weights: NonNegativeInt | None
    weights_version_key: UnsignedIntegerText | None
    weights_rate_limit_blocks: UnsignedIntegerText | None
    immunity_period_blocks: UnsignedIntegerText | None
    activity_cutoff_blocks: UnsignedIntegerText | None
    maximum_weight: ExactNormalizedMetric | None


class ChainNetworkSnapshot(ObserverModel):
    netuid: Literal[SN78_NETUID] = SN78_NETUID
    name: str | None
    symbol: str | None
    identity: str | None
    runtime_spec_version: UnsignedIntegerText | None
    mechanism_count: PositiveInt
    maximum_mechanism_count: PositiveInt | None
    mechanism_id: Literal[UMI_MECHANISM_ID] = UMI_MECHANISM_ID
    mechanism_emission_split: ExactNormalizedMetric | None
    commit_reveal_enabled: bool | None
    commit_reveal_version: UnsignedIntegerText | None
    reveal_period_epochs: UnsignedIntegerText | None
    pending_weight_commit_count: NonNegativeInt | None
    subnet_exists: bool | None
    subnet_started: bool | None
    subnet_emission_enabled: bool | None
    price: ExactExchangeRate | None
    epoch: EpochState
    counts: NetworkCounts
    hyperparameters: NetworkHyperparameters
    unavailable_fields: tuple[NonEmptyText, ...] = ()

    @field_validator("unavailable_fields")
    @classmethod
    def validate_unavailable_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("unavailable_fields must be unique and sorted")
        return value


class ChainParticipantMetrics(ObserverModel):
    """Native-chain metrics, separate from UMI translation evidence."""

    rank: ExactNormalizedMetric | None
    trust: ExactNormalizedMetric | None
    consensus: ExactNormalizedMetric | None
    incentive: ExactNormalizedMetric | None
    dividends: ExactNormalizedMetric | None
    pruning_score: ExactNormalizedMetric | None
    emission: ExactTokenAmount | None
    alpha_stake: ExactTokenAmount | None
    tao_stake: ExactTokenAmount | None
    total_stake: ExactTokenAmount | None

    @model_validator(mode="after")
    def validate_assets(self) -> Self:
        if self.alpha_stake is not None and self.alpha_stake.asset != "subnet_alpha":
            raise ValueError("alpha_stake must use the subnet_alpha asset")
        if self.tao_stake is not None and self.tao_stake.asset != "tao":
            raise ValueError("tao_stake must use the tao asset")
        if self.emission is not None and self.emission.asset != "subnet_alpha":
            raise ValueError("emission must use the subnet_alpha asset")
        return self


class UmiTranslationMetrics(ObserverModel):
    availability: Literal["unavailable", "available"]
    reason_code: NonEmptyText | None
    miner_root: NonEmptyText | None
    accuracy: ExactRational | None
    utility: ExactRational | None
    rank: PositiveInt | None
    audit_bundle_sha256: Hex32 | None
    audit_release_block: UnsignedIntegerText | None

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        values = (
            self.miner_root,
            self.accuracy,
            self.utility,
            self.rank,
            self.audit_bundle_sha256,
            self.audit_release_block,
        )
        if self.availability == "unavailable":
            if self.reason_code is None:
                raise ValueError("unavailable translation metrics require a reason code")
            if any(value is not None for value in values):
                raise ValueError("unavailable translation metrics must not contain score values")
        elif self.reason_code is not None or any(value is None for value in values):
            raise ValueError("available translation metrics require complete released evidence")
        return self


class ChainParticipant(ObserverModel):
    uid: NonNegativeInt
    hotkey: NonEmptyText
    role: ParticipantRole
    chain_active: bool
    validator_permit: bool
    registration_block: UnsignedIntegerText
    last_update_block: UnsignedIntegerText
    last_update_age_blocks: UnsignedIntegerText
    serving_announced: bool
    chain_metrics: ChainParticipantMetrics
    umi_translation: UmiTranslationMetrics

    @model_validator(mode="after")
    def validate_role(self) -> Self:
        expected_role = "validator" if self.validator_permit else "miner"
        if self.role != expected_role:
            raise ValueError("role must follow validator_permit")
        return self


class ObserverSnapshot(ObserverModel):
    schema_: Literal[OBSERVER_SNAPSHOT_SCHEMA] = Field(
        default=OBSERVER_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    collected_at: datetime
    sources: Annotated[tuple[SourceProvenance, ...], Field(min_length=1)]
    network: ChainNetworkSnapshot
    participants: tuple[ChainParticipant, ...]

    @field_validator("collected_at")
    @classmethod
    def validate_collected_at(cls, value: datetime) -> datetime:
        return FinalizedBlock.validate_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        source_ids = [source.source_id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("snapshot sources must be unique")
        chain_blocks = {
            source.block.hash
            for source in self.sources
            if source.source_kind == "chain_finalized" and source.block is not None
        }
        if len(chain_blocks) != 1:
            raise ValueError("a snapshot requires exactly one finalized chain block")
        participant_keys = [(row.uid, row.hotkey) for row in self.participants]
        participant_uids = [row.uid for row in self.participants]
        participant_hotkeys = [row.hotkey for row in self.participants]
        if participant_keys != sorted(participant_keys):
            raise ValueError("participants must be sorted by UID and hotkey")
        if len(participant_uids) != len(set(participant_uids)):
            raise ValueError("participant UIDs must be unique")
        if len(participant_hotkeys) != len(set(participant_hotkeys)):
            raise ValueError("participant hotkeys must be unique")
        if self.network.counts.registered != len(self.participants):
            raise ValueError("participant rows must match the registered count")
        expected_counts = {
            "chain_active": sum(row.chain_active for row in self.participants),
            "miners": sum(not row.validator_permit for row in self.participants),
            "validators": sum(row.validator_permit for row in self.participants),
            "serving_announced": sum(row.serving_announced for row in self.participants),
        }
        for field_name, expected in expected_counts.items():
            if getattr(self.network.counts, field_name) != expected:
                raise ValueError(f"participant rows do not match counts.{field_name}")
        if any(
            participant.umi_translation.availability == "available"
            for participant in self.participants
        ):
            raise ValueError("snapshot schema v1 cannot publish released UMI translation scores")
        return self


class ResponseEnvelope(ObserverModel):
    generated_at: datetime
    freshness: Freshness
    snapshot_age_seconds: NonNegativeInt
    finalized_head_age_seconds: NonNegativeInt
    sources: Annotated[tuple[SourceProvenance, ...], Field(min_length=1)]

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        return FinalizedBlock.validate_utc_timestamp(value)

    @field_validator("sources")
    @classmethod
    def validate_sources(
        cls,
        value: tuple[SourceProvenance, ...],
    ) -> tuple[SourceProvenance, ...]:
        source_ids = [source.source_id for source in value]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("response sources must be unique")
        chain_sources = [
            source
            for source in value
            if source.source_kind == "chain_finalized" and source.block is not None
        ]
        if len(chain_sources) != 1:
            raise ValueError("a response requires exactly one finalized-chain source")
        return value


def _validate_released_evidence(
    sources: tuple[SourceProvenance, ...],
    records: tuple[tuple[str, str], ...],
) -> None:
    finalized_blocks = [
        source.block
        for source in sources
        if source.source_kind == "chain_finalized" and source.block is not None
    ]
    if len(finalized_blocks) != 1:
        raise ValueError("released evidence requires exactly one finalized-chain source")
    released_artifacts = {
        source.artifact_sha256
        for source in sources
        if source.source_kind == "released_audit_bundle" and source.artifact_sha256 is not None
    }
    finalized_height = int(finalized_blocks[0].number)
    for artifact_sha256, audit_release_block in records:
        if artifact_sha256 not in released_artifacts:
            raise ValueError("released evidence must bind to a verified audit-bundle source")
        if int(audit_release_block) > finalized_height:
            raise ValueError("audit release block cannot exceed the finalized source block")


class StatusResponse(ResponseEnvelope):
    schema_: Literal[STATUS_RESPONSE_SCHEMA] = Field(default=STATUS_RESPONSE_SCHEMA, alias="schema")
    service: Literal["umi-observer-api"] = "umi-observer-api"
    api_version: Literal[OBSERVER_API_VERSION] = OBSERVER_API_VERSION
    service_status: Literal["ready", "degraded"]
    protocol_state: ProtocolState
    finalized_block: FinalizedBlock
    outstanding_gap_codes: tuple[NonEmptyText, ...]

    @field_validator("outstanding_gap_codes")
    @classmethod
    def validate_gap_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("outstanding_gap_codes must be unique and sorted")
        return value


class NetworkResponse(ResponseEnvelope):
    schema_: Literal[NETWORK_RESPONSE_SCHEMA] = Field(
        default=NETWORK_RESPONSE_SCHEMA,
        alias="schema",
    )
    protocol_state: ProtocolState
    network: ChainNetworkSnapshot


class CursorPage(ObserverModel):
    role: ParticipantRoleFilter
    limit: PositiveInt
    total: NonNegativeInt
    returned: NonNegativeInt
    next_cursor: Annotated[str, Field(pattern=_CURSOR_RE.pattern)] | None

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if self.returned > self.limit or self.returned > self.total:
            raise ValueError("returned must not exceed limit or total")
        if self.next_cursor is not None and self.returned == 0:
            raise ValueError("an empty page cannot have a next cursor")
        return self


class ParticipantsResponse(ResponseEnvelope):
    schema_: Literal[PARTICIPANTS_RESPONSE_SCHEMA] = Field(
        default=PARTICIPANTS_RESPONSE_SCHEMA,
        alias="schema",
    )
    protocol_state: ProtocolState
    page: CursorPage
    participants: tuple[ChainParticipant, ...]

    @model_validator(mode="after")
    def validate_page_rows(self) -> Self:
        if self.page.returned != len(self.participants):
            raise ValueError("page returned count must match participant rows")
        if self.page.role != "all" and any(
            participant.role != self.page.role for participant in self.participants
        ):
            raise ValueError("participant rows do not match the role filter")
        return self


class LeaderboardEntry(ObserverModel):
    rank: PositiveInt
    miner_root: NonEmptyText
    serving_hotkey: NonEmptyText
    accuracy: ExactRational
    utility: ExactRational
    audit_bundle_sha256: Hex32
    audit_release_block: UnsignedIntegerText


class ChainEconomicLeaderboardEntry(ObserverModel):
    chain_rank: PositiveInt | None
    incentive_tie_size: PositiveInt
    uid: NonNegativeInt
    hotkey: NonEmptyText
    chain_active: bool
    serving_announced: bool
    incentive: ExactNormalizedMetric
    dividends: ExactNormalizedMetric | None
    emission: ExactTokenAmount | None


class ChainEconomicLeaderboard(ObserverModel):
    classification: Literal["unverified"] = "unverified"
    derivation_status: Literal["dashboard_derived"] = "dashboard_derived"
    ranking_basis: Literal["native_incentive_per_u16_descending"] = (
        "native_incentive_per_u16_descending"
    )
    tie_breaker: Literal["uid_ascending"] = "uid_ascending"
    ranking_status: Literal["ranked", "no_economic_separation", "unavailable"]
    reason_code: NonEmptyText | None
    source_ids: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]
    excluded_missing_incentive: NonNegativeInt
    entries: tuple[ChainEconomicLeaderboardEntry, ...]

    @model_validator(mode="after")
    def validate_ranking(self) -> Self:
        if self.source_ids != tuple(sorted(set(self.source_ids))):
            raise ValueError("source_ids must be unique and sorted")
        if self.ranking_status == "unavailable":
            if self.reason_code is None or self.entries:
                raise ValueError("an unavailable chain ranking requires a reason and no entries")
            return self

        if not self.entries:
            raise ValueError("an observed chain ranking requires entries")
        ordered = sorted(
            self.entries,
            key=lambda entry: (-int(entry.incentive.raw_numerator), entry.uid),
        )
        if list(self.entries) != ordered:
            raise ValueError("chain economic entries must follow incentive and UID order")
        counts: dict[str, int] = {}
        first_positions: dict[str, int] = {}
        for position, entry in enumerate(self.entries, start=1):
            raw = entry.incentive.raw_numerator
            counts[raw] = counts.get(raw, 0) + 1
            first_positions.setdefault(raw, position)

        if self.ranking_status == "no_economic_separation":
            if self.reason_code is None or len(counts) != 1:
                raise ValueError("no economic separation requires one tied value and a reason")
            if any(entry.chain_rank is not None for entry in self.entries):
                raise ValueError("a fully tied chain vector must not publish ordinal ranks")
        else:
            if self.reason_code is not None or len(counts) < 2:
                raise ValueError("a ranked chain vector requires separation and no reason")
            if any(
                entry.chain_rank != first_positions[entry.incentive.raw_numerator]
                for entry in self.entries
            ):
                raise ValueError("chain ranks must use competition ranking")
        if any(
            entry.incentive_tie_size != counts[entry.incentive.raw_numerator]
            for entry in self.entries
        ):
            raise ValueError("incentive_tie_size must match each exact incentive group")
        return self


class ErrorDetail(ObserverModel):
    reason_code: NonEmptyText


class ErrorResponse(ObserverModel):
    schema_: Literal[ERROR_RESPONSE_SCHEMA] = Field(
        default=ERROR_RESPONSE_SCHEMA,
        alias="schema",
    )
    freshness: Literal["unavailable"] = "unavailable"
    error: ErrorDetail
    validator_input_eligible: Literal[False] = False


class UmiTranslationLeaderboard(ObserverModel):
    availability: Literal["not_started", "unavailable", "available"]
    reason_code: NonEmptyText | None
    entries: tuple[LeaderboardEntry, ...]

    @model_validator(mode="after")
    def validate_leaderboard(self) -> Self:
        if self.availability in {"not_started", "unavailable"}:
            if self.reason_code is None or self.entries:
                raise ValueError("a non-available leaderboard requires a reason and no entries")
        elif self.reason_code is not None:
            raise ValueError("an available leaderboard must not have an unavailable reason")
        return self


class LeaderboardResponse(ResponseEnvelope):
    schema_: Literal[LEADERBOARD_RESPONSE_SCHEMA] = Field(
        default=LEADERBOARD_RESPONSE_SCHEMA,
        alias="schema",
    )
    protocol_state: ProtocolState
    chain_economics: ChainEconomicLeaderboard
    umi_translation: UmiTranslationLeaderboard

    @model_validator(mode="after")
    def validate_released_scores(self) -> Self:
        if self.umi_translation.availability == "available":
            _validate_released_evidence(
                self.sources,
                tuple(
                    (entry.audit_bundle_sha256, entry.audit_release_block)
                    for entry in self.umi_translation.entries
                ),
            )
        return self


class ReleasedWindow(ObserverModel):
    window_id: Hex32
    window_index: UnsignedIntegerText
    terminal_classification: NonEmptyText
    audit_release_block: UnsignedIntegerText
    audit_bundle_sha256: Hex32


class WindowsResponse(ResponseEnvelope):
    schema_: Literal[WINDOWS_RESPONSE_SCHEMA] = Field(
        default=WINDOWS_RESPONSE_SCHEMA,
        alias="schema",
    )
    protocol_state: ProtocolState
    availability: Literal["not_started", "available"]
    reason_code: NonEmptyText | None
    windows: tuple[ReleasedWindow, ...]

    @model_validator(mode="after")
    def validate_windows(self) -> Self:
        if self.availability == "not_started":
            if self.reason_code is None or self.windows:
                raise ValueError("a feed that has not started requires a reason and no windows")
        elif self.reason_code is not None:
            raise ValueError("an available window feed must not have an unavailable reason")
        else:
            _validate_released_evidence(
                self.sources,
                tuple(
                    (window.audit_bundle_sha256, window.audit_release_block)
                    for window in self.windows
                ),
            )
        return self


class WindowResponse(ResponseEnvelope):
    schema_: Literal[WINDOW_RESPONSE_SCHEMA] = Field(default=WINDOW_RESPONSE_SCHEMA, alias="schema")
    protocol_state: ProtocolState
    window: ReleasedWindow

    @model_validator(mode="after")
    def validate_released_window(self) -> Self:
        _validate_released_evidence(
            self.sources,
            ((self.window.audit_bundle_sha256, self.window.audit_release_block),),
        )
        return self


class ActivationGate(ObserverModel):
    gate_id: NonEmptyText
    status: Literal["passed", "failed", "pending", "unavailable"]
    evidence_available: bool
    evidence_sha256: Hex32 | None

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.evidence_available != (self.evidence_sha256 is not None):
            raise ValueError("evidence_available must match evidence_sha256")
        if self.status in {"passed", "failed"} and self.evidence_sha256 is None:
            raise ValueError("a passed or failed gate requires published evidence")
        return self


class ActivationGatesResponse(ResponseEnvelope):
    schema_: Literal[ACTIVATION_GATES_RESPONSE_SCHEMA] = Field(
        default=ACTIVATION_GATES_RESPONSE_SCHEMA,
        alias="schema",
    )
    protocol_state: ProtocolState
    readiness: Literal["not_ready", "ready"]
    gates: tuple[ActivationGate, ...]


class BenchmarkRecord(ObserverModel):
    benchmark_id: NonEmptyText
    status: Literal["published"]
    artifact_sha256: Hex32


class BenchmarksResponse(ResponseEnvelope):
    schema_: Literal[BENCHMARKS_RESPONSE_SCHEMA] = Field(
        default=BENCHMARKS_RESPONSE_SCHEMA,
        alias="schema",
    )
    protocol_state: ProtocolState
    availability: Literal["not_started", "available"]
    reason_code: NonEmptyText | None
    benchmarks: tuple[BenchmarkRecord, ...]

    @model_validator(mode="after")
    def validate_benchmarks(self) -> Self:
        if self.availability == "not_started":
            if self.reason_code is None or self.benchmarks:
                raise ValueError("an unpublished benchmark feed requires a reason and no records")
        elif self.reason_code is not None:
            raise ValueError("an available benchmark feed must not have an unavailable reason")
        return self


class IncidentRecord(ObserverModel):
    incident_id: Hex32
    reason_code: NonEmptyText
    window_id: Hex32 | None
    published_at: datetime
    artifact_sha256: Hex32

    @field_validator("published_at")
    @classmethod
    def validate_published_at(cls, value: datetime) -> datetime:
        return FinalizedBlock.validate_utc_timestamp(value)


class IncidentsResponse(ResponseEnvelope):
    schema_: Literal[INCIDENTS_RESPONSE_SCHEMA] = Field(
        default=INCIDENTS_RESPONSE_SCHEMA,
        alias="schema",
    )
    protocol_state: ProtocolState
    scope: Literal["published_incidents_only"] = "published_incidents_only"
    availability: Literal["not_started", "available"]
    reason_code: NonEmptyText | None
    incidents: tuple[IncidentRecord, ...]

    @model_validator(mode="after")
    def validate_incidents(self) -> Self:
        if self.availability == "not_started":
            if self.reason_code is None or self.incidents:
                raise ValueError(
                    "an incident feed that has not started requires a reason and no records"
                )
        elif self.reason_code is not None:
            raise ValueError("an available incident feed must not have an unavailable reason")
        return self
