"""Immutable local packages for wallet-free competition publication replay.

The package binds exact signed publications, their retained settlement, and all
inputs needed to replay them.  Its release identity is an expected byte value,
not an attestation of the process that reads it.  Loading a package performs no
network, wallet, subprocess, chain, or weight operation.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal, TypeVar

from pydantic import Field, model_serializer, model_validator
from typing_extensions import Self

from .competition_outcomes import OutcomeEvidence, parse_outcome
from .competition_policy_lineage import registered_lineage, replay_lineage
from .competition_publication import (
    CutoffPublication,
    PublicationReplayLimits,
    SettlementPublication,
    SignedCutoffPublication,
    SignedSettlementPublication,
    authenticated_roster_digest,
    cutoff_publication_digest,
    independent_evidence_set_digest,
    settlement_publication_digest,
    signed_cutoff_publication_digest,
    signed_settlement_publication_digest,
    verify_cutoff_publication,
    verify_settlement_publication,
)
from .competition_settlement import CompetitionSettlement, competition_settlement_digest
from .competition_void import VoidEvaluationEvidence
from .open_competition import CompetitionPolicy, SignedSubmission, StrictProtocolModel, digest
from .protocol import Hex32, canonical_json_bytes

_PACKAGE_DOMAIN = b"umi-competition-replay-package-v1\0"
_RELEASE_DOMAIN = b"umi-competition-replay-release-identity-v1\0"
_LIMITS_DOMAIN = b"umi-competition-publication-replay-limits-v1\0"

_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_POLICY_BYTES = 2 * 1024**2
_MAX_REPLAY_OBJECT_BYTES = 512 * 1024**2
_MAX_SMALL_OBJECT_BYTES = 64 * 1024
_MAX_AGGREGATE_BYTES = 2 * 1024**3
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_PATH_BYTES = 4096

_PAYLOAD_NAMES = (
    "cutoff-certificate.json",
    "evidence.json",
    "policy.json",
    "release-identity.json",
    "replay-limits.json",
    "roster.json",
    "settlement-certificate.json",
    "settlement.json",
)
_TREE_NAMES = frozenset(("manifest.json", *_PAYLOAD_NAMES))
_ModelT = TypeVar("_ModelT", bound=StrictProtocolModel)


class CompetitionReleaseIdentity(StrictProtocolModel):
    """Expected release bytes; equality does not authenticate a running process."""

    schema_: Literal["umi-competition-replay-release-identity/1"] = Field(alias="schema")
    umi_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    release_manifest_sha256: Hex32
    release_bundle_sha256: Hex32
    target_triple: Annotated[
        str,
        Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"),
    ]


class CompetitionPackageLimits(StrictProtocolModel):
    """Caller-selected I/O ceilings bounded by the fixed package profile."""

    maximum_manifest_bytes: Annotated[int, Field(ge=1, le=_MAX_MANIFEST_BYTES)]
    maximum_policy_bytes: Annotated[int, Field(ge=1, le=_MAX_POLICY_BYTES)]
    maximum_cutoff_certificate_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_OBJECT_BYTES)]
    maximum_settlement_certificate_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_OBJECT_BYTES)]
    maximum_settlement_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_OBJECT_BYTES)]
    maximum_roster_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_OBJECT_BYTES)]
    maximum_evidence_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_OBJECT_BYTES)]
    maximum_replay_limits_bytes: Annotated[int, Field(ge=1, le=_MAX_SMALL_OBJECT_BYTES)]
    maximum_release_identity_bytes: Annotated[int, Field(ge=1, le=_MAX_SMALL_OBJECT_BYTES)]
    maximum_aggregate_bytes: Annotated[int, Field(ge=1, le=_MAX_AGGREGATE_BYTES)]

    @model_validator(mode="after")
    def aggregate_covers_each_object(self) -> Self:
        individual = (
            self.maximum_manifest_bytes,
            self.maximum_policy_bytes,
            self.maximum_cutoff_certificate_bytes,
            self.maximum_settlement_certificate_bytes,
            self.maximum_settlement_bytes,
            self.maximum_roster_bytes,
            self.maximum_evidence_bytes,
            self.maximum_replay_limits_bytes,
            self.maximum_release_identity_bytes,
        )
        if self.maximum_aggregate_bytes < max(individual):
            raise ValueError("package aggregate limit is smaller than an object limit")
        return self


class CompetitionPackageFile(StrictProtocolModel):
    name: Literal[
        "cutoff-certificate.json",
        "evidence.json",
        "policy.json",
        "release-identity.json",
        "replay-limits.json",
        "roster.json",
        "settlement-certificate.json",
        "settlement.json",
    ]
    size_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_OBJECT_BYTES)]
    sha256: Hex32


class CompetitionPackageManifest(StrictProtocolModel):
    schema_: Literal["umi-competition-replay-package-manifest/1"] = Field(alias="schema")
    profile: Literal["competition_publication_replay_no_weight/1"]
    files: Annotated[tuple[CompetitionPackageFile, ...], Field(min_length=8, max_length=8)]
    policy_sha256: Hex32
    round_sha256: Hex32
    round_sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    runtime_sha256: Hex32
    cutoff_publication_sha256: Hex32
    cutoff_certificate_sha256: Hex32
    settlement_publication_sha256: Hex32
    settlement_certificate_sha256: Hex32
    settlement_sha256: Hex32
    authenticated_roster_sha256: Hex32
    independent_evidence_set_sha256: Hex32
    projection_sha256: Hex32
    promotion_head_sha256: Hex32
    replay_limits_sha256: Hex32
    release_identity_sha256: Hex32
    wallet_access_required: Literal[False] = False
    network_access_required: Literal[False] = False
    execution_proven: Literal[False] = False
    runtime_identity_authenticated: Literal[False] = False
    finalized_receipt_timing_proven: Literal[False] = False
    global_conflict_absence_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def exact_file_set(self) -> Self:
        if tuple(item.name for item in self.files) != _PAYLOAD_NAMES:
            raise ValueError("package manifest must contain the exact ordered file set")
        return self


class CompetitionPackageRoster(StrictProtocolModel):
    schema_: Literal["umi-competition-replay-roster/1", "umi-competition-replay-roster/2"] = Field(
        alias="schema"
    )
    submissions: Annotated[tuple[SignedSubmission, ...], Field(min_length=1, max_length=512)]
    predecessor_policies: Annotated[tuple[CompetitionPolicy, ...], Field(max_length=8)] = ()

    @model_serializer(mode="wrap")
    def versioned_fields(self, handler):
        result = handler(self)
        if self.schema_ == "umi-competition-replay-roster/1":
            result.pop("predecessor_policies", None)
        return result

    @model_validator(mode="after")
    def canonical_order(self) -> Self:
        if bool(self.predecessor_policies) != (self.schema_ == "umi-competition-replay-roster/2"):
            raise ValueError("declared predecessor policies require roster version 2")
        ids = tuple(digest(item.submission) for item in self.submissions)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("package roster must be sorted and unique")
        return self


class CompetitionPackageEvidenceEntry(StrictProtocolModel):
    submission: SignedSubmission
    evidence: OutcomeEvidence


class CompetitionPackageEvidence(StrictProtocolModel):
    schema_: Literal["umi-competition-replay-evidence/1", "umi-competition-replay-evidence/2"] = (
        Field(alias="schema")
    )
    entries: Annotated[
        tuple[CompetitionPackageEvidenceEntry, ...], Field(min_length=1, max_length=512)
    ]

    @model_validator(mode="after")
    def canonical_order(self) -> Self:
        has_void = any(isinstance(item.evidence, VoidEvaluationEvidence) for item in self.entries)
        if has_void != (self.schema_ == "umi-competition-replay-evidence/2"):
            raise ValueError("mixed void evidence requires package evidence version 2")
        ids = tuple(digest(item.submission.submission) for item in self.entries)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("package evidence must be sorted and unique")
        return self


class PreparedCompetitionPackage(StrictProtocolModel):
    schema_: Literal["umi-prepared-competition-replay-package/1"] = Field(alias="schema")
    package_path: Annotated[str, Field(min_length=1, max_length=_MAX_PATH_BYTES)]
    package_sha256: Hex32
    manifest_sha256: Hex32
    policy_sha256: Hex32
    runtime_identity_authenticated: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


class VerifiedCompetitionPackage(StrictProtocolModel):
    schema_: Literal["umi-verified-competition-replay-package/1"] = Field(alias="schema")
    package_sha256: Hex32
    manifest_sha256: Hex32
    manifest: CompetitionPackageManifest
    policy: CompetitionPolicy
    cutoff_certificate: SignedCutoffPublication
    settlement_certificate: SignedSettlementPublication
    retained_settlement: CompetitionSettlement
    roster: CompetitionPackageRoster
    evidence: CompetitionPackageEvidence
    replay_limits: PublicationReplayLimits
    release_identity: CompetitionReleaseIdentity
    wallet_access_required: Literal[False] = False
    network_access_required: Literal[False] = False
    runtime_identity_authenticated: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


def competition_release_identity_digest(identity: CompetitionReleaseIdentity) -> str:
    identity = _canonical(CompetitionReleaseIdentity, identity)
    return hashlib.sha256(_RELEASE_DOMAIN + canonical_json_bytes(identity)).hexdigest()


def competition_replay_limits_digest(limits: PublicationReplayLimits) -> str:
    limits = _canonical(PublicationReplayLimits, limits)
    return hashlib.sha256(_LIMITS_DOMAIN + canonical_json_bytes(limits)).hexdigest()


def competition_package_digest(manifest: CompetitionPackageManifest) -> str:
    manifest = _canonical(CompetitionPackageManifest, manifest)
    return hashlib.sha256(_PACKAGE_DOMAIN + canonical_json_bytes(manifest)).hexdigest()


def prepare_competition_package(
    *,
    policy: CompetitionPolicy,
    cutoff_certificate: SignedCutoffPublication,
    settlement_certificate: SignedSettlementPublication,
    retained_settlement: CompetitionSettlement,
    roster: Sequence[SignedSubmission],
    evidence: Sequence[tuple[SignedSubmission, OutcomeEvidence]],
    replay_limits: PublicationReplayLimits,
    release_identity: CompetitionReleaseIdentity,
    destination_root: Path,
    limits: CompetitionPackageLimits,
) -> PreparedCompetitionPackage:
    """Validate every replay input, then atomically publish a sealed package."""

    policy = _canonical(CompetitionPolicy, policy)
    cutoff_certificate = _canonical(SignedCutoffPublication, cutoff_certificate)
    settlement_certificate = _canonical(SignedSettlementPublication, settlement_certificate)
    retained_settlement = _canonical(CompetitionSettlement, retained_settlement)
    replay_limits = _canonical(PublicationReplayLimits, replay_limits)
    release_identity = _canonical(CompetitionReleaseIdentity, release_identity)
    limits = _canonical(CompetitionPackageLimits, limits)
    normalized_roster = _roster(roster, policy)
    normalized_evidence = _evidence(evidence)

    cutoff, settlement = _verify_publications(
        policy,
        normalized_roster,
        cutoff_certificate,
        settlement_certificate,
        normalized_evidence,
        retained_settlement,
        replay_limits,
    )

    _verify_repair_release(normalized_evidence, release_identity)

    objects: dict[str, StrictProtocolModel] = {
        "cutoff-certificate.json": cutoff_certificate,
        "evidence.json": normalized_evidence,
        "policy.json": policy,
        "release-identity.json": release_identity,
        "replay-limits.json": replay_limits,
        "roster.json": normalized_roster,
        "settlement-certificate.json": settlement_certificate,
        "settlement.json": retained_settlement,
    }
    files_list = []
    aggregate_size = 0
    for name in _PAYLOAD_NAMES:
        body = canonical_json_bytes(objects[name])
        _enforce_object_size(name, len(body), limits)
        aggregate_size += len(body)
        if aggregate_size > limits.maximum_aggregate_bytes:
            raise ValueError("package exceeds the aggregate byte limit")
        files_list.append(
            CompetitionPackageFile(
                name=name,
                size_bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
            )
        )
    files = tuple(files_list)
    manifest = CompetitionPackageManifest(
        schema="umi-competition-replay-package-manifest/1",
        profile="competition_publication_replay_no_weight/1",
        files=files,
        policy_sha256=digest(policy),
        round_sha256=cutoff.round_sha256,
        round_sequence=cutoff.round.sequence,
        runtime_sha256=cutoff.runtime_sha256,
        cutoff_publication_sha256=cutoff_publication_digest(cutoff),
        cutoff_certificate_sha256=signed_cutoff_publication_digest(cutoff_certificate),
        settlement_publication_sha256=settlement_publication_digest(settlement),
        settlement_certificate_sha256=signed_settlement_publication_digest(settlement_certificate),
        settlement_sha256=competition_settlement_digest(retained_settlement),
        authenticated_roster_sha256=authenticated_roster_digest(
            normalized_roster.submissions,
            maximum_bytes=replay_limits.maximum_roster_bytes,
        ),
        independent_evidence_set_sha256=independent_evidence_set_digest(
            _evidence_pairs(normalized_evidence),
            maximum_bytes=replay_limits.maximum_evidence_bytes,
        ),
        projection_sha256=digest(retained_settlement.projection),
        promotion_head_sha256=digest(retained_settlement.promotion_head),
        replay_limits_sha256=competition_replay_limits_digest(replay_limits),
        release_identity_sha256=competition_release_identity_digest(release_identity),
    )
    manifest_body = canonical_json_bytes(manifest)
    if len(manifest_body) > limits.maximum_manifest_bytes:
        raise ValueError("package manifest exceeds its byte limit")
    if aggregate_size + len(manifest_body) > limits.maximum_aggregate_bytes:
        raise ValueError("package exceeds the aggregate byte limit")
    package_sha256 = competition_package_digest(manifest)

    root = _prepare_destination_root(destination_root)
    final = root / package_sha256
    root_fd = _open_directory_without_links(root)
    try:
        try:
            os.mkdir(package_sha256, 0o700, dir_fd=root_fd)
            created = True
        except FileExistsError:
            created = False
        if created:
            final_fd = os.open(
                package_sha256,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=root_fd,
            )
            try:
                info = os.fstat(final_fd)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError("new package claim is not owned and private")
                # The content-addressed name is claimed without replacement.
                # Until the final chmod, this mode-0700 directory is not an
                # accepted package. A crash leaves an inert partial claim for
                # inspection and never removes an existing destination tree.
                for record in files:
                    body = canonical_json_bytes(objects[record.name])
                    if (
                        len(body) != record.size_bytes
                        or hashlib.sha256(body).hexdigest() != record.sha256
                    ):
                        raise ValueError("package object changed during preparation")
                    _write_sealed_file(final_fd, record.name, body)
                _write_sealed_file(final_fd, "manifest.json", manifest_body)
                os.fsync(final_fd)
                os.fchmod(final_fd, 0o500)
                os.fsync(final_fd)
                os.fsync(root_fd)
            finally:
                os.close(final_fd)
    finally:
        os.close(root_fd)
    if not created:
        loaded = load_competition_package(
            final,
            expected_package_sha256=package_sha256,
            expected_policy_sha256=digest(policy),
            observed_release=release_identity,
            limits=limits,
        )
        return PreparedCompetitionPackage(
            schema="umi-prepared-competition-replay-package/1",
            package_path=str(final),
            package_sha256=loaded.package_sha256,
            manifest_sha256=loaded.manifest_sha256,
            policy_sha256=loaded.manifest.policy_sha256,
        )
    loaded = load_competition_package(
        final,
        expected_package_sha256=package_sha256,
        expected_policy_sha256=digest(policy),
        observed_release=release_identity,
        limits=limits,
    )
    return PreparedCompetitionPackage(
        schema="umi-prepared-competition-replay-package/1",
        package_path=str(final),
        package_sha256=loaded.package_sha256,
        manifest_sha256=loaded.manifest_sha256,
        policy_sha256=loaded.manifest.policy_sha256,
    )


def load_competition_package(
    package_path: Path,
    *,
    expected_package_sha256: str,
    expected_policy_sha256: str,
    observed_release: CompetitionReleaseIdentity,
    limits: CompetitionPackageLimits,
) -> VerifiedCompetitionPackage:
    """Strictly load and replay a sealed package under caller-supplied bounds."""

    _require_hex32(expected_package_sha256, "expected package digest")
    _require_hex32(expected_policy_sha256, "expected policy digest")
    observed_release = _canonical(CompetitionReleaseIdentity, observed_release)
    limits = _canonical(CompetitionPackageLimits, limits)
    path = _canonical_absolute_path(package_path, "package")

    with _opened_sealed_directory(path) as root_fd:
        root_before = _directory_identity(root_fd)
        _check_exact_tree(root_fd)
        manifest_body = _read_sealed_file(
            root_fd,
            "manifest.json",
            maximum_bytes=limits.maximum_manifest_bytes,
        )
        manifest = _parse_canonical(
            CompetitionPackageManifest,
            manifest_body,
            "package manifest",
        )
        if competition_package_digest(manifest) != expected_package_sha256:
            raise ValueError("package digest differs from the caller's expected digest")
        if manifest.policy_sha256 != expected_policy_sha256:
            raise ValueError("package policy differs from the caller's expected policy")

        declared = {item.name: item for item in manifest.files}
        _preflight_declared_sizes(root_fd, declared, limits, len(manifest_body))
        policy = _read_package_model(
            root_fd, declared, limits, "policy.json", CompetitionPolicy, "policy"
        )
        cutoff_certificate = _read_package_model(
            root_fd,
            declared,
            limits,
            "cutoff-certificate.json",
            SignedCutoffPublication,
            "cutoff certificate",
        )
        settlement_certificate = _read_package_model(
            root_fd,
            declared,
            limits,
            "settlement-certificate.json",
            SignedSettlementPublication,
            "settlement certificate",
        )
        retained_settlement = _read_package_model(
            root_fd,
            declared,
            limits,
            "settlement.json",
            CompetitionSettlement,
            "retained settlement",
        )
        roster = _read_package_model(
            root_fd,
            declared,
            limits,
            "roster.json",
            CompetitionPackageRoster,
            "roster",
        )
        evidence = _read_package_model(
            root_fd,
            declared,
            limits,
            "evidence.json",
            CompetitionPackageEvidence,
            "evidence",
        )
        replay_limits = _read_package_model(
            root_fd,
            declared,
            limits,
            "replay-limits.json",
            PublicationReplayLimits,
            "publication replay limits",
        )
        release_identity = _read_package_model(
            root_fd,
            declared,
            limits,
            "release-identity.json",
            CompetitionReleaseIdentity,
            "release identity",
        )
        _check_exact_tree(root_fd)
        if root_before != _directory_identity(root_fd):
            raise ValueError("package directory changed while it was read")
    if release_identity != observed_release:
        raise ValueError("package release identity differs from the observed release")

    cutoff, settlement = _verify_publications(
        policy,
        roster,
        cutoff_certificate,
        settlement_certificate,
        evidence,
        retained_settlement,
        replay_limits,
    )
    _verify_repair_release(evidence, release_identity)
    expected = {
        "policy_sha256": digest(policy),
        "round_sha256": cutoff.round_sha256,
        "round_sequence": cutoff.round.sequence,
        "runtime_sha256": cutoff.runtime_sha256,
        "cutoff_publication_sha256": cutoff_publication_digest(cutoff),
        "cutoff_certificate_sha256": signed_cutoff_publication_digest(cutoff_certificate),
        "settlement_publication_sha256": settlement_publication_digest(settlement),
        "settlement_certificate_sha256": signed_settlement_publication_digest(
            settlement_certificate
        ),
        "settlement_sha256": competition_settlement_digest(retained_settlement),
        "authenticated_roster_sha256": authenticated_roster_digest(
            roster.submissions,
            maximum_bytes=replay_limits.maximum_roster_bytes,
        ),
        "independent_evidence_set_sha256": independent_evidence_set_digest(
            _evidence_pairs(evidence),
            maximum_bytes=replay_limits.maximum_evidence_bytes,
        ),
        "projection_sha256": digest(retained_settlement.projection),
        "promotion_head_sha256": digest(retained_settlement.promotion_head),
        "replay_limits_sha256": competition_replay_limits_digest(replay_limits),
        "release_identity_sha256": competition_release_identity_digest(release_identity),
    }
    if any(getattr(manifest, key) != value for key, value in expected.items()):
        raise ValueError("package manifest semantic binding mismatch")

    return VerifiedCompetitionPackage(
        schema="umi-verified-competition-replay-package/1",
        package_sha256=expected_package_sha256,
        manifest_sha256=hashlib.sha256(manifest_body).hexdigest(),
        manifest=manifest,
        policy=policy,
        cutoff_certificate=cutoff_certificate,
        settlement_certificate=settlement_certificate,
        retained_settlement=retained_settlement,
        roster=roster,
        evidence=evidence,
        replay_limits=replay_limits,
        release_identity=release_identity,
    )


def _verify_repair_release(evidence, release_identity):
    from .competition_dispatch_repair import EndpointUnavailableEvidence
    from .competition_void import VoidEvaluationEvidence

    target = competition_release_identity_digest(release_identity)
    for entry in evidence.entries:
        if isinstance(entry.evidence, VoidEvaluationEvidence):
            for signed in entry.evidence.certificate.void.observations:
                obs = signed.announcement.evidence
                if isinstance(obs, EndpointUnavailableEvidence) and (
                    obs.repair.amendment.successor_release_identity_sha256 != target
                ):
                    raise ValueError("repair package requires its authorized successor release")


def _verify_publications(
    policy: CompetitionPolicy,
    roster: CompetitionPackageRoster,
    cutoff_certificate: SignedCutoffPublication,
    settlement_certificate: SignedSettlementPublication,
    evidence: CompetitionPackageEvidence,
    retained_settlement: CompetitionSettlement,
    replay_limits: PublicationReplayLimits,
) -> tuple[CutoffPublication, SettlementPublication]:
    with replay_lineage(policy, roster.predecessor_policies) as lineage:
        if len(lineage.admitted_policy_sha256s) != len(roster.predecessor_policies) + 1:
            raise ValueError("package predecessor changes submission terms")
        cutoff = verify_cutoff_publication(
            cutoff_certificate,
            policy=policy,
            submissions=roster.submissions,
            limits=replay_limits,
        )
        settlement = verify_settlement_publication(
            settlement_certificate,
            cutoff_certificate=cutoff_certificate,
            policy=policy,
            submissions=roster.submissions,
            evidence=_evidence_pairs(evidence),
            retained_settlement=retained_settlement,
            limits=replay_limits,
        )
        return cutoff, settlement


def _roster(
    submissions: Sequence[SignedSubmission], policy: CompetitionPolicy
) -> CompetitionPackageRoster:
    lineage = registered_lineage(policy)
    predecessors = tuple(lineage.policy(key) for key in lineage.admitted_policy_sha256s[1:])
    normalized = tuple(
        sorted(
            (_canonical(SignedSubmission, item) for item in submissions),
            key=lambda item: digest(item.submission),
        )
    )
    return CompetitionPackageRoster(
        schema="umi-competition-replay-roster/2"
        if predecessors
        else "umi-competition-replay-roster/1",
        predecessor_policies=predecessors,
        submissions=normalized,
    )


def _evidence(
    evidence: Sequence[tuple[SignedSubmission, OutcomeEvidence]],
) -> CompetitionPackageEvidence:
    entries = tuple(
        sorted(
            (
                CompetitionPackageEvidenceEntry(
                    submission=_canonical(SignedSubmission, signed),
                    evidence=parse_outcome(independent),
                )
                for signed, independent in evidence
            ),
            key=lambda item: digest(item.submission.submission),
        )
    )
    return CompetitionPackageEvidence(
        schema=(
            "umi-competition-replay-evidence/2"
            if any(isinstance(e.evidence, VoidEvaluationEvidence) for e in entries)
            else "umi-competition-replay-evidence/1"
        ),
        entries=entries,
    )


def _evidence_pairs(
    evidence: CompetitionPackageEvidence,
) -> tuple[tuple[SignedSubmission, OutcomeEvidence], ...]:
    return tuple((item.submission, item.evidence) for item in evidence.entries)


def _canonical(model_type: type[_ModelT], value: _ModelT) -> _ModelT:
    return model_type.model_validate_json(canonical_json_bytes(value), strict=True)


def _parse_canonical(model_type: type[_ModelT], body: bytes, label: str) -> _ModelT:
    value = model_type.model_validate_json(body, strict=True)
    if canonical_json_bytes(value) != body:
        raise ValueError(f"{label} is not canonical JSON")
    return value


def _read_package_model(
    root_fd: int,
    declared: dict[str, CompetitionPackageFile],
    limits: CompetitionPackageLimits,
    name: str,
    model_type: type[_ModelT],
    label: str,
) -> _ModelT:
    record = declared[name]
    body = _read_sealed_file(
        root_fd,
        name,
        maximum_bytes=_limit_for(name, limits),
        expected_size=record.size_bytes,
        expected_sha256=record.sha256,
    )
    return _parse_canonical(model_type, body, label)


def _require_hex32(value: str, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"invalid {label}")


def _canonical_absolute_path(path: Path, label: str) -> Path:
    path = Path(path)
    if (
        not path.is_absolute()
        or path == Path(path.anchor)
        or len(os.fsencode(path)) > _MAX_PATH_BYTES
        or path != Path(os.path.abspath(path))
    ):
        raise ValueError(f"{label} path must be a dedicated canonical absolute path")
    return path


def _prepare_destination_root(path: Path) -> Path:
    path = _canonical_absolute_path(path, "package destination")
    parent_fd = _open_directory_without_links(path.parent)
    try:
        with suppress(FileExistsError):
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    descriptor = _open_directory_without_links(path)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("package destination must be owned by this user and mode 0700")
    finally:
        os.close(descriptor)
    return path


@contextmanager
def _opened_sealed_directory(path: Path):
    descriptor = _open_directory_without_links(path)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o500
        ):
            raise ValueError("package must be an owned directory with mode 0500")
        yield descriptor
    finally:
        os.close(descriptor)


def _check_exact_tree(root_fd: int) -> None:
    with os.scandir(root_fd) as entries:
        observed = set()
        for entry in entries:
            if entry.name not in _TREE_NAMES or not entry.is_file(follow_symlinks=False):
                raise ValueError("package contains an undeclared file, link or directory")
            observed.add(entry.name)
    if observed != _TREE_NAMES:
        raise ValueError("package does not contain the exact required file set")


def _directory_identity(descriptor: int) -> tuple[int, int, int, int]:
    info = os.fstat(descriptor)
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


def _file_identity(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_uid,
        info.st_nlink,
        info.st_mode,
    )


def _read_sealed_file(
    root_fd: int,
    name: str,
    *,
    maximum_bytes: int,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=root_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size < 1
            or before.st_size > maximum_bytes
            or (expected_size is not None and before.st_size != expected_size)
        ):
            raise ValueError("package object is not a bounded sealed regular file")
        chunks = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(_COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise ValueError("package object was truncated while being read")
            chunks.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("package object grew while being read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    body = bytes(chunks)
    if _file_identity(before) != _file_identity(after):
        raise ValueError("package object changed while it was read")
    if expected_sha256 is not None and hashlib.sha256(body).hexdigest() != expected_sha256:
        raise ValueError("package object digest does not match its manifest")
    return body


def _preflight_declared_sizes(
    root_fd: int,
    declared: dict[str, CompetitionPackageFile],
    limits: CompetitionPackageLimits,
    manifest_size: int,
) -> None:
    total = manifest_size
    for name in _PAYLOAD_NAMES:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=root_fd,
        )
        try:
            info = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o400
            or info.st_size != declared[name].size_bytes
            or info.st_size > _limit_for(name, limits)
        ):
            raise ValueError("package object fails its declared size or file constraints")
        total += info.st_size
        if total > limits.maximum_aggregate_bytes:
            raise ValueError("package exceeds the aggregate byte limit")


def _limit_for(name: str, limits: CompetitionPackageLimits) -> int:
    return {
        "cutoff-certificate.json": limits.maximum_cutoff_certificate_bytes,
        "evidence.json": limits.maximum_evidence_bytes,
        "policy.json": limits.maximum_policy_bytes,
        "release-identity.json": limits.maximum_release_identity_bytes,
        "replay-limits.json": limits.maximum_replay_limits_bytes,
        "roster.json": limits.maximum_roster_bytes,
        "settlement-certificate.json": limits.maximum_settlement_certificate_bytes,
        "settlement.json": limits.maximum_settlement_bytes,
    }[name]


def _enforce_object_size(
    name: str,
    size_bytes: int,
    limits: CompetitionPackageLimits,
) -> None:
    if size_bytes < 1 or size_bytes > _limit_for(name, limits):
        raise ValueError("package object exceeds its byte limit")


def _write_sealed_file(root_fd: int, name: str, body: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=root_fd,
    )
    try:
        total = 0
        while total < len(body):
            written = os.write(descriptor, body[total:])
            if written <= 0:
                raise OSError("package object write made no progress")
            total += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_directory_without_links(path: Path) -> int:
    """Open every absolute component relative to its already-open parent."""

    path = Path(path)
    if path != Path(path.anchor):
        path = _canonical_absolute_path(path, "directory")
    elif not path.is_absolute():
        raise ValueError("directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


__all__ = [
    "CompetitionPackageEvidence",
    "CompetitionPackageEvidenceEntry",
    "CompetitionPackageFile",
    "CompetitionPackageLimits",
    "CompetitionPackageManifest",
    "CompetitionPackageRoster",
    "CompetitionReleaseIdentity",
    "PreparedCompetitionPackage",
    "VerifiedCompetitionPackage",
    "competition_package_digest",
    "competition_release_identity_digest",
    "competition_replay_limits_digest",
    "load_competition_package",
    "prepare_competition_package",
]
