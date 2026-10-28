"""Intake-time optional model-license discovery from retained signed metadata."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_intake import CohortIntake
from .competition_cohort_recovery import verify_recovery_authority
from .competition_model_license import verify_model_license_selection
from .competition_model_training_rights import (
    CONDITIONAL_TRAINING_RIGHTS_SHA256,
    NC_CONTRIBUTION_TERMS_SHA256,
)
from .competition_public_results_directory import atomic_write, owned_directory, read_owned_file
from .competition_verification_reuse import metadata_completion, remember_metadata_completion
from .competition_verification_snapshot import _Checksummed
from .competition_work_progress import WorkProgress
from .open_competition import CompetitionPolicy, SignedModelLicenseTermsAdoption, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_LICENSE_METADATA_BYTES = 1024 * 1024
NC_TERMS_URL = (
    "https://raw.githubusercontent.com/Umi-BitSign/umi/main/docs/MODEL_CONTRIBUTION_TERMS_NC_V1.md"
)


class PublicModelLicenseAdoption(StrictProtocolModel):
    signed_adoption: SignedModelLicenseTermsAdoption
    sha256: Hex32
    terms_sha256: Hex32
    terms_url: Literal[NC_TERMS_URL] = NC_TERMS_URL

    @model_validator(mode="after")
    def exact_metadata(self):
        body = self.signed_adoption.adoption
        if (
            self.sha256 != hashlib.sha256(canonical_json_bytes(self.signed_adoption)).hexdigest()
            or self.terms_sha256 != body.noncommercial_terms_sha256
            or self.terms_sha256 != NC_CONTRIBUTION_TERMS_SHA256
            or body.training_rights_policy_sha256 != CONDITIONAL_TRAINING_RIGHTS_SHA256
        ):
            raise ValueError("published model license metadata differs from reviewed selection")
        return self


class PublicModelLicenseAdoptions(StrictProtocolModel):
    schema_: Literal["umi-public-model-license-adoptions/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32 | None = None
    authority_sha256: Hex32 | None = None
    status: Literal["available", "not_selected"]
    items: Annotated[tuple[PublicModelLicenseAdoption, ...], Field(max_length=16)] = ()
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def exact_scope(self):
        if (self.status == "available") != bool(self.items):
            raise ValueError("model license availability differs from retained selections")
        if self.items and (self.policy_sha256 is None or self.authority_sha256 is None):
            raise ValueError("available model licenses lack native authority")
        ids = [item.sha256 for item in self.items]
        if ids != sorted(set(ids)):
            raise ValueError("model license selections must be unique and sorted")
        for item in self.items:
            body = item.signed_adoption.adoption
            if (
                body.policy_sha256 != self.policy_sha256
                or body.authority_sha256 != self.authority_sha256
                or self.cohort_sha256 not in body.cohort_sha256s
            ):
                raise ValueError("published model license selection has another scope")
        return self


def project_model_license_adoptions(history, policy, selections):
    """Authenticate small metadata once under the existing publication owner."""
    verify_recovery_authority(history.authority, policy)
    authority, cohort = history.authority.authority, digest(history.plan)
    items = []
    for signed in selections:
        body = verify_model_license_selection(signed, policy=policy, authority=authority)
        if cohort not in body.cohort_sha256s or history.plan.sequence < body.first_cohort_sequence:
            continue
        items.append(
            PublicModelLicenseAdoption(
                signed_adoption=signed,
                sha256=hashlib.sha256(canonical_json_bytes(signed)).hexdigest(),
                terms_sha256=body.noncommercial_terms_sha256,
            )
        )
    return PublicModelLicenseAdoptions(
        schema="umi-public-model-license-adoptions/1",
        cohort_sha256=cohort,
        policy_sha256=digest(policy),
        authority_sha256=digest(authority),
        status="available" if items else "not_selected",
        items=tuple(sorted(items, key=lambda item: item.sha256)),
    )


def _paths(root, cohort):
    return root / "cohorts" / (cohort + ".licenses.json"), root / "cohorts" / (
        cohort + ".licenses.published"
    )


def read_model_license_adoptions(root, cohort):
    """HTTP polling reads only the bounded checked public projection."""
    path, checkpoint = _paths(root, cohort)
    try:
        key = read_owned_file(checkpoint, 64)
    except FileNotFoundError:
        if path.exists():
            raise ValueError(
                "model license publication checkpoint missing; repair required"
            ) from None
        return PublicModelLicenseAdoptions(
            schema="umi-public-model-license-adoptions/1",
            cohort_sha256=cohort,
            status="not_selected",
        )
    raw = read_owned_file(path, MAX_LICENSE_METADATA_BYTES)
    if hashlib.sha256(raw).hexdigest().encode() != key:
        raise ValueError("model license publication changed; repair required")
    result = PublicModelLicenseAdoptions.model_validate_json(raw)
    if result.cohort_sha256 != cohort:
        raise ValueError("public model license projection belongs to another cohort")
    return result


def publish_model_license_adoptions(root, projection):
    for directory in (root, root / "cohorts"):
        owned_directory(directory, create=True)
    raw = canonical_json_bytes(projection)
    if len(raw) > MAX_LICENSE_METADATA_BYTES:
        raise ValueError("public model license metadata exceeds capacity")
    path, checkpoint = _paths(root, projection.cohort_sha256)
    atomic_write(checkpoint, hashlib.sha256(raw).hexdigest().encode(), immutable=False)
    atomic_write(path, raw, immutable=False)


class _LicenseCompletion(_Checksummed):
    schema_: Literal["umi-public-model-license-completion/1"] = Field(alias="schema")
    binding_sha256: Hex32
    projection: PublicModelLicenseAdoptions


class ModelLicenseMetadataPublisher:
    """Same catalog owner, independent intake-time metadata checkpoints."""

    def __init__(self, config):
        self.config = config
        self.state = Path(config.state_directory) / "model-license-adoptions"
        self.output = Path(config.template.api.results.directory)
        self.verified = {}
        self.bindings = {}
        source = config.template.native_intake
        for cohort in config.cohorts:
            selected = next(item for item in source.config.cohorts if item.cohort_sha256 == cohort)
            adoptions = tuple(
                item
                for item in config.model_license_adoptions
                if item.adoption.authority_sha256 == selected.authority_sha256
            )
            if adoptions:
                binding = hashlib.sha256(
                    canonical_json_bytes(
                        {
                            "semantics": "umi-public-model-license-publication/1",
                            "policy": config.template.policy.model_dump(mode="json", by_alias=True),
                            "native_intake": source.config.model_dump(mode="json", by_alias=True),
                            "cohort": selected.model_dump(mode="json", by_alias=True),
                            "adoptions": [
                                item.model_dump(mode="json", by_alias=True) for item in adoptions
                            ],
                        }
                    )
                ).hexdigest()
                self.bindings[cohort] = (binding, adoptions, selected)

    def poll_once(self):
        entered = time.monotonic()
        result = {"published": [], "retained": [], "repaired": [], "held": []}
        with WorkProgress(
            "public_model_license_metadata", len(self.bindings), unit="cohorts"
        ) as meter:
            for cohort, (binding, adoptions, selected) in self.bindings.items():
                try:
                    path = self.state / (binding + ".json")
                    if cohort in self.verified:
                        original_stamp, completion = self.verified[cohort]
                        if _stamp(path) != original_stamp:
                            raise ValueError("model license completion changed; repair required")
                    else:
                        try:
                            completion = _LicenseCompletion.model_validate_json(
                                read_owned_file(path, MAX_LICENSE_METADATA_BYTES)
                            ).checked()
                        except FileNotFoundError:
                            if metadata_completion(path).exists():
                                raise ValueError(
                                    "model license completion missing; repair required"
                                ) from None
                            policy = CompetitionPolicy.model_validate_json(
                                self.config.template.policy.read()
                            )
                            source = self.config.template.native_intake
                            intake = CohortIntake(
                                source.config,
                                policy,
                                eligible_tracks=source.eligible_tracks,
                                read_only=True,
                            )
                            history = intake.history(cohort)
                            if (
                                digest(history.plan) != cohort
                                or digest(history.authority.authority) != selected.authority_sha256
                            ):
                                raise ValueError(
                                    "model license history differs from selected intake authority"
                                ) from None
                            projection = project_model_license_adoptions(history, policy, adoptions)
                            completion = _LicenseCompletion(
                                schema="umi-public-model-license-completion/1",
                                binding_sha256=binding,
                                projection=projection,
                            ).sealed()
                            owned_directory(self.state, create=True)
                            atomic_write(path, canonical_json_bytes(completion))
                        if (
                            completion.binding_sha256 != binding
                            or completion.projection.cohort_sha256 != cohort
                        ):
                            raise ValueError(
                                "model license completion has another selected binding"
                            )
                        remember_metadata_completion(path)
                        self.verified[cohort] = (_stamp(path), completion)
                    try:
                        current = read_model_license_adoptions(self.output, cohort)
                    except (FileNotFoundError, ValueError) as error:
                        current = None
                        result["repaired"].append({"cohort_sha256": cohort, "reason": str(error)})
                    if current != completion.projection:
                        publish_model_license_adoptions(self.output, completion.projection)
                        result["published"].append(cohort)
                    else:
                        result["retained"].append(cohort)
                    meter.advance()
                except (OSError, ValueError) as error:
                    result["held"].append(
                        {
                            "cohort_sha256": cohort,
                            "reason": str(error),
                            "error_type": type(error).__name__,
                        }
                    )
        completed = len(result["published"]) + len(result["retained"])
        result.update(
            completed=completed,
            total=len(self.bindings),
            percent=100 * completed / len(self.bindings) if self.bindings else 100,
            elapsed_seconds=round(time.monotonic() - entered, 3),
            eta_seconds=None if result["held"] else 0,
            eta_basis="waiting_for_original_metadata_or_explicit_repair"
            if result["held"]
            else "selected_model_license_metadata_current",
            stalled_or_retrying=bool(result["held"]),
        )
        return result


def _stamp(path):
    value = path.stat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
