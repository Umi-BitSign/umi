"""Explicit local selection of an already authorized ordinary-package verifier.

The private selection file is operator configuration, not a signed migration.
It pins the existing publisher configuration byte-for-byte; that configuration
supplies the established trusted authorities and native continuity consent.
No new authority, receipt, certificate, or execution evidence is synthesized.
Only the first package's replay identity is selected. Publisher admission and
revocation checks remain mandatory and independent.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_package import CompetitionReleaseIdentity, competition_release_identity_digest
from .open_competition import digest
from .private_files import Directory, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ForwardPackageSelection(StrictProtocolModel):
    schema_: Literal["umi-forward-package-selection/1"] = Field(alias="schema")
    round_sha256: Hex32
    predecessor_release_identity_sha256: Hex32
    publisher_config_path: Directory
    publisher_config_sha256: Hex32


class ForwardSuitePackageSelection(StrictProtocolModel):
    """Private prospective selection for one prepared suite, before its round exists."""

    schema_: Literal["umi-forward-suite-package-selection/1"] = Field(alias="schema")
    suite_sha256: Hex32
    predecessor_release_identity_sha256: Hex32
    publisher_config_path: Directory
    publisher_config_sha256: Hex32


def _selection(queue, publication) -> ForwardPackageSelection | None:
    root = Path(queue.config.state_directory) / "forward-releases"
    exact = root / (publication.round_sha256 + ".json")
    suite = root / "suites" / (publication.round.suite_sha256 + ".json")
    selected = None
    if exact.exists() or exact.is_symlink():
        selected = read_private_model(exact, ForwardPackageSelection, maximum_bytes=16384)
    if suite.exists() or suite.is_symlink():
        candidate = read_private_model(suite, ForwardSuitePackageSelection, maximum_bytes=16384)
        if candidate.suite_sha256 != publication.round.suite_sha256:
            raise ValueError("forward package suite selection changes the prepared suite")
        derived = ForwardPackageSelection(
            schema="umi-forward-package-selection/1",
            round_sha256=publication.round_sha256,
            predecessor_release_identity_sha256=candidate.predecessor_release_identity_sha256,
            publisher_config_path=candidate.publisher_config_path,
            publisher_config_sha256=candidate.publisher_config_sha256,
        )
        if selected is not None and selected != derived:
            raise ValueError("forward package round and suite selections conflict")
        selected = derived
    return selected


def ordinary_release_identity(queue, prepared, current_block) -> CompetitionReleaseIdentity:
    """Validate explicit selection and freeze it before the first package attempt.

    Caller holds the settlement queue's serial ownership. Missing configuration
    preserves the historical release. Removing or changing a retained selection
    fails closed; it never changes a previously selected package's identity.
    """
    publication = prepared.publication
    slot = str(publication.round.sequence)
    prior = queue.journal.get("release-selection", slot)
    selection = _selection(queue, publication)
    if selection is None:
        if prior is not None and prior["selection"] is not None:
            raise ValueError("retained forward package selection is missing")
        return queue.config.release_identity
    if (
        selection.round_sha256 != publication.round_sha256
        or selection.predecessor_release_identity_sha256
        != competition_release_identity_digest(queue.config.release_identity)
    ):
        raise ValueError("forward package selection changes the original round or release")
    from .competition_successor_publisher_cli import SuccessorPublisherConfig

    publisher = read_private_model(
        Path(selection.publisher_config_path), SuccessorPublisherConfig, maximum_bytes=4 * 1024**2
    )
    if (
        hashlib.sha256(canonical_json_bytes(publisher)).hexdigest()
        != selection.publisher_config_sha256
    ):
        raise ValueError("forward package publisher configuration changed")
    plan, round_ = publisher.plan, publication.round
    authority = None if plan.continuity is None else plan.continuity.authority
    if (
        authority is None
        or plan.policy_sha256 != digest(queue.policy)
        or round_.policy_sha256 != plan.policy_sha256
        or publisher.intake_directory != str(queue.store.directory)
        or plan.package_limits != queue.config.package_limits
        or publisher.chain.chain_pin != queue.provider.config.chain_pin
        or plan.chain.chain_pin != publisher.chain.chain_pin
        or not publisher.public_launch.contains_schedule(round_.public_schedule)
        or tuple(publisher.public_launch.eligible_tracks) != tuple(round_.eligible_tracks)
        or not authority.first_round_sequence <= round_.sequence <= authority.last_round_sequence
        or (
            round_.sequence == authority.first_round_sequence
            and authority.first_round_sha256 != publication.round_sha256
        )
        or type(current_block) is not int
        or not max(plan.valid_from_block, publication.settlement.observed_block)
        <= current_block
        <= min(
            plan.valid_through_block, round_.valid_through_block, queue.policy.valid_through_block
        )
    ):
        raise ValueError("forward package selection exceeds the approved publisher scope")
    target = plan.release.replay_release_identity
    if (
        target == queue.config.release_identity
        or target.target_triple != queue.config.release_identity.target_triple
    ):
        raise ValueError("forward package selection must name a different same-platform verifier")
    record = {
        "selection": selection.model_dump(mode="json", by_alias=True),
        "release": target.model_dump(mode="json", by_alias=True),
    }
    if prior is not None and prior != record:
        raise ValueError("forward package selection differs from its retained reservation")
    if prior is None and any(
        queue.journal.get(kind, slot) is not None for kind in ("certificate", "package")
    ):
        raise ValueError("forward package selection is too late for an existing package attempt")
    queue.journal.put("release-selection", slot, record)
    return target
