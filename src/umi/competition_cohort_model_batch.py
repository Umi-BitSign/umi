"""Explicit cohort artifact certificates with bounded Merkle membership proofs.

The separate signed adoption authorizes a prospective certificate format under
an exact original history prefix. It does not edit that history, authorize a
phase transition, prove roster completeness, or replace private reviewer policy
selection. Owners and reviewers retain their own adoption and candidate intents.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field

from .competition_assignment_reuse import AssignmentVerificationReuse
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_recovery import Block, ModelRewardCohortAuthority, verify_recovery_quorum
from .open_competition import Signature, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_cohort_model_acceptance import ModelArtifactAcceptance

MAX_BATCH_MODELS = 512
MAX_BATCH_PROOF_DEPTH = (MAX_BATCH_MODELS - 1).bit_length()
_LEAF_DOMAIN = b"umi-model-acceptance-batch-leaf/1\0"
_NODE_DOMAIN = b"umi-model-acceptance-batch-node/1\0"
_EMPTY_ROOT = hashlib.sha256(b"umi-model-acceptance-batch-empty/1\0").hexdigest()
_history_checks = AssignmentVerificationReuse(4 * 1024**2, 512)
_batch_checks = AssignmentVerificationReuse(4 * 1024**2, 512)


def _history_phase(history, policy, *, block):
    # Historical metadata only. Current selection, finality, conflict holds and
    # durable per-model completion remain the caller's separately owned checks.
    key = ("model-batch-history/1", digest(history), digest(policy), block)

    def check():
        return verify_cohort_history(
            history, policy, expected_tip_sha256=_tip(history), current_block=block
        ).state.phase

    return _history_checks.resolve(key, key, check)


class ModelBatchCertificationAdoption(StrictProtocolModel):
    schema_: Literal["umi-model-batch-certification-adoption/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    predecessor_sha256: Hex32
    history_prefix_sha256: Hex32
    effective_at_block: Block
    rule: Literal["cohort_manifest_merkle_quorum/1"] = "cohort_manifest_merkle_quorum/1"
    preserve_legacy_certificates: Literal[True] = True


class SignedModelBatchCertificationAdoption(StrictProtocolModel):
    adoption: ModelBatchCertificationAdoption
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class ModelAcceptanceBatch(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-acceptance-batch/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    adoption_sha256: Hex32
    recovery_tip_sha256: Hex32
    candidate_snapshot_sha256: Hex32
    roster_sha256: Hex32
    accepted_count: Annotated[int, Field(ge=0, le=MAX_BATCH_MODELS)]
    merkle_root_sha256: Hex32
    certified_at_block: Block


class CertifiedModelAcceptanceBatch(StrictProtocolModel):
    batch: ModelAcceptanceBatch
    adoption: SignedModelBatchCertificationAdoption
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class ModelAcceptanceBatchProof(StrictProtocolModel):
    certificate: CertifiedModelAcceptanceBatch
    leaf_index: Annotated[int, Field(ge=0, lt=MAX_BATCH_MODELS)]
    siblings: Annotated[tuple[Hex32, ...], Field(max_length=MAX_BATCH_PROOF_DEPTH)]


def _tip(history):
    return digest(history.transitions[-1].transition if history.transitions else history.genesis)


def _prefix(history, tip):
    tips = [digest(history.genesis), *(digest(s.transition) for s in history.transitions)]
    try:
        index = tips.index(tip)
    except ValueError:
        raise ValueError("model batch authority is outside retained history") from None
    return history.model_copy(update={"transitions": history.transitions[:index]}), index


def _scope(history, policy, *, maximum_block):
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    if type(maximum_block) is not int or not 0 <= maximum_block <= 2**53 - 1:
        raise ValueError("model batch historical block bound is invalid")
    if not isinstance(history.authority.authority, ModelRewardCohortAuthority):
        raise ValueError("model batch requires model-reward cohort authority")
    tip = history.transitions[-1].transition if history.transitions else history.genesis
    tip_block = tip.observed_at_block if history.transitions else tip.admitted_at_block
    _history_phase(history, policy, block=max(maximum_block, tip_block))
    return history


def prepare_model_batch_certification_adoption(
    history, policy, *, expected_tip_sha256: str, effective_at_block: int
) -> ModelBatchCertificationAdoption:
    """Prepare exact unsigned bytes; owner selection and reservation are separate."""
    history = _scope(history, policy, maximum_block=effective_at_block)
    if _tip(history) != expected_tip_sha256:
        raise ValueError("model batch adoption changes the selected predecessor")
    if _history_phase(history, policy, block=effective_at_block) != "intake":
        raise ValueError("model batch adoption requires open intake")
    return ModelBatchCertificationAdoption(
        schema="umi-model-batch-certification-adoption/1",
        policy_sha256=digest(policy),
        cohort_sha256=digest(history.plan),
        authority_sha256=digest(history.authority.authority),
        predecessor_sha256=expected_tip_sha256,
        history_prefix_sha256=digest(history),
        effective_at_block=effective_at_block,
    )


def verify_model_batch_certification_adoption(
    signed: SignedModelBatchCertificationAdoption, history, policy, *, maximum_block: int
) -> None:
    signed = SignedModelBatchCertificationAdoption.model_validate_json(canonical_json_bytes(signed))
    history = _scope(history, policy, maximum_block=maximum_block)
    adoption = signed.adoption
    prefix, index = _prefix(history, adoption.predecessor_sha256)
    expected = prepare_model_batch_certification_adoption(
        prefix,
        policy,
        expected_tip_sha256=adoption.predecessor_sha256,
        effective_at_block=adoption.effective_at_block,
    )
    if (
        adoption != expected
        or adoption.effective_at_block > maximum_block
        or (
            index < len(history.transitions)
            and adoption.effective_at_block
            > history.transitions[index].transition.observed_at_block
        )
    ):
        raise ValueError("model batch adoption changes original authority, history or time")
    verify_recovery_quorum(adoption, signed.signatures, policy)


def _ordered(acceptances):
    acceptances = tuple(acceptances)
    if len(acceptances) > MAX_BATCH_MODELS:
        raise ValueError("model batch exceeds the supported roster bound")
    result = tuple(sorted(acceptances, key=lambda a: a.submission_sha256))
    if len({a.submission_sha256 for a in result}) != len(result):
        raise ValueError("model batch repeats a submission")
    if len({a.accepted_ordinal for a in result}) != len(result):
        raise ValueError("model batch repeats an acceptance ordinal")
    ordered = sorted(result, key=lambda a: a.accepted_ordinal)
    blocks = [a.accepted_at_block for a in ordered]
    if blocks != sorted(blocks):
        raise ValueError("model batch ordinals contradict accepted block order")
    return result


def _leaf(acceptance):
    return hashlib.sha256(_LEAF_DOMAIN + canonical_json_bytes(acceptance)).hexdigest()


def _node(left, right):
    return hashlib.sha256(_NODE_DOMAIN + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def model_acceptance_batch_root(acceptances) -> str:
    """Canonical submission order, domain separation, and odd-node duplication."""
    level = [_leaf(a) for a in _ordered(acceptances)]
    if not level:
        return _EMPTY_ROOT
    while len(level) > 1:
        level = [
            _node(level[n], level[min(n + 1, len(level) - 1)]) for n in range(0, len(level), 2)
        ]
    return level[0]


def verify_model_acceptance_batch_body(
    batch: ModelAcceptanceBatch,
    adoption: SignedModelBatchCertificationAdoption,
    history,
    policy,
    *,
    maximum_block: int,
) -> None:
    """Authenticate a prospective header without pretending a vote is a quorum."""
    batch = ModelAcceptanceBatch.model_validate_json(canonical_json_bytes(batch))
    adoption = SignedModelBatchCertificationAdoption.model_validate_json(
        canonical_json_bytes(adoption)
    )
    history = _scope(history, policy, maximum_block=maximum_block)
    verify_model_batch_certification_adoption(
        adoption, history, policy, maximum_block=maximum_block
    )
    prefix, index = _prefix(history, batch.recovery_tip_sha256)
    _, adoption_index = _prefix(history, adoption.adoption.predecessor_sha256)
    phase = _history_phase(prefix, policy, block=batch.certified_at_block)
    if (
        batch.policy_sha256 != digest(policy)
        or batch.cohort_sha256 != digest(history.plan)
        or batch.authority_sha256 != digest(history.authority.authority)
        or batch.adoption_sha256 != digest(adoption.adoption)
        or not adoption.adoption.effective_at_block <= batch.certified_at_block <= maximum_block
        or index < adoption_index
        or phase != "intake"
        or (
            index < len(history.transitions)
            and batch.certified_at_block > history.transitions[index].transition.observed_at_block
        )
        or "0" * 64 in (batch.candidate_snapshot_sha256, batch.roster_sha256)
        or (batch.accepted_count == 0 and batch.merkle_root_sha256 != _EMPTY_ROOT)
    ):
        raise ValueError("model batch changes its adopted authority, candidate or signing time")


def build_model_acceptance_batch(
    acceptances,
    adoption: SignedModelBatchCertificationAdoption,
    history,
    policy,
    *,
    candidate_snapshot_sha256: str,
    roster_sha256: str,
    certified_at_block: int,
) -> ModelAcceptanceBatch:
    """Bind completed bodies; caller proves owned candidate completeness separately."""
    selected = _ordered(acceptances)
    batch = ModelAcceptanceBatch(
        schema="umi-cohort-model-acceptance-batch/1",
        policy_sha256=digest(policy),
        cohort_sha256=digest(history.plan),
        authority_sha256=digest(history.authority.authority),
        adoption_sha256=digest(adoption.adoption),
        recovery_tip_sha256=_tip(history),
        candidate_snapshot_sha256=candidate_snapshot_sha256,
        roster_sha256=roster_sha256,
        accepted_count=len(selected),
        merkle_root_sha256=model_acceptance_batch_root(selected),
        certified_at_block=certified_at_block,
    )
    verify_model_acceptance_batch_body(
        batch, adoption, history, policy, maximum_block=certified_at_block
    )
    for acceptance in selected:
        _member_scope(acceptance, batch)
    return batch


def verify_model_acceptance_batch(
    certificate: CertifiedModelAcceptanceBatch, history, policy, *, maximum_block: int
) -> None:
    if type(maximum_block) is not int or not 0 <= maximum_block <= 2**53 - 1:
        raise ValueError("model batch historical block bound is invalid")
    certificate = CertifiedModelAcceptanceBatch.model_validate_json(
        canonical_json_bytes(certificate)
    )
    # All membership consumers in one selected snapshot share the expensive
    # header/history/signature check. Merkle membership and each original body's
    # participant/consent checks remain individual. This is not a native verdict.
    key = (
        "model-batch-certificate/1",
        digest(certificate),
        digest(history),
        digest(policy),
        maximum_block,
    )

    def check():
        verify_model_acceptance_batch_body(
            certificate.batch, certificate.adoption, history, policy, maximum_block=maximum_block
        )
        verify_recovery_quorum(certificate.batch, certificate.signatures, policy)
        return True

    _batch_checks.resolve(key, key, check)


def _member_scope(acceptance, batch):
    if (
        acceptance.policy_sha256 != batch.policy_sha256
        or acceptance.cohort_sha256 != batch.cohort_sha256
        or acceptance.authority_sha256 != batch.authority_sha256
        or acceptance.accepted_at_block > batch.certified_at_block
    ):
        raise ValueError("model batch member changes its signed scope or time")


def verify_model_acceptance_batch_proof(
    acceptance: ModelArtifactAcceptance,
    proof: ModelAcceptanceBatchProof,
    history,
    policy,
    *,
    maximum_block: int,
) -> None:
    proof = ModelAcceptanceBatchProof.model_validate_json(canonical_json_bytes(proof))
    certificate, batch = proof.certificate, proof.certificate.batch
    verify_model_acceptance_batch(certificate, history, policy, maximum_block=maximum_block)
    _member_scope(acceptance, batch)
    if identity(acceptance.recipient_hotkey) in {
        identity(s.hotkey) for s in certificate.signatures
    }:
        raise ValueError("model submitters cannot certify their own batch membership")
    count, index = batch.accepted_count, proof.leaf_index
    if not 0 <= index < count or len(proof.siblings) != (count - 1).bit_length():
        raise ValueError("model batch membership geometry differs")
    value = _leaf(acceptance)
    for sibling in proof.siblings:
        if count % 2 and index == count - 1 and sibling != value:
            raise ValueError("model batch odd-node membership differs")
        value = _node(sibling, value) if index % 2 else _node(value, sibling)
        index, count = index // 2, (count + 1) // 2
    if value != batch.merkle_root_sha256:
        raise ValueError("model acceptance is outside its signed batch")


def model_acceptance_batch_proofs(
    acceptances, certificate
) -> tuple[ModelAcceptanceBatchProof, ...]:
    """Return proofs in canonical submission order; do not manufacture signatures."""
    certificate = CertifiedModelAcceptanceBatch.model_validate_json(
        canonical_json_bytes(certificate)
    )
    selected = _ordered(acceptances)
    if (
        len(selected) != certificate.batch.accepted_count
        or model_acceptance_batch_root(selected) != certificate.batch.merkle_root_sha256
    ):
        raise ValueError("model batch manifest changes the certified root or count")
    levels = [[_leaf(a) for a in selected]]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append(
            [_node(level[n], level[min(n + 1, len(level) - 1)]) for n in range(0, len(level), 2)]
        )
    result = []
    for number, acceptance in enumerate(selected):
        _member_scope(acceptance, certificate.batch)
        index, siblings = number, []
        for level in levels[:-1]:
            siblings.append(level[min(index ^ 1, len(level) - 1)])
            index //= 2
        result.append(
            ModelAcceptanceBatchProof(
                certificate=certificate, leaf_index=number, siblings=tuple(siblings)
            )
        )
    return tuple(result)
