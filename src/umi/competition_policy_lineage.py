"""Deal-preserving policy lineage: which signed submissions a live policy admits.

A ``CompetitionPolicy`` mixes two kinds of field. *Deal* fields are what a miner
consents to when signing a ``Submission`` (terms, reward split, licenses, bundle
and lifetime limits). *Operational* fields are the operator's evaluation
configuration (runtime, deadline, evaluators, scoring thresholds, calibration).

A successor that changes only operational fields must not orphan every admitted
submission. This module defines the deal projection and the admission rule: a
submission signed under policy P is admissible under policy Q when Q descends
from P through ``predecessor_sha256`` and the deal projection is byte-identical
at every hop. Hop-by-hop equality, not endpoint equality, so an intermediate
policy that changed terms and then restored them cannot launder a stale consent.

Terms changes keep using ``competition_policy_transition``: that path requires a
fresh signature, and every ``accepted_terms_sha256`` check in the tree is left
untouched, so a terms change still rejects carried submissions on its own.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping

from .open_competition import CompetitionPolicy, digest
from .protocol import canonical_json_bytes

_DEAL_DOMAIN = b"umi-competition-policy-deal-v1\0"

# Fields a miner's signature is understood to consent to. Changing any of these
# requires a fresh signed submission under the successor policy.
DEAL_FIELDS: frozenset[str] = frozenset(
    {
        "schema",
        "network",
        "netuid",
        "valid_from_block",
        "valid_through_block",
        "endpoint_reward_bps",
        "model_reward_bps",
        "maximum_bundle_bytes",
        "maximum_bundle_files",
        "maximum_submission_lifetime_blocks",
        "contribution_terms_sha256",
        "accepted_model_licenses",
        "unallocated_model_burn",
    }
)

# Operator-owned evaluation configuration. A successor may change these without
# re-consent; every submission in a round is evaluated under the round's values.
OPERATIONAL_FIELDS: frozenset[str] = frozenset(
    {
        "sequence",
        "predecessor_sha256",
        "minimum_score_bps",
        "promotion_margin_bps",
        "minimum_cases_per_stratum",
        "maximum_inference_ms",
        "maximum_output_bytes",
        "minimum_submission_interval_blocks",
        "maximum_snapshot_age_blocks",
        "maximum_uids",
        "evaluators",
        "required_evaluator_groups",
        "evaluation_runtime_sha256",
        "minimum_continuous_observed_margin_bps",
        "continuous_dependence_lower_bound_floor_bps",
        "minimum_continuous_dependence_pairs",
        "continuous_dependence_duration_bins",
        "maximum_counterfactual_duration_delta_ms",
        "continuous_dependence_bootstrap_replicates",
        "continuous_dependence_confidence_bps",
        "positive_control_model_sha256",
        "minimum_positive_control_dependence_bps",
    }
)


def _policy_field_names() -> frozenset[str]:
    return frozenset(
        info.alias or name for name, info in CompetitionPolicy.model_fields.items()
    )


def _require_complete_partition() -> None:
    names = _policy_field_names()
    if DEAL_FIELDS & OPERATIONAL_FIELDS:
        raise RuntimeError("policy deal and operational field sets overlap")
    if DEAL_FIELDS | OPERATIONAL_FIELDS != names:
        missing = names - DEAL_FIELDS - OPERATIONAL_FIELDS
        extra = (DEAL_FIELDS | OPERATIONAL_FIELDS) - names
        raise RuntimeError(
            f"policy field partition is stale: unclassified={sorted(missing)} unknown={sorted(extra)}"
        )


_require_complete_partition()


def deal_body(policy: CompetitionPolicy) -> dict:
    """The deal projection of a policy, in canonical wire form."""
    body = policy.model_dump(mode="json", by_alias=True)
    return {key: value for key, value in body.items() if key in DEAL_FIELDS}


def deal_digest(policy: CompetitionPolicy) -> str:
    """Domain-separated SHA-256 of the deal projection."""
    return hashlib.sha256(_DEAL_DOMAIN + canonical_json_bytes(deal_body(policy))).hexdigest()


def operational_successor_of(successor: CompetitionPolicy, prior: CompetitionPolicy) -> bool:
    """True when ``successor`` is the immediate deal-preserving successor of ``prior``."""
    return (
        successor.sequence == prior.sequence + 1
        and successor.predecessor_sha256 == digest(prior)
        and deal_digest(successor) == deal_digest(prior)
    )


def validate_operational_successor(successor: CompetitionPolicy, prior: CompetitionPolicy) -> None:
    """Reject a successor that changed a deal field without the terms-transition path."""
    if successor.sequence != prior.sequence + 1 or successor.predecessor_sha256 != digest(prior):
        raise ValueError("successor policy does not immediately follow its predecessor")
    if deal_digest(successor) != deal_digest(prior):
        changed = sorted(
            key for key in DEAL_FIELDS if deal_body(successor).get(key) != deal_body(prior).get(key)
        )
        raise ValueError(f"successor policy changes deal fields without re-consent: {changed}")


class PolicyLineage:
    """The live policy plus the chain of predecessors whose deal it preserves.

    ``admitted_policy_sha256s`` is ordered newest first and always begins with
    the live policy's own digest. Construction validates that every supplied
    predecessor is the immediate predecessor of the one before it; it stops
    honoring the chain at the first hop whose deal projection differs, so a
    predecessor behind a terms change is never admitted.
    """

    def __init__(self, live: CompetitionPolicy, predecessors: Iterable[CompetitionPolicy] = ()):
        self.live = CompetitionPolicy.model_validate_json(canonical_json_bytes(live))
        self.deal_sha256 = deal_digest(self.live)
        admitted: list[str] = [digest(self.live)]
        bodies: dict[str, CompetitionPolicy] = {admitted[0]: self.live}
        current = self.live
        for candidate in predecessors:
            candidate = CompetitionPolicy.model_validate_json(canonical_json_bytes(candidate))
            if current.predecessor_sha256 is None or digest(candidate) != current.predecessor_sha256:
                raise ValueError("policy lineage is not a contiguous predecessor chain")
            if not operational_successor_of(current, candidate):
                break
            admitted.append(digest(candidate))
            bodies[admitted[-1]] = candidate
            current = candidate
        self.admitted_policy_sha256s: tuple[str, ...] = tuple(admitted)
        self._bodies: Mapping[str, CompetitionPolicy] = bodies

    def admits(self, policy_sha256: str) -> bool:
        return policy_sha256 in self.admitted_policy_sha256s

    def policy(self, policy_sha256: str) -> CompetitionPolicy:
        return self._bodies[policy_sha256]


def policy_admits(
    live: CompetitionPolicy, policy_sha256: str, predecessors: Iterable[CompetitionPolicy] = ()
) -> bool:
    """Convenience for single checks; callers on hot paths should hold a ``PolicyLineage``."""
    return PolicyLineage(live, predecessors).admits(policy_sha256)


# Process-wide lineage registry, keyed by live policy digest. The command entry
# point registers the operator-supplied predecessors once; pure validation
# functions deep in the round/dispatch/execution paths look the lineage up by
# the policy they already hold. With nothing registered every site keeps its
# exact-digest behavior, so the default is unchanged from before this module.
_REGISTRY: dict[str, PolicyLineage] = {}


def register_lineage(live: CompetitionPolicy, predecessors: Iterable[CompetitionPolicy] = ()) -> PolicyLineage:
    lineage = PolicyLineage(live, predecessors)
    _REGISTRY[digest(lineage.live)] = lineage
    return lineage


def clear_lineage_registry() -> None:
    """Forget every registered lineage (test isolation; never called by services)."""
    _REGISTRY.clear()


def registered_admitted_sha256s(policy_sha256: str) -> tuple[str, ...]:
    """Admitted digests for a registered live policy digest; the digest alone if unregistered."""
    lineage = _REGISTRY.get(policy_sha256)
    return (policy_sha256,) if lineage is None else lineage.admitted_policy_sha256s


def registered_lineage(policy: CompetitionPolicy) -> PolicyLineage:
    """The lineage registered for ``policy`` by the command entry point, or the policy alone."""
    return _REGISTRY.get(digest(policy)) or PolicyLineage(policy)


def admitted_policy_sha256s(policy: CompetitionPolicy) -> tuple[str, ...]:
    """Policy digests whose signed submissions ``policy`` admits (itself first)."""
    lineage = _REGISTRY.get(digest(policy))
    return (digest(policy),) if lineage is None else lineage.admitted_policy_sha256s


def submission_policy_admitted(policy: CompetitionPolicy, submission_policy_sha256: str) -> bool:
    return submission_policy_sha256 in admitted_policy_sha256s(policy)


__all__ = [
    "DEAL_FIELDS",
    "OPERATIONAL_FIELDS",
    "PolicyLineage",
    "deal_body",
    "deal_digest",
    "operational_successor_of",
    "admitted_policy_sha256s",
    "clear_lineage_registry",
    "policy_admits",
    "register_lineage",
    "registered_admitted_sha256s",
    "registered_lineage",
    "submission_policy_admitted",
    "validate_operational_successor",
]
