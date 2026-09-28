"""Bounded retained inputs for the installed standing reward service.

Delivery writes canonical objects into these private directories. File presence
and hashes identify content only; native readers still verify every signature,
package, chain proof and opportunity interval before granting authority.
"""

from pathlib import Path

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_evidence_codec import checked_digest
from .competition_reward_decisions import MAX_DECISION_BYTES, SignedRewardControlDecision
from .competition_reward_opportunity import RewardOpportunityCertificate, RewardOpportunityWitness
from .competition_reward_opportunity_review import MAX_CERTIFICATE_BYTES
from .open_competition import digest
from .private_files import private_path, read_private_model
from .protocol import canonical_json_bytes


class StandingRewardFiles:
    def __init__(self, root: Path, *, maximum_package_bytes: int, maximum_witness_bytes: int):
        self.root = Path(private_path(str(root)))
        self.maximum_package_bytes = maximum_package_bytes
        self.maximum_witness_bytes = maximum_witness_bytes

    def _read(self, kind, sha, model, maximum):
        checked_digest(sha)
        value = read_private_model(self.root / kind / (sha + ".json"), model, maximum_bytes=maximum)
        # Decisions are addressed by their signed body, independently of the
        # envelope's signature ordering. Other objects use their complete body.
        selected = value.decision if kind == "decisions" else value
        if digest(selected) != sha:
            raise ValueError("standing input differs from its requested identity")
        return value

    def package(self, sha: str) -> CohortRewardPackage:
        return self._read("packages", sha, CohortRewardPackage, self.maximum_package_bytes)

    def decision(self, sha: str) -> bytes:
        return canonical_json_bytes(
            self._read("decisions", sha, SignedRewardControlDecision, MAX_DECISION_BYTES)
        )

    def certificate(self, sha: str) -> bytes:
        return canonical_json_bytes(
            self._read("opportunities", sha, RewardOpportunityCertificate, MAX_CERTIFICATE_BYTES)
        )

    def witness(self, sha: str) -> bytes:
        return canonical_json_bytes(
            self._read("witnesses", sha, RewardOpportunityWitness, self.maximum_witness_bytes)
        )
