"""Bounded retained inputs for the installed standing reward service.

Delivery writes canonical objects into these private directories. File presence
and hashes identify content only; native readers still verify every signature,
package, chain proof and opportunity interval before granting authority.
"""

from pathlib import Path

from .competition_cohort_aggregate_files import publish_aggregate_model, read_aggregate_model
from .competition_cohort_aggregate_replica import replicate_verified_aggregate
from .competition_cohort_capacity import check_aggregate_evidence_bytes
from .competition_cohort_reward_package import CohortRewardPackage
from .competition_evidence_codec import checked_digest
from .competition_reward_adoption import MAX_REWARD_ADOPTION_BYTES, SignedRewardModelAdoption
from .competition_reward_decisions import MAX_DECISION_BYTES, SignedRewardControlDecision
from .competition_reward_opportunity import RewardOpportunityCertificate, RewardOpportunityWitness
from .competition_reward_opportunity_review import MAX_CERTIFICATE_BYTES
from .competition_verification_snapshot import VerificationPackageStore, VerifiedPackageSnapshot
from .open_competition import digest
from .private_files import (
    ensure_private_directory,
    private_path,
    publish_private_model,
    read_private_model,
)
from .protocol import canonical_json_bytes


class StandingRewardFiles:
    def __init__(self, root: Path, *, maximum_package_bytes: int, maximum_witness_bytes: int):
        self.root = Path(private_path(str(root)))
        self.maximum_package_bytes = check_aggregate_evidence_bytes(maximum_package_bytes)
        self.maximum_witness_bytes = maximum_witness_bytes
        ensure_private_directory(self.root)

    @property
    def package_store(self):
        return VerificationPackageStore(self.root / "verification" / "packages")

    def _read(self, kind, sha, model, maximum):
        checked_digest(sha)
        reader = read_aggregate_model if kind == "packages" else read_private_model
        value = reader(self.root / kind / (sha + ".json"), model, maximum_bytes=maximum)
        # Decisions are addressed by their signed body, independently of the
        # envelope's signature ordering. Other objects use their complete body.
        selected = (
            value.decision
            if kind == "decisions"
            else value.adoption
            if kind == "adoptions"
            else value
        )
        if digest(selected) != sha:
            raise ValueError("standing input differs from its requested identity")
        return value

    def package(self, sha: str) -> CohortRewardPackage:
        return self._read("packages", sha, CohortRewardPackage, self.maximum_package_bytes)

    def adoption(self, sha: str) -> SignedRewardModelAdoption:
        return self._read("adoptions", sha, SignedRewardModelAdoption, MAX_REWARD_ADOPTION_BYTES)

    def retain_adoption(self, value: SignedRewardModelAdoption) -> None:
        publish_private_model(
            self.root / "adoptions" / (digest(value.adoption) + ".json"),
            value,
            maximum_bytes=MAX_REWARD_ADOPTION_BYTES,
        )

    def verified_package(self, sha: str) -> VerifiedPackageSnapshot:
        """Prepare a new source once; damaged completed state requires repair."""
        checked_digest(sha)
        return self.package_store.load(
            self.root / "packages" / (sha + ".json"),
            CohortRewardPackage,
            maximum_bytes=self.maximum_package_bytes,
            expected_sha256=sha,
        )

    def retain_package(self, package: CohortRewardPackage | VerifiedPackageSnapshot) -> None:
        """Retain immutable package bytes; presence does not replace native replay."""
        if type(package) is VerifiedPackageSnapshot:
            package.check(package.package, package.sha256, self.maximum_package_bytes)
            binding = replicate_verified_aggregate(
                Path(package.record.original_path),
                self.root / "packages" / (package.sha256 + ".json"),
                expected_digest=package.sha256,
                maximum_bytes=self.maximum_package_bytes,
                verified_source=package,
            )
            if binding is not None:
                self.package_store.bind_replica(
                    package, binding, maximum_bytes=self.maximum_package_bytes
                )
            else:
                # An unqualified filesystem clock cannot create a reusable
                # replica capability. The ordinary native first preparation
                # remains supported and emits its own progress.
                self.verified_package(package.sha256)
            return
        package = CohortRewardPackage.model_validate_json(canonical_json_bytes(package))
        publish_aggregate_model(
            self.root / "packages" / (digest(package) + ".json"),
            package,
            maximum_bytes=self.maximum_package_bytes,
        )

    def decision(self, sha: str) -> bytes:
        return canonical_json_bytes(
            self._read("decisions", sha, SignedRewardControlDecision, MAX_DECISION_BYTES)
        )

    def retain_decision(self, value: SignedRewardControlDecision) -> None:
        """Retain exact delivery bytes; signature and chain review are separate."""
        publish_private_model(
            self.root / "decisions" / (digest(value.decision) + ".json"),
            value,
            maximum_bytes=MAX_DECISION_BYTES,
        )

    def certificate(self, sha: str) -> bytes:
        return canonical_json_bytes(
            self._read("opportunities", sha, RewardOpportunityCertificate, MAX_CERTIFICATE_BYTES)
        )

    def witness(self, sha: str) -> bytes:
        return canonical_json_bytes(
            self._read("witnesses", sha, RewardOpportunityWitness, self.maximum_witness_bytes)
        )

    def retain_completion(self, certificate: RewardOpportunityCertificate, witness_source) -> None:
        """Publish immutable witnesses first; retry a partial export exactly.

        These are discovery inputs, not evidence of payment or authority. The
        original endpoints and proof archive are needed for native replay.
        """
        for contribution in certificate.contributions:
            raw = witness_source(contribution.witness_sha256)
            if type(raw) is not bytes or not 0 < len(raw) <= self.maximum_witness_bytes:
                raise ValueError("completion witness exceeds host byte capacity")
            witness = RewardOpportunityWitness.model_validate_json(raw)
            if (
                canonical_json_bytes(witness) != raw
                or digest(witness) != contribution.witness_sha256
            ):
                raise ValueError("completion witness differs from selected identity")
            publish_private_model(
                self.root / "witnesses" / (digest(witness) + ".json"),
                witness,
                maximum_bytes=self.maximum_witness_bytes,
            )
        publish_private_model(
            self.root / "opportunities" / (digest(certificate) + ".json"),
            certificate,
            maximum_bytes=MAX_CERTIFICATE_BYTES,
        )
