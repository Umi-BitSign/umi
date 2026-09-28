"""Private original source publications for recurring settlement tests.

The historical consent fixture is seeded into an intake owner's ledger. Export,
assembly, replay, signing and delivery run through their native implementations.
Registration proofs and original inference remain the parent fixture's fake ports.
"""

from pathlib import Path

from umi.competition_cohort_intake import CohortIntake, CohortIntakeConfig
from umi.competition_cohort_intake_records import read_participation
from umi.competition_cohort_preparation import PreparedCohortRound
from umi.competition_cohort_settlement_config import SettlementOriginalSources
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.competition_settlement import PromotionHeadBinding
from umi.open_competition import digest, identity
from umi.policy import scoring_policy_hash
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_execution import boundary
from .test_drand import pulse_record


def select_original_sources(root, history):
    return SettlementOriginalSources(
        intake=CohortIntakeConfig(
            directory=str(root / "intake"),
            cohorts=(
                {
                    "cohort_sha256": digest(history.plan),
                    "authority_sha256": digest(history.authority.authority),
                },
            ),
        ),
        eligible_tracks=("endpoint",),
        **{
            key: str(root / key)
            for key in (
                "round_directory",
                "objects_directory",
                "catalogs_directory",
                "transport_directory",
                "pulses_directory",
            )
        },
    )


def publish_original_intake(config, b):
    history, policy = b["history"], b["policy"]
    cohort = digest(history.plan)
    intake = CohortIntake(config, policy, initialize=True)
    with intake._connection() as (db, store):
        store.admit(
            history.plan,
            history.authority,
            policy,
            admitted_at_block=history.genesis.admitted_at_block,
        )
        for d in b["decisions"].values():
            store.retain_source(cohort, d)
        store.publish_history(history, policy, current_block=1000000)
        for key, raw in b["records"]:
            r = read_participation(raw)
            sub, a = r.request.signed_submission.submission, r.proposed_admission
            db.execute(
                "INSERT INTO cohort_consents VALUES (?,?,?,?,?,?,?,?)",
                (
                    key,
                    cohort,
                    identity(sub.hotkey),
                    sub.track,
                    sub.sequence,
                    r.observation.block,
                    a.recovery_tip_sha256,
                    raw,
                ),
            )
        seal = b["roster"].intake_seal
        db.execute(
            "INSERT INTO cohort_intake_seals VALUES (?,?,?)",
            (cohort, seal.recovery_tip_sha256, canonical_json_bytes(seal)),
        )
    return intake


def publish_original_sources(sources, b, *, intake=None):
    native_requests = intake is not None
    intake = intake or publish_original_intake(sources.intake, b)
    cohort = digest(b["history"].plan)
    objects = SettlementEvidenceFiles(Path(sources.objects_directory))
    values = dict(b["objects"])
    c = b["service_case"]
    for v in (b["closure"], b["reveal"], b["suite"], b["transport"], c.terms):
        values[digest(v)] = canonical_json_bytes(v)
    if native_requests:
        # These must be built and delivered by the request/settlement owners.
        for v in (b["closure"], b["reveal"]):
            values.pop(digest(v), None)
    for key in values:
        objects.publish(key, values.__getitem__)
    prepared = PreparedCohortRound(
        schema="umi-prepared-cohort-round/1",
        roster=b["roster"],
        promotion_head=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="a1" * 32,
            model_sha256=b["roster"].round.incumbent_model_sha256,
            contributor_hotkey=None,
        ),
        observation=boundary(b["roster"].round.prepared_at_block),
    )
    publish_private_model(Path(sources.round_directory) / (cohort + ".json"), prepared)
    catalog = c.assignment.catalog
    publish_private_model(
        Path(sources.catalogs_directory) / (digest(catalog.catalog) + ".json"), catalog
    )
    pulse = RetainedRevealPulse(**pulse_record())
    publish_private_model(Path(sources.pulses_directory) / (str(pulse.round) + ".json"), pulse)
    publish_private_model(
        Path(sources.transport_directory) / (scoring_policy_hash(b["transport"]) + ".json"),
        b["transport"],
    )
    return intake
