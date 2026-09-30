"""Proportional public-model rewards from retained native benchmark evidence."""

import shutil
from fractions import Fraction

import pytest

from umi.competition_cohort_model_award import PendingModelAward, ProportionalModelAward
from umi.competition_cohort_reward_allocation import (
    build_reward_allocation,
    retain_reward_allocation,
)
from umi.competition_cohort_reward_certification import replay_reward_allocation
from umi.competition_round_journal import RoundJournal
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_model_award import award, service_boundary
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import model_case as model_case
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_quality import reviewer
from .test_competition_cohort_recovery import signatures
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize(
    "receipt_scenario", ["proportional-model-awards"], indirect=True
)


def allocate(case, decision=None):
    sr, service = service_boundary(case, 5000)
    return build_reward_allocation(
        service,
        sr,
        case[2],
        case[1],
        None,
        model_award=award(case) if decision is None else decision,
    )


@pytest.mark.parametrize("model_case", [("proportional", 2)], indirect=True)
def test_all_eligible_models_receive_score_proportional_shares(model_case):
    decision = award(model_case)
    assert isinstance(decision, ProportionalModelAward)
    assert len(decision.credits) == 2
    scores = {
        c.recipient_hotkey: Fraction(int(c.score.numerator), int(c.score.denominator))
        for c in decision.credits
    }
    assert (
        0 < scores[wallet("Alice").hotkey.ss58_address] < scores[wallet("Bob").hotkey.ss58_address]
    )
    result = allocate(model_case, decision)
    assert result.schema_ == "umi-cohort-reward-allocation/3"
    assert len(result.recipients) == 2
    assert result.burn_weight == 32767
    assert sum(r.raw_weight for r in result.recipients) == 32768
    for recipient in result.recipients:
        ideal = 32768 * scores[recipient.hotkey] / sum(scores.values())
        assert abs(recipient.raw_weight - ideal) < 1
    # Later replay cannot change scores or reassign the pool.
    assert canonical_json_bytes(
        award(model_case, review=reviewer(model_case[0], current_block=2**53 - 1))
    ) == canonical_json_bytes(decision)


@pytest.mark.parametrize("model_case", [("equal", 2)], indirect=True)
def test_aliases_keep_one_content_share_and_original_complete_recipient(model_case):
    decision = award(model_case)
    assert len(decision.candidates) == 2 and len(decision.credits) == 1
    first = min(decision.acceptances, key=lambda a: a.acceptance.accepted_ordinal).acceptance
    assert decision.credits[0].recipient_hotkey == first.recipient_hotkey
    result = allocate(model_case, decision)
    assert len(result.recipients) == 1
    assert result.recipients[0].raw_weight == 32768
    assert result.recipients[0].hotkey == first.recipient_hotkey


@pytest.mark.parametrize(
    "model_case", [("baseline", 1), ("zero", 1), ("distinct-zero", 2), ("below", 1)], indirect=True
)
def test_equality_zero_total_and_no_eligible_model(model_case):
    decision = award(model_case)
    result = allocate(model_case, decision)
    if not decision.credits:
        assert result.recipients == () and result.burn_weight == 65535
    else:
        assert len(result.recipients) == len(decision.credits)
        assert all(r.raw_weight == 32768 // len(decision.credits) for r in result.recipients)
        assert result.burn_weight == 32767


@pytest.mark.parametrize("model_case", [("proportional", 2)], indirect=True)
def test_slow_competitor_cannot_be_omitted(model_case):
    with pytest.raises(PendingModelAward, match="entire sealed"):
        award(model_case, acceptances=model_case[3][:1])


@pytest.mark.parametrize("model_case", [("duplicate-disagree", 2)], indirect=True)
def test_duplicate_content_cannot_obtain_different_scores(model_case):
    with pytest.raises(PendingModelAward, match="inconsistent quality"):
        award(model_case)


@pytest.mark.parametrize("model_case", [("proportional", 2)], indirect=True)
def test_model_reward_adds_to_same_hotkeys_service_reward(model_case):
    from umi.competition_cohort_service_allocation import ServiceRecipientAmount

    sr, certificate = service_boundary(model_case, 5000)
    paid = certificate.statement.allocation.model_copy(
        update={
            "recipients": (
                ServiceRecipientAmount(hotkey=wallet("Alice").hotkey.ss58_address, raw_weight=100),
            ),
            "burn_weight": 32667,
        }
    )
    sr.statement = certificate.statement.model_copy(update={"allocation": paid})
    certificate = certificate.model_copy(
        update={"statement": sr.statement, "signatures": signatures(sr.statement)}
    )
    original = allocate(model_case)
    combined = build_reward_allocation(
        certificate, sr, model_case[2], model_case[1], None, model_award=award(model_case)
    )
    expected = {r.hotkey: r.raw_weight for r in original.recipients}
    expected[wallet("Alice").hotkey.ss58_address] += 100
    assert {r.hotkey: r.raw_weight for r in combined.recipients} == expected
    assert combined.burn_weight == original.burn_weight - 100


@pytest.mark.parametrize("model_case", [("proportional", 2)], indirect=True)
def test_restart_replays_exact_award_and_rejects_altered_scores(model_case, tmp_path, monkeypatch):
    b, br, benchmark, accepted, archive = model_case
    sr, service = service_boundary(model_case, 5000)
    store = CompetitionStore(tmp_path / "native-model-store", b["policy"])
    shutil.copytree(archive, store.directory / "model-reward-artifacts")
    paths = []
    for receipt in accepted:
        path = (
            store.directory
            / "model-reward-acceptances"
            / digest(b["history"].plan)
            / (receipt.acceptance.submission_sha256 + ".json")
        )
        publish_private_model(path, receipt)
        paths.append(path)
    root, binding = tmp_path / "owner", {"scope": "proportional-model-test"}
    owner = RoundJournal(root, binding)
    put = owner.put

    def retain(journal):
        return retain_reward_allocation(
            journal, store, service, sr, benchmark, br, maximum_promotion_bytes=1_000_000
        )

    def lose_reply(kind, key, value):
        put(kind, key, value)
        if kind == "cohort_reward_allocation":
            raise OSError("lost allocation reply")

    with monkeypatch.context() as patch:
        patch.setattr(owner, "put", lose_reply)
        with pytest.raises(OSError, match="lost allocation reply"):
            retain(owner)
    saved = owner.get("cohort_reward_allocation", sr.slot)
    for path in paths:
        path.unlink()
    result = retain(RoundJournal(root, binding))
    assert canonical_json_bytes(result) == canonical_json_bytes(saved)

    def replay(value):
        return replay_reward_allocation(
            value, store, service, sr, benchmark, br, maximum_promotion_bytes=1_000_000
        )

    assert replay(result) == result
    credits = result.model_award.credits
    for changes in (
        {"score": credits[0].score.model_copy(update={"numerator": "0"})},
        {"recipient_hotkey": wallet("Eve").hotkey.ss58_address},
    ):
        changed_award = result.model_award.model_copy(
            update={"credits": (credits[0].model_copy(update=changes), *credits[1:])}
        )
        with pytest.raises(ValueError, match="independently replayed"):
            replay(result.model_copy(update={"model_award": changed_award}))
    with pytest.raises(ValueError, match="version differs"):
        replay(result.model_copy(update={"schema_": "umi-cohort-reward-allocation/2"}))
