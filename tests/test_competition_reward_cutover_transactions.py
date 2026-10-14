"""Native signed-byte/journal fixtures with an explicit archived-proof replay port."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_cutover as cutover
from umi.competition_reward_signing import RewardDecisionSigner
from umi.open_competition import digest
from umi.signed_extrinsic import encode_mortal_call

from .test_competition_reward_control_publisher import chain as chain
from .test_competition_reward_control_publisher import chain_config as chain_config
from .test_competition_reward_control_publisher import control as control
from .test_competition_reward_control_publisher import native_encoding as native_encoding
from .test_competition_reward_control_publisher import policy as policy
from .test_competition_reward_control_publisher import publisher_case as publisher_case
from .test_competition_reward_control_publisher import series_case as series_case
from .test_competition_reward_signing import signing_case as signing_case
from .test_open_competition import wallet


async def test_all_local_intents_votes_and_certificates_remain_exact(signing_case):
    c = signing_case
    journal = c.signing_journal()
    signer = RewardDecisionSigner(journal, c.sign)
    await signer.attest(c.review())
    before = journal.journal.path.read_bytes()
    prefix, intents = cutover.retained_decisions(journal)
    assert prefix == () and intents == (journal.load(0),)
    assert journal.journal.path.read_bytes() == before
    # Imported prior certificates need not have been locally voted, while every
    # retained vote still needs its original intent.
    first = c.decision(c.genesis, 5, observed=162)
    await signer.attest(c.review(first.decision, (c.genesis,)))
    prefix, intents = cutover.retained_decisions(journal)
    assert prefix == (c.genesis,) and len(intents) == 2
    action, reserved, finalized = cutover._decision(
        first.decision.activation.cohort_sha256, prefix, intents, (c.genesis,), "absent"
    )
    assert action == "preserve_reserved_activation_before_native_revision"
    assert reserved == (digest(first.decision),) and not finalized
    # Preserve data on an orphan-vote fault; never delete to make the review pass.
    journal.journal.put("reward_vote", "a0" * 32, {"untrusted_orphan": True})
    with pytest.raises(ValueError, match="orphan"):
        cutover.retained_decisions(journal)
    assert journal.journal.get("reward_vote", "a0" * 32) == {"untrusted_orphan": True}


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("fence", ["live", "era", "nonce"])
async def test_original_pending_proofs_and_bytes_checked_even_when_expired(
    publisher_case,
    monkeypatch,
    signed,
    fence,
):
    h = publisher_case
    journal, original = h.publisher.journal, h.current
    pending = journal.reserve(h.c.genesis, original, mortality_period=128)
    if signed:
        raw = encode_mortal_call(
            pending.intent.call(),
            runtime=original.runtime,
            signer=wallet("Ferdie").hotkey,
            validator_hotkey=h.c.series.control_hotkey,
            nonce=original.nonce,
            mortality_period=128,
            genesis_hash="0x" + h.c.series.genesis_hash,
        )
        pending = journal.retain_signed(pending.intent, raw, original)
    archived = []

    async def review(provider, **kwargs):
        assert provider is h.item.provider
        assert kwargs["control_evidence"] == original.control.evidence
        assert kwargs["nonce_evidence"] == original.nonce_evidence
        assert kwargs["metadata"] == original.runtime.metadata_bytes
        archived.append(kwargs)
        return original

    monkeypatch.setattr(cutover, "review_control_signing_state", review)
    owner = SimpleNamespace(
        provider=h.item.provider,
        transactions=journal,
        config=SimpleNamespace(series=h.c.series, policy=h.item.policy, reward_adoptions=None),
    )
    await cutover.NativeRewardCutoverReview._recover(owner, pending, (h.c.genesis,))
    assert len(archived) == 1
    if signed:
        damaged = replace(pending, signed=pending.signed.model_copy(update={"encoded": "00"}))
        with pytest.raises(ValueError):
            await cutover.NativeRewardCutoverReview._recover(owner, damaged, (h.c.genesis,))
    current = h.state(block=378 if fence == "era" else 250, nonce=5 if fence == "nonce" else 4)
    result = cutover._pending_status(pending, current, SimpleNamespace(writes=()))
    assert result == (
        "live_original_attempt" if fence == "live" else "era_or_nonce_fenced_outcome_unknown"
    )
    if fence != "live":
        assert (
            cutover._pending_status(
                pending,
                current,
                SimpleNamespace(
                    writes=(SimpleNamespace(decision_sha256=digest(h.c.genesis.decision)),)
                ),
            )
            == "decision_present_in_verified_ordered_history"
        )
    assert journal.pending() == pending and not h.signs and not h.sends
    with pytest.raises(ValueError, match="rolled back"):
        cutover._pending_status(pending, h.state(nonce=3), SimpleNamespace(writes=()))
    with pytest.raises(ValueError, match="certified prefix"):
        await cutover.NativeRewardCutoverReview._recover(owner, pending, ())


async def test_bad_original_archive_never_bypassed_after_expiry(publisher_case, monkeypatch):
    h = publisher_case
    pending = h.publisher.journal.reserve(h.c.genesis, h.current, mortality_period=128)

    async def fail(*args, **kwargs):
        raise ValueError("archive native proof failed")

    monkeypatch.setattr(cutover, "review_control_signing_state", fail)
    owner = SimpleNamespace(
        provider=h.item.provider,
        transactions=h.publisher.journal,
        config=SimpleNamespace(series=h.c.series, policy=h.item.policy, reward_adoptions=None),
    )
    assert cutover._pending_status(pending, h.state(block=378), SimpleNamespace(writes=())) == (
        "era_or_nonce_fenced_outcome_unknown"
    )
    with pytest.raises(ValueError, match="proof failed"):
        await cutover.NativeRewardCutoverReview._recover(owner, pending, (h.c.genesis,))
    assert h.publisher.journal.pending() == pending
