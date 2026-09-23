from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as host
from umi.competition_evidence_continuity import (
    audit_continuity_transitions,
    record_continuity_transition,
)
from umi.competition_history_compatibility import original_consent_digest, transition_target_consent
from umi.competition_reward_continuity import UNTIL_SUPERSEDED_BLOCK
from umi.competition_supervisor import SuccessorSupervisorOperatorConsent

from .test_competition_history_compatibility import (
    package_case as package_case,
)
from .test_competition_history_compatibility import (
    package_limits as package_limits,
)
from .test_competition_history_compatibility import (
    policy as policy,
)
from .test_competition_history_compatibility import (
    release_identity as release_identity,
)
from .test_competition_history_compatibility import (
    replay_limits as replay_limits,
)
from .test_competition_history_compatibility import (
    sign,
)
from .test_competition_history_compatibility import (
    successor_case as successor_case,
)
from .test_competition_history_compatibility import (
    successor_chain as successor_chain,
)
from .test_competition_history_compatibility import (
    successor_release as successor_release,
)
from .test_competition_history_compatibility import (
    transition as transition,
)
from .test_competition_history_compatibility import (
    v3_predecessor as v3_predecessor,
)


@pytest.fixture
def handoff(transition, monkeypatch):
    t = transition
    original = t.case.consent.model_copy(
        update={
            "reward_continuity_sha256": "0f" * 32,
            "valid_through_block": UNTIL_SUPERSEDED_BLOCK,
        }
    )
    target = transition_target_consent(t.consent).model_copy(
        update={
            "reward_continuity_sha256": "0e" * 32,
            "valid_through_block": UNTIL_SUPERSEDED_BLOCK,
        }
    )
    grant = t.body.model_copy(
        update={
            "original_consent_sha256": original_consent_digest(original),
            "target_consent_sha256": original_consent_digest(target),
        }
    )
    consent = SuccessorSupervisorOperatorConsent.model_validate(
        {
            **target.model_dump(by_alias=True),
            "schema": "umi-validator-supervisor-operator-consent/2",
            "historical_consent": original,
            "history_compatibility": sign(grant),
        }
    )

    class Active:
        checks = 0
        fail_at = None

        def recheck(self):
            self.checks += 1
            if self.checks == self.fail_at:
                raise ValueError("fixture activation expired")

    # Explicit host capability test port. The quorum, digest, scope checks and
    # SQLite transaction are real; this test cannot authorize a live worker.
    monkeypatch.setattr(host, "AuthenticatedSuccessorActivation", Active)
    active = Active()
    active._inputs = SimpleNamespace(
        operator_consent=consent,
        config=t.config,
        _receipt=SimpleNamespace(evidence_migration=object()),
        receipt_sha256="ac" * 32,
    )
    active.signed_directive = t.signed
    active.directive_sha256 = t.signed.directive_sha256
    active.package_sha256 = t.signed.directive.replay_package.package_sha256
    before = ("0f" * 32, grant.first_round_sequence - 1, "a0" * 32, "a1" * 32)
    after = ("0e" * 32, grant.first_round_sequence, active.package_sha256, "a2" * 32)
    return SimpleNamespace(
        activation=active, policy=grant.forward_policy_sha256s[0], before=before, after=after
    )


def write(db, case, **updates):
    record_continuity_transition(db, **(vars(case) | updates))


def test_previous_authority_and_allocation_are_retained(handoff):
    with sqlite3.connect(":memory:") as db:
        db.execute("BEGIN")
        write(db, handoff)
        raw = db.execute("SELECT body FROM weight_proof_continuity_transitions").fetchone()[0]
        assert handoff.before[0].encode() in raw and handoff.before[2].encode() in raw
        audit_continuity_transitions(db)
        with pytest.raises(sqlite3.IntegrityError):
            write(db, handoff)
        assert (
            db.execute("SELECT count(*) FROM weight_proof_continuity_transitions").fetchone()[0]
            == 1
        )


@pytest.mark.parametrize(
    "fault", ["authority", "old_authority", "round", "policy", "package", "expired", "missing_seal"]
)
def test_unauthorized_or_rollback_handoff_is_rejected(handoff, fault):
    h = handoff
    updates = {}
    if fault == "authority":
        updates["after"] = ("ff" * 32, *h.after[1:])
    elif fault == "old_authority":
        updates["before"] = ("ff" * 32, *h.before[1:])
    elif fault == "round":
        updates["after"] = (h.after[0], h.before[1], *h.after[2:])
    elif fault == "policy":
        updates["policy"] = "ff" * 32
    elif fault == "package":
        updates["after"] = (*h.after[:2], "ff" * 32, h.after[3])
    elif fault == "expired":
        h.activation.fail_at = 1
    else:
        h.activation._inputs._receipt.evidence_migration = None
    with sqlite3.connect(":memory:") as db:
        db.execute("BEGIN")
        with pytest.raises(ValueError):
            write(db, h, **updates)
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='weight_proof_continuity_transitions'"
        ).fetchone()


def test_failed_postwrite_recheck_rolls_back_handoff(handoff):
    handoff.activation.fail_at = 2
    db = sqlite3.connect(":memory:")
    try:
        with pytest.raises(ValueError, match="expired"), db:
            db.execute("BEGIN")
            write(db, handoff)
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='weight_proof_continuity_transitions'"
        ).fetchone()
    finally:
        db.close()


def test_changed_retained_transition_detected(handoff):
    with sqlite3.connect(":memory:") as db:
        db.execute("BEGIN")
        write(db, handoff)
        db.execute("UPDATE weight_proof_continuity_transitions SET body=?", (b"{}",))
        with pytest.raises(ValueError, match="checksum"):
            audit_continuity_transitions(db)
