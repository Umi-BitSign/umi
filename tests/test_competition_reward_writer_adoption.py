"""Supplemental signed selection preserves native preparation and recovery bindings."""

import hashlib
import json

import pytest

from umi.competition_reward_adoption import RewardAdoptionSelection, SignedRewardModelAdoption
from umi.competition_reward_boot import StandingRewardBootConfig
from umi.competition_reward_writer_adoption import select_writer_adoptions
from umi.competition_reward_writer_selection import (
    WriterHistorySelection,
    _journal_path,
    recover_writer_history_selection,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_bootstrap import bootstrap_case
from .test_competition_reward_decisions import signatures
from .test_competition_reward_writer_selection import (  # noqa: F401
    activation_case,
    anchor_case,
    boot_inputs,
    chain,
    chain_config,
    control,
    explicit,
    installed_case,
    limits,
    package_case,
    package_limits,
    policy,
    prepared,
    release_identity,
    replay_limits,
    series_case,
    staging_case,
    successor_release,
    trusted_ports,
    worker_capacity,
)


def signed_adoptions(config, case):
    bootstrap = bootstrap_case(case)
    body = bootstrap.adoption.adoption.model_copy(
        update={
            "series_sha256": digest(config.series),
            "policy_sha256": digest(config.policy),
            "authority_sha256": digest(config.series.recovery.authority),
            "cohort_sha256": digest(config.series.cohorts[0]),
            "issued_at_block": max(181, config.series.recovery.authority.issued_at_block),
        }
    )
    return RewardAdoptionSelection(
        schema=bootstrap.selection.schema_,
        adoptions=(SignedRewardModelAdoption(adoption=body, signatures=signatures(body)),),
    )


@pytest.fixture
def adopted(prepared, series_case, tmp_path):  # noqa: F811
    c = prepared
    c.adoptions = signed_adoptions(c.config, series_case)
    c.adoption_path = tmp_path / "signed-adoptions.json"
    c.save(c.adoption_path, canonical_json_bytes(c.adoptions))
    return c


def test_authenticated_selection_preserves_old_boot_and_ordinary_adopted_boot(adopted):
    c = adopted
    before = c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes()
    value = select_writer_adoptions(c.config, "current", c.adoption_path)
    assert value.selection == c.adoptions
    value.recheck()
    adopted_boot = StandingRewardBootConfig.model_validate_json(
        canonical_json_bytes(c.config.model_copy(update={"reward_adoptions": value.selection}))
    )
    assert adopted_boot.reward_adoptions == c.adoptions
    assert select_writer_adoptions(adopted_boot, "current").selection == c.adoptions
    assert before == (c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes())


@pytest.mark.parametrize("fault", ["signature", "series", "noncanonical", "digest", "writable"])
def test_bad_input_refuses_before_selection_journal(adopted, fault):
    c = adopted
    raw = c.adoption_path.read_bytes()
    expected = None
    if fault in {"series", "signature"}:
        signed = c.adoptions.adoptions[0]
        body = signed.adoption.model_copy(update={"series_sha256": "ab" * 32})
        changed = SignedRewardModelAdoption(
            adoption=body,
            signatures=signatures(body) if fault == "series" else signed.signatures,
        )
        c.save(
            c.adoption_path,
            canonical_json_bytes(c.adoptions.model_copy(update={"adoptions": (changed,)})),
        )
    elif fault == "noncanonical":
        c.save(c.adoption_path, raw + b"\n")
    elif fault == "digest":
        expected = "00" * 32
    else:
        c.adoption_path.chmod(0o644)
    with pytest.raises(ValueError):
        select_writer_adoptions(c.config, "current", c.adoption_path, expected_sha256=expected)
    assert not _journal_path(c.root, "adopted-v2").exists()


def test_lineage_extension_cannot_drop_or_replace_retained_signature(adopted):
    c = adopted
    retained = c.config.model_copy(update={"reward_adoptions": c.adoptions})
    first = c.adoptions.adoptions[0]
    body = first.adoption.model_copy(
        update={
            "revision": 2,
            "predecessor_adoption_sha256": digest(first.adoption),
            "issued_at_block": first.adoption.issued_at_block + 1,
        }
    )
    second = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    extended = c.adoptions.model_copy(update={"adoptions": (first, second)})
    c.save(c.adoption_path, canonical_json_bytes(extended))
    assert select_writer_adoptions(retained, "current", c.adoption_path).selection == extended
    c.save(c.adoption_path, canonical_json_bytes(c.adoptions))
    with pytest.raises(ValueError, match="retained signed lineage"):
        select_writer_adoptions(
            c.config.model_copy(update={"reward_adoptions": extended}), "current", c.adoption_path
        )
    changed = first.adoption.model_copy(update={"effective_allocation_sha256": "aa" * 32})
    c.save(
        c.adoption_path,
        canonical_json_bytes(
            c.adoptions.model_copy(
                update={
                    "adoptions": (
                        SignedRewardModelAdoption(adoption=changed, signatures=signatures(changed)),
                    )
                }
            )
        ),
    )
    with pytest.raises(ValueError, match="retained signed lineage"):
        select_writer_adoptions(retained, "current", c.adoption_path)


@pytest.mark.parametrize("committed", [False, True])
def test_restart_binds_exact_supplemental_bytes_and_keeps_historical_schema(adopted, committed):
    c = adopted
    before = c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes()
    original_inode = c.original.stat().st_ino
    with c.open() as lease:
        operation = WriterHistorySelection(
            lease, operation="adopted-v2", reward_adoptions=c.adoption_path
        )
        operation.exchange()
        if committed:
            operation.commit()
    journal = _journal_path(c.root, "adopted-v2")
    value = json.loads(journal.read_bytes())
    assert value["schema"] == "umi-writer-history-selection/2"
    assert value["reward_adoptions"] == {
        "path": str(c.adoption_path),
        "raw_sha256": hashlib.sha256(c.adoption_path.read_bytes()).hexdigest(),
    }

    def recover(path):
        return recover_writer_history_selection(
            c.anchor,
            standing_boot=c.boot,
            approval_path=c.path,
            operation="adopted-v2",
            reward_adoptions=path,
        )

    inode = c.original.stat().st_ino
    with pytest.raises(ValueError, match="adoption changed or is missing"):
        recover(None)
    duplicate = c.adoption_path.with_name("other-adoptions.json")
    c.save(duplicate, c.adoption_path.read_bytes())
    with pytest.raises(ValueError, match="adoption changed or is missing"):
        recover(duplicate)
    assert c.original.stat().st_ino == inode
    assert recover(c.adoption_path) == ("committed" if committed else "rolled_back")
    assert recover(c.adoption_path) == ("committed" if committed else "rolled_back")
    assert (c.original.stat().st_ino == original_inode) is not committed
    assert before == (c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes())


def test_control_mutation_detected_during_live_selection(adopted):
    c = adopted
    with c.open() as lease:
        operation = WriterHistorySelection(
            lease, operation="adopted-v2", reward_adoptions=c.adoption_path
        )
        c.save(c.adoption_path, c.adoption_path.read_bytes())
        with pytest.raises(ValueError, match="adoption control changed"):
            operation.recheck()
    # The same exact root-selected bytes can be deliberately restored/reselected
    # on process restart, while the live inode/ctime watch rejects replacement.
    assert (
        recover_writer_history_selection(
            c.anchor,
            standing_boot=c.boot,
            approval_path=c.path,
            operation="adopted-v2",
            reward_adoptions=c.adoption_path,
        )
        == "rolled_back"
    )


def test_historical_selection_cannot_gain_new_adoption_during_recovery(adopted):
    c = adopted
    with c.open() as lease:
        operation = WriterHistorySelection(lease, operation="historical-v1")
        operation.exchange()
        operation.commit()
    value = json.loads(_journal_path(c.root, "historical-v1").read_bytes())
    assert value["schema"] == "umi-writer-history-selection/1"
    assert "reward_adoptions" not in value
    inode = c.original.stat().st_ino
    with pytest.raises(ValueError, match="adoption changed or is missing"):
        recover_writer_history_selection(
            c.anchor,
            standing_boot=c.boot,
            approval_path=c.path,
            operation="historical-v1",
            reward_adoptions=c.adoption_path,
        )
    assert c.original.stat().st_ino == inode
    assert (
        recover_writer_history_selection(
            c.anchor, standing_boot=c.boot, approval_path=c.path, operation="historical-v1"
        )
        == "committed"
    )


def test_valid_new_signed_bytes_cannot_rebind_committed_operation(adopted):
    c = adopted
    with c.open() as lease:
        operation = WriterHistorySelection(
            lease, operation="adopted-v2", reward_adoptions=c.adoption_path
        )
        operation.exchange()
        operation.commit()
    old = c.adoption_path.read_bytes()
    first = c.adoptions.adoptions[0]
    body = first.adoption.model_copy(update={"effective_allocation_sha256": "ab" * 32})
    replacement = c.adoptions.model_copy(
        update={
            "adoptions": (SignedRewardModelAdoption(adoption=body, signatures=signatures(body)),)
        }
    )
    c.save(c.adoption_path, canonical_json_bytes(replacement))
    inode = c.original.stat().st_ino
    with pytest.raises(ValueError, match="adoption changed or is missing"):
        recover_writer_history_selection(
            c.anchor,
            standing_boot=c.boot,
            approval_path=c.path,
            operation="adopted-v2",
            reward_adoptions=c.adoption_path,
        )
    assert c.original.stat().st_ino == inode
    c.save(c.adoption_path, old)
    assert (
        recover_writer_history_selection(
            c.anchor,
            standing_boot=c.boot,
            approval_path=c.path,
            operation="adopted-v2",
            reward_adoptions=c.adoption_path,
        )
        == "committed"
    )


def test_successor_and_predecessor_select_their_own_signed_lineage(boot_inputs, monkeypatch):  # noqa: F811
    import os

    from umi import competition_reward_history_preparation as preparation

    from .test_competition_reward_adoption_boot import selected_adoption
    from .test_competition_reward_boot import successor_boot

    monkeypatch.setattr(preparation, "_root_owner_uid", os.getuid)
    candidate, _ = successor_boot(boot_inputs)
    config = StandingRewardBootConfig.model_validate_json(canonical_json_bytes(candidate))
    path = boot_inputs.path.with_name("successor-adoptions.json")
    current = selected_adoption(config)
    boot_inputs.save(path, canonical_json_bytes(current))
    assert select_writer_adoptions(config, "current", path).selection == current
    with pytest.raises(ValueError, match="selected standing authority"):
        select_writer_adoptions(config, "predecessor", path)
    prior = selected_adoption(config, series=config.predecessor_series)
    boot_inputs.save(path, canonical_json_bytes(prior))
    assert select_writer_adoptions(config, "predecessor", path).selection == prior
    with pytest.raises(ValueError, match="selected standing authority"):
        select_writer_adoptions(config, "current", path)
