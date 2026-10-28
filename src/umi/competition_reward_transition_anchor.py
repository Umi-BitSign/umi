"""Bounded discovery of immutable, natively retained actual row-write endpoints.

These records are lookup hints, not portable proof receipts. Consumers restore
the selected endpoint through NativeRewardCoverageSource.replay before deriving
live age. Older journals are not scanned or replayed to manufacture an anchor.
"""

from .competition_evidence_codec import checked_digest
from .competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from .competition_reward_coverage_intervals import CoveragePoint, coverage_point
from .competition_reward_decisions import RewardActivation
from .competition_transport_verification import TransferProgress
from .open_competition import digest, identity
from .protocol import canonical_json_bytes


class RewardLiveAnchorMissing(ValueError):
    """No indexed actual row-write; recover one explicit native endpoint."""


def _kind(rule_sha256, activation_sha256):
    return "coverage_live_anchor_" + digest([rule_sha256, activation_sha256])


def _key(point):
    # Fixed-width ordering makes earliest selection one indexed metadata lookup.
    # Equal heights across validators have a stable, arrival-independent order.
    return f"{point.block:016x}:{point.validator_account_id}"


def remember_live_anchor(owner, endpoint, completed):
    """Called only by the coverage owner's successful native retention path."""
    point = coverage_point(endpoint, owner.rule)
    eligibility = getattr(endpoint, "eligibility", None)
    updated = (
        eligibility.subject.validator_last_update
        if eligibility is not None
        else endpoint.validator_last_update
    )
    if (
        not point.covered
        or endpoint.row_matches is not True
        or type(updated) is not int
        or updated != point.block
    ):
        return
    if (
        completed is None
        or completed["owner"] != owner.checkpoints.owner
        or completed["semantics"] != owner.checkpoints.semantics
        or CoveragePoint.model_validate(completed["point"]) != point
        or completed.get("row_state") != {"row_matches": True, "validator_last_update": point.block}
    ):
        raise CoverageCheckpointRepairRequired("live anchor lacks its completed native row-write")
    record = {
        "schema": "umi-reward-live-anchor/1",
        "owner": owner.checkpoints.owner,
        "rule_sha256": owner.rule_sha256,
        "point": point.model_dump(mode="json"),
        "package_sha256": completed["package_sha256"],
        "endpoint_sha256": point.key(),
    }
    owner.journal.put(_kind(owner.rule_sha256, point.activation_sha256), _key(point), record)


def first_live_anchor(owner, activation, *, validators, chain_config_sha256, not_before_block):
    """Return the earliest retained row-write hint, requiring native restoration.

    Each endpoint record is immutable. Out-of-order backfill may reveal an
    earlier fact; a producer must retain its chosen key with its signed intent.
    Missing indexes require an explicit bounded endpoint recovery, never a new
    full-history pass. No package, model or proof payload is read here.
    """
    owner._check_rule()
    activation = RewardActivation.model_validate_json(canonical_json_bytes(activation))
    chain_config_sha256 = checked_digest(chain_config_sha256)
    validators = tuple(validators)
    if not 1 <= len(validators) <= 256 or (
        type(not_before_block) is not int or not 1 <= not_before_block < 2**53
    ):
        raise ValueError("live anchor requires bounded validators and an original block boundary")
    accounts = {identity(key) for key in validators}
    if len(accounts) != len(validators):
        raise ValueError("live anchor validator identities must be distinct")
    kind = _kind(owner.rule_sha256, digest(activation))
    with TransferProgress("reward_live_anchor_lookup", 1, unit="anchors") as progress:
        with owner.journal.read_transaction() as db:
            selected = db.execute(
                "SELECT id FROM records WHERE kind=? AND id>=? ORDER BY id LIMIT 1",
                (kind, f"{not_before_block:016x}:"),
            ).fetchone()
            if selected is None:
                progress.emit("waiting", reason="native_first_live_anchor_missing")
                raise RewardLiveAnchorMissing(
                    "native first-live anchor missing; "
                    "recover one bounded actual row-write endpoint"
                )
            value = owner.journal.get(kind, selected[0], db=db)
        try:
            if type(value) is not dict or set(value) != {
                "schema",
                "owner",
                "rule_sha256",
                "point",
                "package_sha256",
                "endpoint_sha256",
            }:
                raise ValueError("invalid anchor")
            point = CoveragePoint.model_validate(value["point"])
            if (
                value["schema"] != "umi-reward-live-anchor/1"
                or value["owner"] != owner.checkpoints.owner
                or value["rule_sha256"] != owner.rule_sha256
                or value["package_sha256"] != activation.package_sha256
                or value["endpoint_sha256"] != point.key()
                or selected[0] != _key(point)
                or point.series_sha256 != owner.rule.series_sha256
                or point.runtime_profile_sha256 != owner.rule.runtime_profile_sha256
                or point.activation_sha256 != digest(activation)
                or point.allocation_sha256
                != (activation.effective_allocation_sha256 or activation.allocation_sha256)
                or point.chain_config_sha256 != chain_config_sha256
                or point.validator_account_id not in accounts
                or point.block < not_before_block
                or not point.covered
            ):
                raise ValueError("changed anchor domain")
        except (ValueError, KeyError, TypeError) as error:
            raise CoverageCheckpointRepairRequired("native first-live anchor changed") from error
        progress.advance(1, restored=True)
        return point.key()
