"""Registration-bound funding assertions carried inside a signed bridge policy.

This is an explicitly temporary shared-sender cap, not proof of human identity
or of the source of a registration fee. Unknown histories add no funding edge.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .encoding import account_id32
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .registration_funding_audit import TRANSFER_URL, FundingRoster, _address

UInt = Annotated[int, Field(ge=0, le=2**53 - 1)]


class FundingBinding(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: str
    coldkey: str
    registered_at_block: UInt
    funder: str
    history_sha256: Hex32

    @field_validator("hotkey", "coldkey", "funder")
    @classmethod
    def address(cls, value):
        if _address(value) != value:
            raise ValueError("noncanonical funding address")
        return value

    @model_validator(mode="after")
    def not_self(self):
        if self.funder == self.coldkey:
            raise ValueError("self funding cannot link owners")
        return self


class FundingSnapshot(StrictProtocolModel):
    schema_: Literal["umi-registration-funding-snapshot/1"] = Field(alias="schema")
    source: Literal[TRANSFER_URL]
    rule: Literal["single_recorded_pre_registration_sender/1"]
    report_sha256: Hex32
    finalized_block: Annotated[int, Field(gt=0, le=2**53 - 1)]
    finalized_block_hash: BlockHash
    bindings: Annotated[list[FundingBinding], Field(max_length=256)]
    shared_funders_excluded: Annotated[list[str], Field(max_length=256)]

    @model_validator(mode="after")
    def consistent(self):
        uids = [b.uid for b in self.bindings]
        if uids != sorted(set(uids)):
            raise ValueError("funding bindings must be unique and ordered")
        excluded = self.shared_funders_excluded
        if excluded != sorted({_address(a) for a in excluded}):
            raise ValueError("funding exclusions must be canonical and ordered")
        owners = {}
        for binding in self.bindings:
            if binding.registered_at_block > self.finalized_block:
                raise ValueError("future funding registration")
            if binding.funder in excluded:
                raise ValueError("excluded shared service in funding bindings")
            previous = owners.setdefault(binding.coldkey, binding.funder)
            if previous != binding.funder:
                raise ValueError("conflicting funders for one owner")
        return self


def snapshot_from_report(report: dict) -> FundingSnapshot:
    """Recompute assertions from the completed histories, not candidate_groups.

    The coordinator signs the resulting policy; validators need neither an API
    secret nor permission to trust an unsigned report that can change later.
    """
    if (
        report.get("schema") != "umi-registration-funding-audit/1"
        or report.get("source") != TRANSFER_URL
    ):
        raise ValueError("unsupported funding report")
    roster = FundingRoster.model_validate(report["roster"])
    excluded = sorted({_address(a) for a in report["shared_funders_excluded"]})
    histories = report["histories"]
    if not isinstance(histories, list) or len(histories) > 256:
        raise ValueError("invalid funding histories")
    owners = defaultdict(list)
    for p in roster.participants:
        owners[p.coldkey].append(p)
    bindings, seen = [], set()
    for history in histories:
        owner = _address(history["coldkey"])
        if owner in seen or owner not in owners:
            raise ValueError("duplicate or unknown funding owner")
        seen.add(owner)
        registrations = owners[owner]
        before = min(p.registered_at_block for p in registrations)
        if history["before_registration_block"] != before or sorted(history["uids"]) != sorted(
            p.uid for p in registrations
        ):
            raise ValueError("funding query does not bind registrations")
        if history["status"] != "single_recorded_sender":
            continue
        transfers, pages = history["transfers"], history["page_sha256"]
        if not isinstance(transfers, list) or not 1 <= len(transfers) <= 2000:
            raise ValueError("invalid complete funding history")
        if not isinstance(pages, list) or not 1 <= len(pages) <= 10:
            raise ValueError("missing funding source pages")
        if any(
            not isinstance(p, str) or len(p) != 64 or any(c not in "0123456789abcdef" for c in p)
            for p in pages
        ):
            raise ValueError("invalid funding page digest")
        senders, identities = set(), set()
        for transfer in transfers:
            sender, receiver = _address(transfer["from"]), _address(transfer["to"])
            block, amount = transfer["block_number"], transfer["amount_rao"]
            if receiver != owner or type(block) is not int or not 0 <= block < before:
                raise ValueError("transfer outside registration query")
            if (
                not isinstance(amount, str)
                or not amount.isascii()
                or not amount.isdecimal()
                or not 0 < int(amount) < 2**128
            ):
                raise ValueError("invalid funding amount")
            identity = transfer["id"]
            if (
                not isinstance(identity, str)
                or not identity.startswith(f"finney-{block}-")
                or identity in identities
            ):
                raise ValueError("duplicate or invalid funding event")
            identities.add(identity)
            if sender != owner:
                senders.add(sender)
        if (
            len(senders) != 1
            or sorted(senders) != history["recorded_senders"]
            or history["candidate_funder"] not in senders
        ):
            raise ValueError("funding sender assertion disagrees with history")
        funder = next(iter(senders))
        if funder in excluded:
            continue
        digest = hashlib.sha256(canonical_json_bytes(history)).hexdigest()
        bindings.extend(
            FundingBinding(
                uid=p.uid,
                hotkey=p.hotkey,
                coldkey=p.coldkey,
                registered_at_block=p.registered_at_block,
                funder=funder,
                history_sha256=digest,
            )
            for p in registrations
        )
    return FundingSnapshot(
        schema="umi-registration-funding-snapshot/1",
        source=TRANSFER_URL,
        rule="single_recorded_pre_registration_sender/1",
        report_sha256=hashlib.sha256(canonical_json_bytes(report)).hexdigest(),
        finalized_block=roster.finalized_block,
        finalized_block_hash=roster.finalized_block_hash,
        bindings=sorted(bindings, key=lambda b: b.uid),
        shared_funders_excluded=excluded,
    )


def matching_funders(snapshot: FundingSnapshot, participants) -> dict[int, bytes]:
    """A recycled UID or changed owner gets no stale funding assertion."""
    current = {p.uid: p for p in participants}
    result = {}
    for binding in snapshot.bindings:
        p = current.get(binding.uid)
        if p is not None and (
            account_id32(p.hotkey),
            account_id32(p.coldkey),
            p.registered_at_block,
        ) == (
            account_id32(binding.hotkey),
            account_id32(binding.coldkey),
            binding.registered_at_block,
        ):
            result[p.uid] = account_id32(binding.funder)
    return result
