"""Read-only registration funding candidates from Taostats transfer history.

No wallet files, signing, validator control, or reward-policy mutation. A shared
sender is a review candidate, not proof that recipients have the same operator.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import httpx
from pydantic import Field, field_validator, model_validator

from .encoding import account_id32
from .protocol import BlockHash, StrictProtocolModel, canonical_json_bytes

TRANSFER_URL = "https://api.taostats.io/api/transfer/v1"
PAGE_SIZE = 200
MAX_PAGE_BYTES = 2 * 1024**2
MAX_PAGES = 10
REQUEST_INTERVAL_SECONDS = 12.5  # At most five starts per rolling minute.
UInt = Annotated[int, Field(ge=0, le=2**53 - 1)]


def _address(value: str) -> str:
    import bittensor as bt

    return bt.sp_core.Keypair(public_key=account_id32(value)).ss58_address


class FundingRegistration(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: str
    coldkey: str
    registered_at_block: UInt
    validator_permit: bool

    @field_validator("hotkey", "coldkey")
    @classmethod
    def address(cls, value):
        return _address(value)


class FundingRoster(StrictProtocolModel):
    finalized_block: Annotated[int, Field(gt=0, le=2**53 - 1)]
    finalized_block_hash: BlockHash
    participants: Annotated[list[FundingRegistration], Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def consistent(self):
        if len({p.uid for p in self.participants}) != len(self.participants):
            raise ValueError("duplicate UID in roster")
        if len({p.hotkey for p in self.participants}) != len(self.participants):
            raise ValueError("duplicate hotkey in roster")
        if any(p.registered_at_block > self.finalized_block for p in self.participants):
            raise ValueError("registration is later than the roster block")
        return self


class FundingAuditError(ValueError):
    pass


class APIAccessError(FundingAuditError):
    pass


@dataclass(frozen=True)
class TransferHistory:
    status: str
    transfers: tuple[dict, ...] = ()
    page_sha256: tuple[str, ...] = ()


def _uint(value, maximum=2**53 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise FundingAuditError("invalid_integer")
    return value


def _transfer(value, *, recipient, before_block):
    if not isinstance(value, dict) or value.get("network") != "finney":
        raise FundingAuditError("invalid_transfer_network")
    sender, receiver = _address(value["from"]["ss58"]), _address(value["to"]["ss58"])
    block = _uint(value["block_number"])
    amount = value["amount"]
    if (
        receiver != recipient
        or block >= before_block
        or not isinstance(amount, str)
        or not re.fullmatch(r"[1-9][0-9]{0,38}", amount)
        or int(amount) >= 2**128
    ):
        raise FundingAuditError("transfer_outside_query")
    identity, extrinsic, digest = value["id"], value["extrinsic_id"], value["transaction_hash"]
    if (
        not isinstance(identity, str)
        or not re.fullmatch(rf"finney-{block}-[0-9]+", identity)
        or not isinstance(extrinsic, str)
        or not re.fullmatch(rf"{block}-[0-9]+", extrinsic)
        or not isinstance(digest, str)
        or not re.fullmatch(r"0x[0-9a-f]{64}", digest)
    ):
        raise FundingAuditError("invalid_transfer_reference")
    return {
        "id": identity,
        "from": sender,
        "to": receiver,
        "block_number": block,
        "amount_rao": amount,
        "extrinsic_id": extrinsic,
        "transaction_hash": digest,
    }


class TaostatsTransfers:
    """Fixed-origin, bounded client. Errors never include headers or response bodies."""

    def __init__(
        self, client: httpx.AsyncClient, *, request_interval_seconds=REQUEST_INTERVAL_SECONDS
    ):
        self.client = client
        self.interval = request_interval_seconds
        self.last_request = 0.0

    async def _page(self, recipient, before_block, page):
        await asyncio.sleep(max(0.0, self.last_request + self.interval - time.monotonic()))
        self.last_request = time.monotonic()
        async with self.client.stream(
            "GET",
            TRANSFER_URL,
            params={
                "network": "finney",
                "to": recipient,
                "block_end": before_block - 1,
                "amount_min": "1",
                "order": "block_number_asc",
                "page": page,
                "limit": PAGE_SIZE,
            },
            follow_redirects=False,
        ) as response:
            if response.status_code in {401, 403}:
                raise APIAccessError("taostats_access_required")
            if response.status_code != 200:
                raise FundingAuditError("taostats_request_failed")
            payload = bytearray()
            async for chunk in response.aiter_bytes():
                payload.extend(chunk)
                if len(payload) > MAX_PAGE_BYTES:
                    raise FundingAuditError("taostats_page_too_large")
        return json.loads(payload), hashlib.sha256(payload).hexdigest()

    async def history(self, recipient, before_block, *, max_pages=MAX_PAGES):
        recipient = _address(recipient)
        _uint(before_block)
        if before_block == 0:
            return TransferHistory("registration_at_genesis")
        if type(max_pages) is not int or not 1 <= max_pages <= MAX_PAGES:
            raise FundingAuditError("invalid_page_bound")
        records, page_hashes, seen, total = [], [], set(), None
        try:
            for number in range(1, max_pages + 1):
                body, digest = await self._page(recipient, before_block, number)
                page_hashes.append(digest)
                pagination, data = body["pagination"], body["data"]
                count = _uint(pagination["total_items"])
                pages = _uint(pagination["total_pages"])
                per_page = _uint(pagination["per_page"], PAGE_SIZE)
                if (
                    _uint(pagination["current_page"]) != number
                    or per_page == 0
                    or not isinstance(data, list)
                    or len(data) > per_page
                    or (total is not None and total != count)
                ):
                    raise FundingAuditError("inconsistent_pagination")
                expected_pages = max(1, (count + per_page - 1) // per_page)
                # Accept either documented convention for an empty result.
                if pages != expected_pages and not (count == pages == 0):
                    raise FundingAuditError("inconsistent_pagination")
                total = count
                for item in data:
                    record = _transfer(item, recipient=recipient, before_block=before_block)
                    if record["id"] in seen:
                        raise FundingAuditError("duplicate_transfer")
                    seen.add(record["id"])
                    records.append(record)
                next_page = pagination["next_page"]
                if next_page is None:
                    if len(records) != total or number != max(1, pages):
                        raise FundingAuditError("incomplete_pagination")
                    return TransferHistory("reported_complete", tuple(records), tuple(page_hashes))
                if _uint(next_page) != number + 1 or number >= pages or not data:
                    raise FundingAuditError("inconsistent_pagination")
            return TransferHistory("page_bound_reached", tuple(records), tuple(page_hashes))
        except APIAccessError:
            raise
        except (httpx.HTTPError, ValueError, KeyError, TypeError, RecursionError):
            return TransferHistory("unverified_history", tuple(records), tuple(page_hashes))


async def capture_roster() -> FundingRoster:
    """Pin all storage reads to a finalized RPC block; do not load any wallet."""
    import bittensor as bt
    from bittensor._generated import storage

    from .bootstrap_weight_operator import _participants
    from .observer_chain import _default_client_factory, _first_finalized_header
    from .simple_bootstrap_validator import _account_bytes

    async with _default_client_factory("finney") as client:
        head = await _first_finalized_header(client, 30)
        pinned = await client.at(head.number)
        direct = storage.SubtensorModule
        info, graph, permits, updates = await asyncio.gather(
            pinned.block_info(),
            pinned.subnets.metagraph(netuid=78, commitments=False),
            pinned.query(direct.ValidatorPermit, [78]),
            pinned.query(direct.LastUpdate, [78]),
        )
        participants = _participants(
            graph, block_number=head.number, permits=permits, last_updates=updates
        )

        async def batch(item, params):
            result = []
            for offset in range(0, len(params), 64):
                chunk = params[offset : offset + 64]
                values = await pinned.query_batch(item, chunk)
                if not isinstance(values, list) or len(values) != len(chunk):
                    raise FundingAuditError("incomplete_roster_read")
                result.extend(values)
            return result

        owners, registrations = await asyncio.gather(
            batch(direct.Owner, [[p.hotkey] for p in participants]),
            batch(direct.BlockAtRegistration, [[78, p.uid] for p in participants]),
        )
    return FundingRoster(
        finalized_block=head.number,
        finalized_block_hash=info.hash,
        participants=[
            FundingRegistration(
                uid=p.uid,
                hotkey=p.hotkey,
                coldkey=bt.sp_core.Keypair(public_key=_account_bytes(owner)).ss58_address,
                registered_at_block=registration,
                validator_permit=p.validator_permit,
            )
            for p, owner, registration in zip(participants, owners, registrations, strict=True)
        ],
    )


async def audit_funding(
    roster: FundingRoster, api: TaostatsTransfers, *, shared_funders=(), selected_uids=None
):
    excluded = {_address(value) for value in shared_funders}
    owners, candidates, histories = defaultdict(list), defaultdict(list), []
    selected = {p.uid for p in roster.participants} if selected_uids is None else set(selected_uids)
    if not selected or not selected <= {p.uid for p in roster.participants}:
        raise FundingAuditError("selected_uid_not_registered")
    selected_owners = {p.coldkey for p in roster.participants if p.uid in selected}
    for registration in sorted(roster.participants, key=lambda p: p.uid):
        if registration.coldkey in selected_owners:
            owners[registration.coldkey].append(registration)
    for owner, registrations in sorted(owners.items()):
        before = min(p.registered_at_block for p in registrations)
        history = await api.history(owner, before)
        senders = sorted({t["from"] for t in history.transfers if t["from"] != owner})
        status, candidate = history.status, None
        if status == "reported_complete":
            if len(senders) == 1:
                candidate = senders[0]
                status = (
                    "shared_service_funder_excluded"
                    if candidate in excluded
                    else "single_recorded_sender"
                )
            else:
                status = "multiple_recorded_senders" if senders else "no_recorded_sender"
        entry = {
            "coldkey": owner,
            "uids": [p.uid for p in registrations],
            "before_registration_block": before,
            "status": status,
            "candidate_funder": candidate,
            "recorded_senders": senders,
            "transfers": list(history.transfers),
            "page_sha256": list(history.page_sha256),
        }
        histories.append(entry)
        if status == "single_recorded_sender":
            candidates[candidate].append(entry)
    return {
        "schema": "umi-registration-funding-audit/1",
        "mode": "read_only_review_candidates",
        "reward_changes_authorized": False,
        "selected_uids": sorted(selected),
        "roster": roster.model_dump(mode="json", by_alias=True),
        "source": TRANSFER_URL,
        "limitations": [
            "RPC roster is block-pinned, not storage-proof verified.",
            "Transfer completeness is reported by the indexer, not independently proved.",
            "Current coldkey ownership may differ from ownership at registration.",
            "Same-block funding and non-transfer balance changes are not attributed.",
            "Single sender does not prove registration payment or common operator ownership.",
            "Unlabelled exchange or shared-service senders may remain among candidates.",
            "No recursive grouping, endpoint health check, ban or payout change is performed.",
        ],
        "shared_funders_excluded": sorted(excluded),
        "candidate_groups": [
            {
                "funder": funder,
                "coldkeys": [m["coldkey"] for m in members],
                "uids": sorted(uid for member in members for uid in member["uids"]),
                "requires_review": True,
            }
            for funder, members in sorted(candidates.items())
            if len(members) > 1
        ],
        "histories": histories,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--roster", type=Path, help="saved FundingRoster JSON; otherwise read Finney"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="new report file; never overwritten"
    )
    parser.add_argument(
        "--shared-funder", action="append", default=[], help="known shared-service SS58"
    )
    parser.add_argument(
        "--uid", type=int, action="append", help="limit audit to these UIDs' coldkeys"
    )
    parser.add_argument(
        "--prompt-api-key", action="store_true", help="read key with terminal echo disabled"
    )
    args = parser.parse_args(argv)
    key = (
        getpass.getpass("Taostats API key: ")
        if args.prompt_api_key
        else os.environ.get("TAOSTATS_API_KEY", "")
    ).strip()
    if not key:
        print('{"status":"held","reason":"taostats_api_key_missing"}')
        return 2

    async def run():
        if args.roster:
            with args.roster.open("rb") as source:
                payload = source.read(MAX_PAGE_BYTES + 1)
            if len(payload) > MAX_PAGE_BYTES:
                raise FundingAuditError("roster_too_large")
            roster = FundingRoster.model_validate_json(payload)
        else:
            roster = await asyncio.wait_for(capture_roster(), 120)
        async with httpx.AsyncClient(
            headers={"Authorization": key, "Accept": "application/json"},
            timeout=20,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            return await audit_funding(
                roster,
                TaostatsTransfers(client),
                shared_funders=args.shared_funder,
                selected_uids=args.uid,
            )

    try:
        result = asyncio.run(run())
        descriptor = os.open(
            args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical_json_bytes(result))
            output.flush()
            os.fsync(output.fileno())
    except APIAccessError:
        print('{"status":"held","reason":"taostats_access_required"}')
        return 2
    except (ValueError, OSError, RuntimeError, httpx.HTTPError):
        print('{"status":"held","reason":"funding_audit_failed"}')
        return 1
    print(
        json.dumps(
            {
                "status": "report_written",
                "candidate_groups": len(result["candidate_groups"]),
                "coldkeys_examined": len(result["histories"]),
                "reward_changes_authorized": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
