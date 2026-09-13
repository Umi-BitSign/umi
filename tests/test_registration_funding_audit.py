from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from umi import registration_funding_audit as audit

from .factories import dev_wallet


def address(n):
    return dev_wallet(f"//FundingAudit{n}").hotkey.ss58_address


def transfer(sender=1, recipient=2, block=100, index=1, amount="1000000000"):
    return {
        "id": f"finney-{block}-{index:04}",
        "from": {"ss58": address(sender)},
        "to": {"ss58": address(recipient)},
        "block_number": block,
        "amount": amount,
        "network": "finney",
        "transaction_hash": "0x" + f"{index:064x}",
        "extrinsic_id": f"{block}-0001",
    }


def page(rows, number=1, total=None, per_page=200):
    total = len(rows) if total is None else total
    pages = max(1, (total + per_page - 1) // per_page)
    return {
        "data": rows,
        "pagination": {
            "current_page": number,
            "per_page": per_page,
            "total_items": total,
            "total_pages": pages,
            "next_page": number + 1 if number < pages else None,
        },
    }


async def fetch(handler, **kwargs):
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        return await audit.TaostatsTransfers(client, request_interval_seconds=0).history(
            address(2), 120, **kwargs
        )


async def test_valid_history_is_bounded_to_before_registration_and_has_evidence():
    def handler(request):
        assert str(request.url).startswith(audit.TRANSFER_URL + "?")
        assert request.url.params["to"] == address(2)
        assert request.url.params["block_end"] == "119"
        assert request.url.params["amount_min"] == "1"
        assert request.url.params["limit"] == "200"
        return httpx.Response(200, json=page([transfer()]))

    result = await fetch(handler)
    assert result.status == "reported_complete"
    assert result.transfers[0]["from"] == address(1)
    assert result.transfers[0]["extrinsic_id"] == "100-0001"
    assert len(result.page_sha256) == 1 and len(result.page_sha256[0]) == 64


async def test_all_pages_required_and_each_requested_once():
    calls = []

    def handler(request):
        number = int(request.url.params["page"])
        calls.append(number)
        return httpx.Response(200, json=page([transfer(index=number)], number, 2, 1))

    result = await fetch(handler)
    assert result.status == "reported_complete"
    assert calls == [1, 2] and len(result.transfers) == 2
    result = await fetch(handler, max_pages=1)
    assert result.status == "page_bound_reached"


@pytest.mark.parametrize("status", [301, 302, 429, 500, 503])
async def test_http_errors_and_redirects_never_create_complete_history(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"location": "https://attacker.invalid"})

    result = await fetch(handler)
    assert result.status == "unverified_history" and len(calls) == 1


@pytest.mark.parametrize("status", [401, 403])
async def test_invalid_key_aborts_without_echoing_provider_body(status):
    with pytest.raises(audit.APIAccessError, match=r"^taostats_access_required$"):
        await fetch(lambda _: httpx.Response(status, text="SECRET-DONT-PRINT"))


@pytest.mark.parametrize(
    "bad",
    [
        {"network": "nakamoto"},
        {"block_number": 120},
        {"block_number": True},
        {"amount": "0"},
        {"amount": "-1"},
        {"amount": "1e9"},
        {"amount": 1000},
        {"to": {"ss58": address(3)}},
        {"id": "malformed"},
        {"transaction_hash": "unknown"},
        {"extrinsic_id": "999-0001"},
    ],
)
async def test_malformed_or_out_of_scope_transfer_is_unverified(bad):
    result = await fetch(lambda _: httpx.Response(200, json=page([{**transfer(), **bad}])))
    assert result.status == "unverified_history"


@pytest.mark.parametrize(
    "bad",
    [
        {"current_page": 2},
        {"per_page": 0},
        {"total_items": 9},
        {"next_page": 2},
        {"total_pages": 5},
        {"total_items": True},
    ],
)
async def test_pagination_inconsistency_never_becomes_no_history(bad):
    value = page([transfer()])
    value["pagination"].update(bad)
    assert (await fetch(lambda _: httpx.Response(200, json=value))).status == "unverified_history"


async def test_empty_history_and_duplicate_records():
    value = page([])
    for total_pages in (0, 1):
        value["pagination"]["total_pages"] = total_pages
        result = await fetch(lambda _: httpx.Response(200, json=value))
        assert result.status == "reported_complete" and not result.transfers
    result = await fetch(lambda _: httpx.Response(200, json=page([transfer(), transfer()])))
    assert result.status == "unverified_history"


async def test_oversized_or_non_json_response():
    for payload in (b"not JSON", b" " * (audit.MAX_PAGE_BYTES + 1)):
        assert (
            await fetch(lambda _, payload=payload: httpx.Response(200, content=payload))
        ).status == "unverified_history"


def roster():
    return audit.FundingRoster(
        finalized_block=200,
        finalized_block_hash="0x" + "ab" * 32,
        participants=[
            audit.FundingRegistration(
                uid=uid,
                hotkey=address(uid + 100),
                coldkey=address(owner),
                registered_at_block=block,
                validator_permit=False,
            )
            for uid, owner, block in [(71, 2, 120), (72, 3, 130), (73, 2, 140), (74, 4, 150)]
        ],
    )


def histories(status="reported_complete"):
    calls = []

    async def history(owner, before):
        calls.append((owner, before))
        number = next(n for n in (2, 3, 4) if address(n) == owner)
        # Coldkeys 2 and 3 share one sender. 4 has two senders and stays ambiguous.
        senders = (1,) if number != 4 else (1, 5)
        return audit.TransferHistory(
            status,
            tuple(
                audit._transfer(
                    transfer(sender=n, recipient=number, index=n),
                    recipient=owner,
                    before_block=before,
                )
                for n in senders
            ),
        )

    return SimpleNamespace(history=history, calls=calls)


async def test_groups_are_direct_review_candidates_not_transitive_ownership_claims():
    api = histories()
    result = await audit.audit_funding(roster(), api)
    assert len(api.calls) == 3
    assert (address(2), 120) in api.calls  # One history for two UIDs, before earliest registration.
    assert result["reward_changes_authorized"] is False
    assert result["candidate_groups"] == [
        {
            "funder": address(1),
            "coldkeys": sorted([address(2), address(3)]),
            "uids": [71, 72, 73],
            "requires_review": True,
        }
    ]
    ambiguous = next(h for h in result["histories"] if h["coldkey"] == address(4))
    assert ambiguous["status"] == "multiple_recorded_senders"
    assert ambiguous["candidate_funder"] is None


@pytest.mark.parametrize("status", ["page_bound_reached", "unverified_history"])
async def test_partial_history_never_forms_a_group(status):
    assert not (await audit.audit_funding(roster(), histories(status)))["candidate_groups"]


async def test_known_shared_service_is_excluded_and_uid_selection_preserves_all_owned_uids():
    api = histories()
    result = await audit.audit_funding(
        roster(), api, shared_funders=[address(1)], selected_uids=[71, 72]
    )
    assert len(api.calls) == 2 and not result["candidate_groups"]
    assert all(h["status"] == "shared_service_funder_excluded" for h in result["histories"])
    assert sorted(uid for h in result["histories"] for uid in h["uids"]) == [71, 72, 73]


async def test_unknown_uid_is_rejected_before_api_access():
    api = histories()
    with pytest.raises(audit.FundingAuditError):
        await audit.audit_funding(roster(), api, selected_uids=[255])
    assert not api.calls


def test_missing_key_does_not_read_wallet_network_or_create_report(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("TAOSTATS_API_KEY", raising=False)
    output = tmp_path / "report.json"
    assert audit.main(["--output", str(output)]) == 2
    assert not output.exists()
    assert json.loads(capsys.readouterr().out)["reason"] == "taostats_api_key_missing"


async def test_five_per_minute_throttle(monkeypatch):
    clock, starts = [100.0], []
    monkeypatch.setattr(audit.time, "monotonic", lambda: clock[0])

    async def sleep(delay):
        clock[0] += delay

    monkeypatch.setattr(audit.asyncio, "sleep", sleep)

    def handler(_):
        starts.append(clock[0])
        return httpx.Response(200, json=page([]))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        api = audit.TaostatsTransfers(client)
        for _ in range(6):
            await api.history(address(2), 120)
    assert starts == [100, 112.5, 125, 137.5, 150, 162.5]
