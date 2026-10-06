"""Single-record relay pages must not turn outage catchup into repeated audits."""

import asyncio

import pytest

from umi.competition_supervisor import SuccessorSupervisorDirectivePage
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import MAX_SUPERVISOR_DIRECTIVES_PER_PAGE

from .test_competition_supervisor_runtime import case as case
from .test_competition_supervisor_runtime import next_directive
from .test_competition_supervisor_runtime import package_case as package_case
from .test_competition_supervisor_runtime import package_limits as package_limits
from .test_competition_supervisor_runtime import policy as policy
from .test_competition_supervisor_runtime import release_identity as release_identity
from .test_competition_supervisor_runtime import replay_limits as replay_limits
from .test_competition_supervisor_runtime import successor_case as successor_case
from .test_competition_supervisor_runtime import successor_chain as successor_chain
from .test_competition_supervisor_runtime import successor_release as successor_release
from .test_competition_supervisor_runtime import v3_predecessor as v3_predecessor


async def test_single_record_pages_reach_current_head_without_intermediate_activation(case):
    previous = case.source.signed.directive_sha256
    records = []
    for index in range(6):
        signed = next_directive(
            case,
            previous=previous,
            sequence=3 + index,
            start=150 + 10 * index,
            end=400 if index == 5 else 154 + 10 * index,
        )
        records.append(signed)
        previous = signed.directive_sha256
    case.observation.block = 202
    calls = []

    async def page(**cursor):
        calls.append(cursor)
        index = cursor["after_sequence"] - 2
        item = records[index]
        return canonical_json_bytes(
            SuccessorSupervisorDirectivePage(
                schema="umi-validator-supervisor-directive-page/4",
                **cursor,
                directives=[item],
                more=index + 1 < len(records),
                head=item,
            )
        )

    case.fetcher.fetch_directive_page = page
    async with case.make() as engine:
        result = await engine.reconcile()
        if result.status == "holding":
            assert result.reason == "successor_history_catchup_incomplete", result
            assert result.accepted_sequence == 3 and len(calls) == 1, result
        assert result.status == "started" and result.accepted_sequence == 8, result
        assert len(calls) == 6
        assert len(engine._load_history()[1]) == 7
        started = [event[1] for event in case.adapter.events if event[0] in {"replay", "weights"}]
        assert started == [records[-1].directive_sha256]
        assert sum(event[0] == "recover" for event in case.adapter.events) <= 2


@pytest.mark.parametrize("failure", ["unavailable", "wrong_cursor", "cancelled", "bad_signature"])
async def test_partial_catchup_preserves_holds_and_rejects_invalid_authority(case, failure):
    first = next_directive(case, sequence=3, start=150, end=154)
    second = next_directive(case, previous=first.directive_sha256, sequence=4, start=160, end=400)
    case.observation.block = 202
    calls = []

    async def page(**cursor):
        calls.append(cursor)
        if len(calls) == 1:
            item, more = first, True
        else:
            if failure == "unavailable":
                raise OSError("feed unavailable")
            if failure == "cancelled":
                raise asyncio.CancelledError()
            if failure == "wrong_cursor":
                cursor = {**cursor, "after_directive_sha256": "00" * 32}
                item = second.model_copy(
                    update={
                        "directive": second.directive.model_copy(
                            update={"previous_directive_sha256": "00" * 32}
                        )
                    }
                )
            else:
                item = second.model_copy(
                    update={
                        "signatures": [
                            signature.model_copy(update={"signature": "0x" + "00" * 64})
                            for signature in second.signatures
                        ]
                    }
                )
            more = False
        return canonical_json_bytes(
            SuccessorSupervisorDirectivePage(
                schema="umi-validator-supervisor-directive-page/4",
                **cursor,
                directives=[item],
                more=more,
                head=item,
            )
        )

    case.fetcher.fetch_directive_page = page
    async with case.make() as engine:
        if failure == "cancelled":
            with pytest.raises(asyncio.CancelledError):
                await engine.reconcile()
        else:
            result = await engine.reconcile()
            assert result.status == "holding"
            assert result.accepted_sequence in (2, 3)
        assert not [event for event in case.adapter.events if event[0] in {"replay", "weights"}]


async def test_single_record_catchup_stops_at_native_page_bound(case):
    prior, records = case.source.signed.directive_sha256, []
    for index in range(MAX_SUPERVISOR_DIRECTIVES_PER_PAGE + 4):
        item = next_directive(case, previous=prior, sequence=3 + index, start=150, end=154)
        records.append(item)
        prior = item.directive_sha256
    case.observation.block = 202
    calls = []

    async def page(**cursor):
        calls.append(cursor)
        item = records[cursor["after_sequence"] - 2]
        return canonical_json_bytes(
            SuccessorSupervisorDirectivePage(
                schema="umi-validator-supervisor-directive-page/4",
                **cursor,
                directives=[item],
                more=True,
                head=item,
            )
        )

    case.fetcher.fetch_directive_page = page
    limits = type(case.limits)(maximum_history_records=256, maximum_history_bytes=8 * 1024**2)
    async with case.make(limits=limits) as engine:
        result = await engine.reconcile()
        assert result.status == "holding"
        assert result.reason == "successor_history_catchup_incomplete"
        assert result.accepted_sequence == 2 + MAX_SUPERVISOR_DIRECTIVES_PER_PAGE
        assert len(calls) == MAX_SUPERVISOR_DIRECTIVES_PER_PAGE
        assert not [event for event in case.adapter.events if event[0] in {"replay", "weights"}]
