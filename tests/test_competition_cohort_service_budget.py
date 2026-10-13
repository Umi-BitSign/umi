"""Selected paid execution allowances reach the native route and every caller."""

from dataclasses import replace

import httpx
import pytest

from umi.competition_cohort_service_budget import (
    service_execution_budget,
    service_review_capacity_requirement,
    validate_service_execution_path,
    validate_service_review_capacity,
)
from umi.competition_cohort_service_selection import SelectedServiceReviewer
from umi.competition_cohort_service_vote_http import ServiceVotePeer, service_vote_routes
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_review_budget import (
    chain as chain,
)
from .test_competition_cohort_review_budget import (
    chain_config as chain_config,
)
from .test_competition_cohort_review_budget import (
    control as control,
)
from .test_competition_cohort_review_budget import (
    inputs as inputs,
)
from .test_competition_cohort_review_budget import (
    policy as policy,
)
from .test_competition_cohort_review_budget import (
    profile,
    select,
    with_service,
)
from .test_competition_cohort_review_budget import (
    selected as selected,
)
from .test_competition_cohort_review_budget import (
    series_case as series_case,
)


def test_serial_paid_budget_counts_whole_reads_and_outer_queues(policy):
    selected = profile(policy, export_seconds=43200)
    budget = service_execution_budget(selected)
    assert budget.read_seconds == 86411
    assert budget.call_seconds == 91411
    assert budget.vote_seconds == 11 * 91411 + 7 * 5000 + 300 + 31
    assert budget.exchange_seconds == budget.vote_seconds + 31 + 11
    assert budget.export_seconds == 43200
    # Explicit local allowances may enlarge but never shorten the profile.
    assert service_execution_budget(selected, read_seconds=1) == budget
    larger = service_execution_budget(selected, read_seconds=100000)
    assert larger.read_seconds == 100000 and larger.vote_seconds > budget.vote_seconds


def test_legacy_budget_and_invalid_composite(policy):
    legacy = service_execution_budget(None, read_seconds=12, vote_seconds=21, operation_seconds=9)
    assert legacy.read_seconds == legacy.call_seconds == 12
    assert legacy.vote_seconds == legacy.exchange_seconds == 21
    assert legacy.export_seconds == legacy.dispatch_seconds == 9
    with pytest.raises(ValueError, match="outside bounds"):
        service_execution_budget(profile(policy), read_seconds=2**53 - 1)
    with pytest.raises(ValueError, match=r"shortens.*signing"):
        service_execution_budget(profile(policy), signing_seconds=301)


@pytest.mark.parametrize("selected_profile", [False, True])
async def test_selected_paid_readers_peer_route_and_restart_preserve_binding(
    selected, monkeypatch, selected_profile
):
    config = with_service(selected.config)
    if selected_profile:
        config = select(config, profile(config.policy, export_seconds=43200))
    expected = service_execution_budget(config.phase_review_budget)
    async with httpx.AsyncClient() as client:
        reviewer = SelectedServiceReviewer(config, None, client, "t" * 32, None, None)
        assert reviewer.history.timeout == reviewer.owner.timeout == expected.read_seconds
        assert (
            reviewer.history.fetch.timeout_seconds
            == reviewer.owner.fetch.timeout_seconds
            == expected.read_seconds
        )
        reviewer.journal.put("selected_budget_test", "original", {"preserve": True})
        with reviewer.journal.read_transaction() as db:
            original_binding = db.execute("SELECT body FROM binding").fetchone()[0]
        peer = ServiceVotePeer(
            client,
            config.owner_origin,
            policy=config.policy,
            cohorts=config.service_signing.cohorts,
            signer=config.service_signing.signer,
            token="v" * 32,
            budget=config.phase_review_budget,
        )
        assert (
            peer.requests.timeout_seconds
            == peer.retries.timeout_seconds
            == expected.exchange_seconds
        )

        from umi import competition_cohort_service_vote_http as routes

        native = routes.phase_review_routes
        allowances = []

        def inspect(responder, **kwargs):
            allowances.append(responder.timeout_seconds)
            return native(responder, **kwargs)

        monkeypatch.setattr(routes, "phase_review_routes", inspect)
        service_vote_routes(reviewer, token="v" * 32, budget=reviewer.budget)
        assert allowances == [expected.vote_seconds, expected.vote_seconds]
        # Operational read/capacity changes reopen the exact legacy journal;
        # neither the phase profile nor timers become signed authority.
        adjusted = config.model_copy(
            update={
                "service_signing": config.service_signing.model_copy(
                    update={
                        "read_timeout_seconds": 90000,
                        "maximum_votes": 60000,
                    }
                ),
            }
        )
        reopened = SelectedServiceReviewer(adjusted, None, client, "t" * 32, None, None)
        assert reopened.journal.get("selected_budget_test", "original") == {"preserve": True}
        with reopened.journal.read_transaction() as db:
            assert db.execute("SELECT body FROM binding").fetchone()[0] == original_binding
        assert canonical_json_bytes(config.service_signing) == canonical_json_bytes(
            type(config.service_signing).model_validate_json(
                canonical_json_bytes(config.service_signing)
            )
        )


def test_complete_service_path_rejects_short_proxy_and_override(policy):
    selected = profile(policy, export_seconds=43200)
    budget = service_execution_budget(selected)
    path = dict(
        owner=selected,
        owner_budget=budget,
        reviewer=selected,
        peer=selected,
        reviewer_budget=budget,
        peer_budget=budget,
        direct_owner=True,
        direct_vote=True,
    )
    validate_service_execution_path(**path)
    with pytest.raises(ValueError, match="peer shortens"):
        validate_service_execution_path(
            **(path | {"peer_budget": replace(budget, exchange_seconds=2400)})
        )
    with pytest.raises(ValueError, match="vote proxy shortens"):
        validate_service_execution_path(
            **(path | {"direct_vote": False, "vote_proxy_seconds": 2400})
        )
    with pytest.raises(ValueError, match="owner proxy shortens"):
        validate_service_execution_path(
            **(path | {"direct_owner": False, "owner_proxy_seconds": 2400})
        )


def test_paid_capacity_counts_catalog_scope_and_both_intent_kinds():
    required = service_review_capacity_requirement(
        [8192, 8192, 100],
        maximum_claims_per_catalog=8192,
        attempts_per_claim=3,
    )
    assert required["admissible_claims"] == 16484
    assert required["required_intents"] == 98904
    assert required["retry_cutoff_authorized"] is False
    for capacity in (4096, 8192, 65536):
        with pytest.raises(ValueError, match="omits admitted work"):
            validate_service_review_capacity(maximum_votes=capacity, requirement=required)
    validate_service_review_capacity(maximum_votes=98904, requirement=required)
