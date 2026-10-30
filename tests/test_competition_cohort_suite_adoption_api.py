"""Native suite owner/reviewer/signing integration; synthetic media/finality ports."""

import asyncio
from functools import partial
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_suite_adoption_candidate as candidate_module
from umi.competition_cohort_history_http import CohortHistoryHTTPClient, CohortHistoryReader
from umi.competition_cohort_progress_signer import CohortProgressSigner, CohortProgressSignerConfig
from umi.competition_cohort_request_rule import prepare_request_tail_adoption_at_block
from umi.competition_cohort_suite_adoption_api import (
    ROOT,
    EvaluationSuiteAdoptionCommit,
    EvaluationSuiteAdoptionOwner,
    EvaluationSuiteAdoptionPrepare,
    EvaluationSuiteAdoptionProposal,
    EvaluationSuiteAdoptionReviewer,
    EvaluationSuiteAdoptionVotePeer,
    assemble_evaluation_suite_adoption,
    evaluation_suite_adoption_owner_routes,
    evaluation_suite_adoption_vote_routes,
)
from umi.competition_cohort_suite_adoption_candidate import (
    EvaluationSuiteAdoptionCandidate,
    EvaluationSuiteAdoptionCandidateConfig,
    require_successor_suite_diversity,
)
from umi.competition_cohort_suite_adoption_reservation import (
    EvaluationSuiteReservationReader,
    evaluation_suite_reservation_routes,
)
from umi.competition_suite_reference_qa import SuiteReferenceInterval, SuiteReferenceQA
from umi.open_competition import digest, sign_object
from umi.private_files import ensure_private_directory, publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_request_rule_adoption import original as original
from .test_competition_cohort_request_rule_api import api as api
from .test_competition_cohort_request_rule_api import post
from .test_competition_cohort_standing_phases import standing
from .test_competition_suite_selection import candidate as metadata_candidate
from .test_competition_suite_selection import case as selector_case_fixture
from .test_competition_suite_selection import categorized, select
from .test_competition_two_task_profile import launch_policy
from .test_open_competition import policy as base_policy
from .test_open_competition import wallet


@pytest.fixture
def policy():
    return launch_policy(base_policy.__wrapped__())


@pytest.fixture
def selection_case(policy, request):
    c = selector_case_fixture.__wrapped__(policy)
    c.inventory, c.counts = categorized(c)
    if getattr(request, "param", None) == "wide":
        values = tuple(
            entry.model_copy(update={"topic": "Cooking"})
            if entry.case.stratum == "continuous" and entry.topic is None
            else entry
            for entry in c.inventory.cases
        )
        extra = metadata_candidate(
            111,
            "Rain falls slowly across the western plains",
            dataset="AnotherCorpus",
            signer=111,
            topic="Weather",
        )
        c.inventory = c.inventory.model_copy(update={"cases": (*values, extra)})
        c.counts = c.counts.model_copy(
            update={
                "continuous": 4,
                "maximum_continuous_dataset_share_bps": 5000,
                "minimum_continuous_topics": 4,
                "minimum_fingerspelling_datasets": 2,
                "maximum_fingerspelling_dataset_share_bps": 7500,
                "maximum_cases_per_dataset": 2,
            }
        )
    return c


def test_historical_candidate_retains_original_source_and_training_exclusion_rules(selection_case):
    require_successor_suite_diversity = partial(
        candidate_module.require_successor_suite_diversity,
        candidate_schema="umi-evaluation-suite-adoption-candidate/1",
    )
    counts = selection_case.counts
    require_successor_suite_diversity(6, counts)
    with pytest.raises(ValueError, match="source cap"):
        require_successor_suite_diversity(7, counts)
    capped = counts.model_copy(
        update={
            "continuous": 4,
            "maximum_continuous_dataset_share_bps": 5000,
            "minimum_continuous_topics": 4,
        }
    )
    with pytest.raises(ValueError, match="fingerspelling sources"):
        require_successor_suite_diversity(7, capped)
    broader = capped.model_copy(
        update={
            "minimum_fingerspelling_datasets": 2,
            "maximum_fingerspelling_dataset_share_bps": 7500,
        }
    )
    with pytest.raises(ValueError, match="training-exclusion evidence"):
        require_successor_suite_diversity(7, broader)
    broader = broader.model_copy(
        update={
            "minimum_training_excluded_fingerspelling": 2,
            "minimum_training_excluded_continuous": 2,
        }
    )
    with pytest.raises(ValueError, match="training-exclusion evidence"):
        require_successor_suite_diversity(7, broader)
    broader = broader.model_copy(
        update={
            "minimum_training_excluded_fingerspelling": broader.fingerspelling,
            "minimum_training_excluded_continuous": broader.continuous,
        }
    )
    require_successor_suite_diversity(7, broader)
    require_successor_suite_diversity(8, broader)
    with pytest.raises(ValueError, match="source cap"):
        require_successor_suite_diversity(
            8, capped.model_copy(update={"maximum_continuous_dataset_share_bps": 5001})
        )


def test_current_candidate_accepts_public_sources_with_global_two_case_cap(selection_case):
    counts = selection_case.counts.model_copy(
        update={
            "continuous": 4,
            "maximum_continuous_dataset_share_bps": 5000,
            "minimum_continuous_topics": 4,
            "minimum_fingerspelling_datasets": 2,
            "maximum_fingerspelling_dataset_share_bps": 7500,
            "maximum_cases_per_dataset": 2,
        }
    )
    assert counts.minimum_training_excluded_fingerspelling == 0
    assert counts.minimum_training_excluded_continuous == 0
    for sequence in (7, 8, 9, 10, 11):
        require_successor_suite_diversity(sequence, counts)
    for cap in (None, 3):
        with pytest.raises(ValueError, match="maximum_cases_per_dataset of 1 or 2"):
            require_successor_suite_diversity(
                7,
                counts.model_copy(
                    update={
                        "maximum_cases_per_dataset": cap,
                    }
                ),
            )
    require_successor_suite_diversity(
        7,
        counts.model_copy(
            update={
                "maximum_cases_per_dataset": 1,
            }
        ),
    )
    with pytest.raises(ValueError, match="source cap"):
        require_successor_suite_diversity(
            7,
            counts.model_copy(
                update={
                    "maximum_continuous_dataset_share_bps": 5001,
                }
            ),
        )
    with pytest.raises(ValueError, match="fingerspelling sources"):
        require_successor_suite_diversity(
            7,
            counts.model_copy(
                update={
                    "minimum_fingerspelling_datasets": 1,
                }
            ),
        )


@pytest.fixture
def candidate(original, selection_case, tmp_path, monkeypatch):
    c = selection_case
    history, _ = original
    root = tmp_path / "private-candidate"
    ensure_private_directory(root)
    ensure_private_directory(root / "reference-qa")
    values = []
    for entry in c.inventory.cases:
        qualified = SuiteReferenceQA(
            schema="umi-suite-reference-qa/1",
            case_sha256=digest(entry.case),
            source_group_sha256=entry.source_group_sha256,
            signer_group_sha256=entry.signer_group_sha256,
            provenance_sha256=entry.provenance_sha256,
            reference_sha256=digest(entry.case.references),
            annotation_source_sha256="d1" * 32,
            reference_basis="publisher_annotation",
            annotation_source="synthetic publisher evidence",
            interval=SuiteReferenceInterval(kind="publisher_labeled_clip"),
            reference_and_interval_checked=True,
            fingerspelling_category=entry.fingerspelling_category,
        )
        publish_private_model(root / "reference-qa" / (digest(qualified) + ".json"), qualified)
        values.append(entry.model_copy(update={"reference_qa_sha256": digest(qualified)}))
    c.inventory = c.inventory.model_copy(update={"cases": tuple(values)})
    suite, report = select(c)
    for name, value in (
        ("suite", suite),
        ("manifest", report),
        ("inventory", c.inventory),
        ("exclusions", c.exclusions),
    ):
        if name == "manifest":
            (root / (name + ".json")).write_bytes(canonical_json_bytes(value))
            (root / (name + ".json")).chmod(0o600)
        else:
            publish_private_model(root / (name + ".json"), value)
    (root / "key").write_bytes(c.key)
    (root / "key").chmod(0o600)
    ensure_private_directory(root / "videos")
    for case in suite.cases:
        path = root / "videos" / (case.video_sha256 + ".mp4")
        path.write_bytes(b"synthetic-media-port")
        path.chmod(0o600)
    config = EvaluationSuiteAdoptionCandidateConfig(
        schema="umi-evaluation-suite-adoption-candidate/1",
        cohort_sha256=digest(history.plan),
        verification_owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        suite_file=str(root / "suite.json"),
        selection_manifest_file=str(root / "manifest.json"),
        inventory_file=str(root / "inventory.json"),
        exclusions_file=str(root / "exclusions.json"),
        selection_key_file=str(root / "key"),
        videos_directory=str(root / "videos"),
        reference_qa_directory=str(root / "reference-qa"),
        verification_directory=str(root / "checks"),
        ffmpeg_binary=str(root / "ffmpeg"),
        ffprobe_binary=str(root / "ffprobe"),
        ffmpeg_sha256="a1" * 32,
        ffprobe_sha256="a2" * 32,
    )
    calls = []

    def inspect(path, **kwargs):
        calls.append(path.stem)
        return SimpleNamespace(video_sha256=path.stem)

    monkeypatch.setattr(candidate_module, "inspect_media_pinned", inspect)
    return SimpleNamespace(
        value=EvaluationSuiteAdoptionCandidate(config, c.policy),
        config=config,
        history=history,
        suite=suite,
        calls=calls,
        root=root,
    )


def test_candidate_schema_defaults_to_current_and_preserves_explicit_historical_bytes(candidate):
    old = canonical_json_bytes(candidate.config)
    assert candidate.config.schema_ == "umi-evaluation-suite-adoption-candidate/1"
    restored = EvaluationSuiteAdoptionCandidateConfig.model_validate_json(old)
    assert canonical_json_bytes(restored) == old
    body = candidate.config.model_dump(by_alias=True)
    body.pop("schema")
    current = EvaluationSuiteAdoptionCandidateConfig.model_validate(body)
    assert current.schema_ == "umi-evaluation-suite-adoption-candidate/2"
    assert current.model_dump(by_alias=True) == body | {
        "schema": "umi-evaluation-suite-adoption-candidate/2"
    }


@pytest.mark.parametrize("selection_case", ["wide"], indirect=True)
async def test_current_c7_public_suite_native_review_reuses_qa_media_and_preserves_history(
    candidate, monkeypatch
):
    c = candidate
    plan = c.history.plan.model_copy(update={"sequence": 7})
    authority, genesis, _ = standing(plan, c.value.policy, model_rewards=True)
    history = c.history.model_copy(
        update={
            "plan": plan,
            "authority": authority,
            "genesis": genesis,
            "genesis_signatures": signatures(genesis),
        }
    )
    original_history = canonical_json_bytes(history)
    config = c.config.model_copy(
        update={
            "schema_": "umi-evaluation-suite-adoption-candidate/2",
            "cohort_sha256": digest(plan),
        }
    )
    owner = EvaluationSuiteAdoptionCandidate(config, c.value.policy)
    suite, manifest = owner.selection()
    assert manifest["selected_training_exposure"] == {"known_public": 8}
    assert max(manifest["selected_dataset_totals"].values()) <= 2
    proposal = owner._proposal(history, 220, suite, manifest)
    first = await owner.verify(history, proposal)
    assert first["cases"] == 8 and first["private_source_exposure_not_proven_unseen"]
    assert len(c.calls) == 8

    def forbidden(*args, **kwargs):
        pytest.fail("completed current-suite selection and media must be reused")

    monkeypatch.setattr(candidate_module, "select_future_suite", forbidden)
    monkeypatch.setattr(candidate_module, "inspect_media_pinned", forbidden)
    assert (
        await EvaluationSuiteAdoptionCandidate(config, c.value.policy).verify(history, proposal)
        == first
    )
    historical = config.model_copy(update={"schema_": "umi-evaluation-suite-adoption-candidate/1"})
    with pytest.raises(ValueError, match="training-exclusion evidence"):
        await EvaluationSuiteAdoptionCandidate(historical, c.value.policy).verify(history, proposal)
    assert canonical_json_bytes(history) == original_history


async def test_candidate_reuses_each_native_selection_and_media_result_after_restart(
    candidate, monkeypatch
):
    c = candidate
    proposal = c.value._proposal(c.history, 220, *c.value.selection())
    first = await c.value.verify(c.history, proposal)
    assert len(c.calls) == len(c.suite.cases)

    def forbidden(*args, **kwargs):
        pytest.fail("unchanged completed verification cannot repeat selection or media I/O")

    monkeypatch.setattr(candidate_module, "select_future_suite", forbidden)
    monkeypatch.setattr(candidate_module, "inspect_media_pinned", forbidden)
    reopened = EvaluationSuiteAdoptionCandidate(c.config, c.value.policy)
    assert await reopened.verify(c.history, proposal) == first
    assert first["private_source_exposure_not_proven_unseen"]


async def test_candidate_resumes_individual_completed_videos_and_requires_explicit_repair(
    candidate, monkeypatch
):
    c = candidate
    proposal = c.value._proposal(c.history, 220, *c.value.selection())
    original_inspect = candidate_module.inspect_media_pinned
    attempts = []

    def interrupted(path, **kwargs):
        attempts.append(path.stem)
        if len(attempts) == 3:
            raise OSError("interrupted native media check")
        return original_inspect(path, **kwargs)

    monkeypatch.setattr(candidate_module, "inspect_media_pinned", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        await c.value.verify(c.history, proposal)
    monkeypatch.setattr(candidate_module, "inspect_media_pinned", original_inspect)
    await EvaluationSuiteAdoptionCandidate(c.config, c.value.policy).verify(c.history, proposal)
    assert len(c.calls) == len(c.suite.cases) and len(set(c.calls)) == len(c.suite.cases)
    path = c.root / "videos" / (c.suite.cases[0].video_sha256 + ".mp4")
    path.write_bytes(b"changed identity")
    with pytest.raises(ValueError, match="explicit repair"):
        await c.value.verify(c.history, proposal)
    repaired = c.config.model_copy(update={"verification_repair_reason": "restore verified source"})
    await EvaluationSuiteAdoptionCandidate(repaired, c.value.policy).verify(c.history, proposal)
    assert len(c.calls) == len(c.suite.cases) + 1


async def test_candidate_refuses_changed_selection_and_false_content_identity(
    candidate, monkeypatch
):
    c = candidate
    proposal = c.value._proposal(c.history, 220, *c.value.selection())
    monkeypatch.setattr(
        candidate_module,
        "inspect_media_pinned",
        lambda *a, **k: SimpleNamespace(video_sha256="f1" * 32),
    )
    with pytest.raises(ValueError, match="committed content"):
        await c.value.verify(c.history, proposal)
    (c.root / "key").write_bytes(bytes(reversed(range(32))))
    monkeypatch.setattr(
        candidate_module, "select_future_suite", lambda *a, **k: (c.suite, {"false": "report"})
    )
    with pytest.raises(ValueError, match="provenance"):
        repaired = c.config.model_copy(
            update={"verification_repair_reason": "verify replacement key"}
        )
        await EvaluationSuiteAdoptionCandidate(repaired, c.value.policy).verify(c.history, proposal)


@pytest.fixture
def suite_api(api, candidate):
    h = api
    h.host.config = SimpleNamespace(evaluation_suite_adoption_candidates=(candidate.config,))
    h.host.evaluation_suite_candidates = {h.cohort: candidate.value}
    h.host.model_delivery_serial = asyncio.Lock()
    h.app.include_router(evaluation_suite_adoption_owner_routes(h.host, token="o" * 32))
    h.app.include_router(evaluation_suite_reservation_routes(h.host, token="h" * 32))
    h.candidate = candidate
    return h


def prepare_request(h):
    return EvaluationSuiteAdoptionPrepare(
        schema="umi-evaluation-suite-adoption-prepare/1",
        series_sha256=digest(h.series),
        cohort_sha256=h.cohort,
        predecessor_sha256=h.state.tip_sha256,
    )


async def test_native_owner_routes_review_quorum_commit_preserve_clock_and_reuse(
    suite_api, tmp_path
):
    h = suite_api
    plan_bytes = canonical_json_bytes(h.plan)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        request = prepare_request(h)
        denied = await post(client, ROOT + "/prepare", request, token="h" * 32)
        assert denied.status_code == 401
        prepared = await post(client, ROOT + "/prepare", request)
        assert prepared.status_code == 200, prepared.text
        proposal = EvaluationSuiteAdoptionProposal.model_validate_json(prepared.content)
        assert (await post(client, ROOT + "/reserve", proposal)).status_code == 200
        assert (await post(client, ROOT + "/reserve", proposal)).status_code == 200
        h.block += 1
        assert (await post(client, ROOT + "/prepare", request)).content == prepared.content
        history = CohortHistoryReader(
            wallet("Charlie").hotkey.ss58_address,
            CohortHistoryHTTPClient(client, "https://owner.example", token="h" * 32),
        )
        reviewer = SimpleNamespace(
            policy=h.policy,
            cohorts=h.intake.config.cohorts,
            evaluation_suite_adoption=EvaluationSuiteAdoptionReviewer(
                h.series,
                h.policy,
                h,
                history,
                EvaluationSuiteReservationReader(
                    client,
                    "https://owner.example",
                    token="h" * 32,
                    owner=wallet("Charlie").hotkey.ss58_address,
                ),
                candidates={h.cohort: h.candidate.value},
            ),
        )
        votes, signers = [], []
        for name in ("Charlie", "Dave"):
            own_config = h.candidate.config.model_copy(
                update={
                    "verification_owner_hotkey": wallet(name).hotkey.ss58_address,
                    "verification_directory": str(tmp_path / (name + "-independent-media")),
                }
            )
            reviewer.evaluation_suite_adoption.candidates[h.cohort] = (
                EvaluationSuiteAdoptionCandidate(own_config, h.policy)
            )

            async def sign(body, name=name):
                return sign_object(body, wallet(name))

            signer = CohortProgressSigner(
                CohortProgressSignerConfig(
                    schema="umi-cohort-progress-signer-config/1",
                    directory=str(tmp_path / name),
                    policy_sha256=digest(h.policy),
                    signer=wallet(name).hotkey.ss58_address,
                    cohorts=h.intake.config.cohorts,
                ),
                reviewer,
                sign,
            )
            signers.append(signer)
            app = FastAPI()
            app.include_router(
                evaluation_suite_adoption_vote_routes(signer, h.series, token="v" * 32)
            )
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as peer_client:
                peer = EvaluationSuiteAdoptionVotePeer(
                    peer_client,
                    "https://review.example",
                    signer=signer.config.signer,
                    token="v" * 32,
                )
                votes.append(await peer.certify(proposal))
                assert await peer.certify(proposal) == votes[-1]
        other = prepare_request_tail_adoption_at_block(h.candidate.history, h.policy, 220)
        with pytest.raises(ValueError, match="reserved for another body"):
            await signers[0].certify_request_tail_adoption(other)
        commit = EvaluationSuiteAdoptionCommit(
            schema="umi-evaluation-suite-adoption-commit/1",
            series_sha256=digest(h.series),
            certificate=assemble_evaluation_suite_adoption(proposal, votes, h.policy),
        )
        assert (await post(client, ROOT + "/commit", commit)).status_code == 200
        assert (await post(client, ROOT + "/commit", commit)).status_code == 200
        assert h.intake.pending_policy_adoption(h.cohort) is None
        assert h.state.phase == "intake" and h.state.targets == proposal.transition.targets
        assert canonical_json_bytes(h.intake.history(h.cohort).plan) == plan_bytes
        assert len(h.candidate.calls) == 3 * len(h.candidate.suite.cases)


async def test_intake_first_reservation_recovers_exact_bytes_after_control_crash(
    suite_api, monkeypatch
):
    h = suite_api
    request = prepare_request(h)
    prepared = await EvaluationSuiteAdoptionOwner(h.host, "prepare").respond(request)
    proposal = EvaluationSuiteAdoptionProposal.model_validate_json(prepared)
    original_reserve = h.store.reserve_exact

    def interrupted(*args, **kwargs):
        raise OSError("control acknowledgement lost")

    monkeypatch.setattr(h.store, "reserve_exact", interrupted)
    with pytest.raises(OSError, match="acknowledgement"):
        await EvaluationSuiteAdoptionOwner(h.host, "reserve").respond(proposal)
    assert h.intake.pending_policy_adoption(h.cohort) == proposal.transition
    monkeypatch.setattr(h.store, "reserve_exact", original_reserve)
    h.restart()
    h.node.controller.store = h.store
    assert await EvaluationSuiteAdoptionOwner(h.host, "reserve").respond(proposal) == prepared
    h.block += 10
    assert await EvaluationSuiteAdoptionOwner(h.host, "prepare").respond(request) == prepared


@pytest.mark.parametrize("changed", ["challenge", "history", "owner", "canonical"])
async def test_fresh_reservation_proof_cannot_move_between_requests_or_histories(
    suite_api, changed
):
    from umi.competition_cohort_suite_adoption_reservation import (
        EvaluationSuiteReservationExporter,
        EvaluationSuiteReservationRequest,
    )

    h = suite_api
    raw = await EvaluationSuiteAdoptionOwner(h.host, "prepare").respond(prepare_request(h))
    proposal = EvaluationSuiteAdoptionProposal.model_validate_json(raw)
    await EvaluationSuiteAdoptionOwner(h.host, "reserve").respond(proposal)
    request = EvaluationSuiteReservationRequest(
        schema="umi-evaluation-suite-reservation-request/1",
        transition=proposal.transition,
        challenge="a3" * 32,
    )
    raw = await EvaluationSuiteReservationExporter(h.host).respond(request)
    history = h.candidate.history
    owner = wallet("Charlie").hotkey.ss58_address
    if changed == "challenge":
        request = request.model_copy(update={"challenge": "b3" * 32})
    elif changed == "history":
        history = history.model_copy(update={"genesis_signatures": ()})
    elif changed == "owner":
        owner = wallet("Dave").hotkey.ss58_address
    else:
        raw += b"\n"
    reader = EvaluationSuiteReservationReader(
        None, "https://owner.example", token="h" * 32, owner=owner
    )
    with pytest.raises(ValueError, match="challenge, history or owner"):
        reader._verify(raw, request, history)


@pytest.mark.parametrize("changed", ["finality", "candidate"])
async def test_independent_reviewer_refuses_missing_owned_basis(suite_api, changed):
    h = suite_api
    raw = await EvaluationSuiteAdoptionOwner(h.host, "prepare").respond(prepare_request(h))
    proposal = EvaluationSuiteAdoptionProposal.model_validate_json(raw)
    await EvaluationSuiteAdoptionOwner(h.host, "reserve").respond(proposal)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://owner.example"
    ) as client:
        history = CohortHistoryReader(
            wallet("Charlie").hotkey.ss58_address,
            CohortHistoryHTTPClient(client, "https://owner.example", token="h" * 32),
        )
        reviewer = EvaluationSuiteAdoptionReviewer(
            h.series,
            h.policy,
            h,
            history,
            EvaluationSuiteReservationReader(
                client,
                "https://owner.example",
                token="h" * 32,
                owner=wallet("Charlie").hotkey.ss58_address,
            ),
            candidates={},
        )
        if changed == "finality":
            h.block = proposal.transition.observed_at_block - 1
        with pytest.raises(ValueError, match=r"owned finality|independently selected"):
            await reviewer(proposal.transition)


@pytest.mark.parametrize("damage", ["missing", "reference", "relaxed_signers"])
async def test_owner_cannot_prepare_proposal_without_bound_reference_qualification(
    candidate, damage
):
    import json

    c = candidate
    manifest_path = c.root / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    row = manifest["selected_provenance"][0]
    path = c.root / "reference-qa" / (row["reference_qa_sha256"] + ".json")
    if damage == "missing":
        path.unlink()
        with pytest.raises(FileNotFoundError):
            c.value.prepare(c.history, 220)
    elif damage == "reference":
        value = json.loads(path.read_bytes())
        value["reference_sha256"] = "f3" * 32
        path.write_bytes(canonical_json_bytes(value))
        with pytest.raises(ValueError, match="retained reference QA changes"):
            c.value.prepare(c.history, 220)
    else:
        manifest["counts"]["distinct_signer_per_case"] = False
        manifest_path.write_bytes(canonical_json_bytes(manifest))
        with pytest.raises(ValueError, match="distinct known signers"):
            c.value.prepare(c.history, 220)
    assert c.calls == []


@pytest.mark.parametrize(
    "interval",
    [
        {"kind": "publisher_labeled_clip", "start": 0, "end": 1000},
        {"kind": "source_milliseconds", "start": 1000, "end": 1000},
        {"kind": "source_frames", "start": 10, "end": 20},
        {
            "kind": "source_frames",
            "start": 10,
            "end": 20,
            "fps_numerator": 30,
            "fps_denominator": 1,
        },
        {"kind": "source_milliseconds", "start": 1.5, "end": 2000},
    ],
)
def test_reference_intervals_refuse_ambiguous_bounds_and_assumed_fps(interval):
    with pytest.raises(ValueError):
        SuiteReferenceInterval.model_validate(interval)


@pytest.mark.parametrize("kind", ["prepare", "reserve"])
@pytest.mark.parametrize("changed", ["none", "tip", "input"])
async def test_first_qualification_keeps_owner_locks_free_and_rechecks_only_bound_identities(
    suite_api, monkeypatch, kind, changed
):
    import threading

    from .test_competition_cohort_recovery import signed_transition

    h = suite_api
    c = h.candidate
    transition = c.value._proposal(c.history, 220, *c.value.selection())
    request = (
        prepare_request(h)
        if kind == "prepare"
        else EvaluationSuiteAdoptionProposal(
            schema="umi-evaluation-suite-adoption-proposal/1",
            series_sha256=digest(h.series),
            transition=transition,
        )
    )
    method = "prepare_qualified" if kind == "prepare" else "qualify"
    native = getattr(c.value, method)
    entered, release = threading.Event(), threading.Event()

    def paused(*args):
        result = native(*args)
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test failed to release qualified candidate")
        return result

    async def check_owner_locks():
        async with h.node.serial, h.node.controller.serial, h.node.controller.sampling_lock:
            assert h.intake.pending_policy_adoption(h.cohort) is None
            if changed == "tip":
                other = prepare_request_tail_adoption_at_block(c.history, h.policy, 220)
                h.store.commit(signed_transition(other))
            elif changed == "input":
                path = c.root / "videos" / (c.suite.cases[0].video_sha256 + ".mp4")
                path.write_bytes(b"changed after exact independent qualification")

    monkeypatch.setattr(c.value, method, paused)
    task = asyncio.create_task(EvaluationSuiteAdoptionOwner(h.host, kind).respond(request))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        await asyncio.wait_for(check_owner_locks(), timeout=1)
    finally:
        release.set()
    if changed == "none":
        result = EvaluationSuiteAdoptionProposal.model_validate_json(await task)
        assert result.transition == transition and len(c.calls) == len(c.suite.cases)
    else:
        with pytest.raises(
            ValueError, match=r"predecessor|control tip|qualified suite inputs changed"
        ):
            await task
        assert h.intake.pending_policy_adoption(h.cohort) is None


async def test_native_adoption_refuses_missing_four_category_minimums(candidate):
    import json

    path = candidate.root / "manifest.json"
    report = json.loads(path.read_bytes())
    report["counts"].pop("fingerspelling_category_minimums")
    path.write_bytes(canonical_json_bytes(report))
    with pytest.raises(ValueError, match="explicit four-category"):
        candidate.value.prepare(candidate.history, 220)
    assert candidate.calls == []


async def test_native_qa_requires_the_declared_fingerspelling_category_not_only_valid_hash(
    candidate,
):
    from umi.competition_suite_selection import (
        SuiteCandidateInventory,
        SuiteSelectionCounts,
        select_future_suite,
    )

    c = candidate
    inventory = c.value._document(c.config.inventory_file, SuiteCandidateInventory)
    target = inventory.cases[0]
    qa_path = c.root / "reference-qa" / (target.reference_qa_sha256 + ".json")
    qa = c.value._document(qa_path, SuiteReferenceQA).model_copy(
        update={"fingerspelling_category": "sentence"}
    )
    publish_private_model(c.root / "reference-qa" / (digest(qa) + ".json"), qa)
    replacement = target.model_copy(update={"reference_qa_sha256": digest(qa)})
    inventory = inventory.model_copy(update={"cases": (replacement, *inventory.cases[1:])})
    (c.root / "inventory.json").write_bytes(canonical_json_bytes(inventory))
    manifest = c.value._document(c.config.selection_manifest_file)
    counts = SuiteSelectionCounts.model_validate(manifest["counts"])
    from umi.competition_suite_selection import SuiteExclusions

    exclusions = c.value._document(c.config.exclusions_file, SuiteExclusions)
    _, report = select_future_suite(
        inventory, exclusions, counts, c.value.policy, selection_key=(c.root / "key").read_bytes()
    )
    (c.root / "manifest.json").write_bytes(canonical_json_bytes(report))
    with pytest.raises(ValueError, match="retained reference QA changes"):
        c.value.prepare(c.history, 220)
    assert c.calls == []
