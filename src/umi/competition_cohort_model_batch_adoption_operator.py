"""Resumable operator composition for one prospective batch-format adoption.

No wallet is opened here. Reviewer HTTP votes use the owner's configured peers;
private selection publication runs under each selected service account. The
owner is selected last. File delivery is not a claim of runtime activation.
"""

from __future__ import annotations

import ast
import fcntl
import json
import os
import pwd
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_intake import CohortIntakeBinding
from .competition_cohort_model_batch import (
    SignedModelBatchCertificationAdoption,
    prepare_model_batch_certification_adoption,
    verify_model_batch_certification_adoption,
)
from .competition_cohort_model_batch_adoption import (
    ModelBatchAdoptionReviewRequest,
    ModelBatchAdoptionVote,
    check_model_batch_adoption_vote,
)
from .competition_cohort_model_review_http import ModelReviewPeer
from .competition_cohort_recovery import Block
from .competition_cohort_review_config import PhaseReviewServiceConfig
from .competition_cohort_review_http import _credential
from .competition_host_activation import _read_root_control_path
from .competition_service import CompetitionServiceConfig
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import (
    Directory,
    ensure_private_directory,
    lock_private_file,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ModelBatchAdoptionRefused(ValueError):
    """A specific non-sensitive refusal that operator diagnostics may retain."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason_code = re.sub(r"[^a-z0-9]+", "_", reason.lower()).strip("_")[:256]


class ModelBatchAdoptionTarget(StrictProtocolModel):
    role: Literal["owner", "reviewer"]
    service_unit: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_.@-]+\.service$")]
    service_account: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,63}$")]
    config_path: Directory
    config_sha256: Hex32


class ModelBatchAdoptionOperatorConfig(StrictProtocolModel):
    schema_: Literal["umi-model-batch-adoption-operator/1"] = Field(alias="schema")
    state_directory: Directory
    policy_file: Directory
    history_file: Directory
    expected_tip_sha256: Hex32
    effective_at_block: Block
    operator_request_reference: Annotated[str, Field(min_length=1, max_length=2048)]
    owner: ModelBatchAdoptionTarget
    reviewers: Annotated[tuple[ModelBatchAdoptionTarget, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def distinct_targets(self):
        targets = (self.owner, *self.reviewers)
        if self.owner.role != "owner" or any(t.role != "reviewer" for t in self.reviewers):
            raise ModelBatchAdoptionRefused(
                "batch adoption targets require one owner and explicit reviewers"
            )
        if any(
            len({getattr(t, field) for t in targets}) != len(targets)
            for field in ("service_unit", "config_path")
        ):
            raise ModelBatchAdoptionRefused(
                "batch adoption targets repeat a selected service or configuration"
            )
        return self


class ModelBatchAdoptionOperatorPlan(StrictProtocolModel):
    config: ModelBatchAdoptionOperatorConfig
    policy_sha256: Hex32
    history_sha256: Hex32
    request: ModelBatchAdoptionReviewRequest


class ModelBatchAdoptionOperatorCompletion(StrictProtocolModel):
    status: Literal["signed_selection_published"] = "signed_selection_published"
    cohort_sha256: Hex32
    adoption_sha256: Hex32
    signed_sha256: Hex32
    reviewer_votes: Annotated[int, Field(ge=1, le=64)]
    selected_consumers: Annotated[int, Field(ge=2, le=65)]
    runtime_activation_verified: Literal[False] = False


@dataclass(frozen=True)
class SelectedBatchAdoptionTarget:
    target: ModelBatchAdoptionTarget
    directory: Path
    policy_sha256: str
    cohorts: tuple[CohortIntakeBinding, ...]
    signer: str | None = None
    peers: tuple = ()
    cohort_sequences: tuple[tuple[str, int], ...] = ()


def load_adoption_target(target):
    raw = _read_root_control_path(Path(target.config_path), 8 * 1024**2, modes={0o444})
    kind = CompetitionServiceConfig if target.role == "owner" else PhaseReviewServiceConfig
    config = kind.model_validate_json(raw)
    if canonical_json_bytes(config) != raw or digest(config) != target.config_sha256:
        raise ModelBatchAdoptionRefused("batch adoption selected configuration changed")
    if target.role == "owner":
        host = config.recoverable_service
        intake = config.recoverable_intake
        if host is None or intake is None:
            raise ModelBatchAdoptionRefused("batch adoption owner lacks supported service intake")
        directory = host.batch_certification_adoptions_directory
        result = SelectedBatchAdoptionTarget(
            target,
            Path(directory or "/"),
            config.policy_sha256,
            intake.cohorts,
            peers=host.model_review_peers,
            cohort_sequences=tuple((digest(plan), plan.sequence) for plan in host.series.cohorts),
        )
    else:
        model = config.model_signing
        if model is None:
            raise ModelBatchAdoptionRefused("batch adoption reviewer lacks model signing")
        directory = model.batch_certification_adoptions_directory
        result = SelectedBatchAdoptionTarget(
            target,
            Path(directory or "/"),
            digest(config.policy),
            model.cohorts,
            signer=model.signer,
        )
    if directory is None:
        raise ModelBatchAdoptionRefused(
            "batch adoption directory is not selected in installed configuration"
        )
    return result


def _startup_arguments(argv):
    """Read the supported maintenance wrapper's literal argv without executing it."""
    if "-c" not in argv:
        return argv
    index = argv.index("-c")
    if index + 1 >= len(argv):
        raise ModelBatchAdoptionRefused("incomplete selected Python startup")
    candidates = []
    for node in ast.walk(ast.parse(argv[index + 1])):
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(t, ast.Attribute)
            and isinstance(t.value, ast.Name)
            and t.value.id == "sys"
            and t.attr == "argv"
            for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ModelBatchAdoptionRefused("unsupported selected startup argv")
            candidates.append(value)
    if len(candidates) != 1:
        raise ModelBatchAdoptionRefused(
            "selected startup does not expose one supported configuration argv"
        )
    return candidates[0]


def check_target_process(target):
    raw = subprocess.check_output(
        [
            "systemctl",
            "show",
            target.service_unit,
            "-p",
            "User",
            "-p",
            "MainPID",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
        ],
        timeout=10,
        text=True,
    )
    state = dict(line.split("=", 1) for line in raw.splitlines())
    if (
        state.get("User") != target.service_account
        or state.get("ActiveState") != "active"
        or state.get("SubState") != "running"
    ):
        raise ModelBatchAdoptionRefused(
            "batch adoption target is not running under its selected service account"
        )
    pid = int(state.get("MainPID", "0"))
    if pid <= 0:
        raise ModelBatchAdoptionRefused("batch adoption target has no selected process")
    with Path(f"/proc/{pid}/cmdline").open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ModelBatchAdoptionRefused("selected process arguments exceed the metadata bound")
    args = _startup_arguments([part.decode() for part in raw.split(b"\0") if part])
    if args.count("--config") != 1 or args[args.index("--config") + 1 :] == []:
        raise ModelBatchAdoptionRefused("selected process does not expose its configuration")
    if args[args.index("--config") + 1] != target.config_path:
        raise ModelBatchAdoptionRefused(
            "batch adoption configuration is not selected by the running process"
        )
    return {
        "service_unit": target.service_unit,
        "pid": pid,
        "service_account": target.service_account,
        "config_sha256": target.config_sha256,
    }


def publish_for_actor(target, request, signed=None, *, check_only=False):
    """Actor-side check/publication; never changes ownership or existing bytes."""
    if pwd.getpwuid(os.getuid()).pw_name != target.service_account:
        raise ModelBatchAdoptionRefused(
            "batch adoption publication must use the selected service account"
        )
    check_target_process(target)
    selected = load_adoption_target(target)
    adoption = request.adoption
    if selected.policy_sha256 != adoption.policy_sha256 or not any(
        c.cohort_sha256 == adoption.cohort_sha256
        and c.authority_sha256 == adoption.authority_sha256
        for c in selected.cohorts
    ):
        raise ModelBatchAdoptionRefused("batch adoption publication is outside selected authority")
    ensure_private_directory(selected.directory, create=not check_only)
    candidate = selected.directory / (adoption.cohort_sha256 + ".candidate.json")
    final = selected.directory / (adoption.cohort_sha256 + ".json")
    if candidate.exists() or candidate.is_symlink():
        if (
            read_private_model(candidate, ModelBatchAdoptionReviewRequest, maximum_bytes=65536)
            != request
        ):
            raise ModelBatchAdoptionRefused(
                "batch adoption changes the retained operator candidate"
            )
    elif signed is not None:
        raise ModelBatchAdoptionRefused(
            "batch adoption selection lost its original candidate; repair required"
        )
    existing = None
    if final.exists() or final.is_symlink():
        existing = read_private_model(
            final, SignedModelBatchCertificationAdoption, maximum_bytes=65536
        )
        if existing.adoption != adoption or (signed is not None and existing != signed):
            raise ModelBatchAdoptionRefused("batch adoption changes an existing signed selection")
    if signed is not None and signed.adoption != adoption:
        raise ModelBatchAdoptionRefused("batch adoption publication changes its reserved body")
    if not check_only:
        publish_private_model(candidate, request, maximum_bytes=65536)
        if signed is not None:
            publish_private_model(final, signed, maximum_bytes=65536)
    actual = existing if check_only else (signed or existing)
    return {
        "role": target.role,
        "config_sha256": target.config_sha256,
        "candidate_sha256": digest(request),
        "selected_sha256": None if actual is None else digest(actual),
    }


def actor_publication(target, request, signed=None, *, check_only=False):
    # Source-maintenance deployments use the already selected qualified source
    # with an installed isolated interpreter. Keep that exact module source in
    # the child; do not import from its cwd or mutate the interpreter's tree.
    module = "umi.competition_cohort_model_batch_adoption_cli"
    source = str(Path(__file__).resolve().parents[1])
    code = (
        "import runpy,sys;sys.path.insert(0," + repr(source) + ");"
        "sys.argv=["
        + repr(module)
        + ",'publish'];runpy.run_module("
        + repr(module)
        + ",run_name='__main__')"
    )
    payload = {
        "target": target.model_dump(mode="json"),
        "request": request.model_dump(mode="json", by_alias=True),
        "signed": None if signed is None else signed.model_dump(mode="json", by_alias=True),
        "check_only": check_only,
    }
    command = [sys.executable, "-I", "-B", "-c", code]
    if pwd.getpwuid(os.getuid()).pw_name != target.service_account:
        command = ["sudo", "-n", "-u", target.service_account, "--", *command]
    result = subprocess.run(
        command, input=canonical_json_bytes(payload), capture_output=True, timeout=30
    )
    if len(result.stdout) > 16384:
        raise ModelBatchAdoptionRefused("batch adoption actor response exceeds its bound")
    try:
        response = json.loads(result.stdout)
    except ValueError:
        raise ModelBatchAdoptionRefused("batch adoption actor response is invalid") from None
    if result.returncode:
        reason = response.get("reason_code") if isinstance(response, dict) else None
        if not isinstance(reason, str) or re.fullmatch(r"[a-z0-9_]{1,256}", reason) is None:
            reason = "actor_private_validation_failed"
        raise ModelBatchAdoptionRefused("batch adoption actor publication refused " + reason)
    return response


def _selected_targets(config, policy, request):
    targets = tuple(load_adoption_target(t) for t in (config.owner, *config.reviewers))
    owner, *reviewers = targets
    peers = {identity(peer.signer): peer for peer in owner.peers}
    if len(peers) != len(owner.peers) or set(peers) != {identity(t.signer) for t in reviewers}:
        raise ModelBatchAdoptionRefused(
            "batch adoption must include every configured model reviewer exactly once"
        )
    if len({identity(t.signer) for t in reviewers}) != len(reviewers):
        raise ModelBatchAdoptionRefused("batch adoption repeats a reviewer identity")
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    if (
        not set(peers) <= set(groups)
        or len({groups[key] for key in peers}) < policy.required_evaluator_groups
    ):
        raise ModelBatchAdoptionRefused(
            "batch adoption configured reviewers cannot supply the policy quorum"
        )
    roots = [Path(config.state_directory), *(t.directory for t in targets)]
    if any(
        a == b or a in b.parents or b in a.parents
        for n, a in enumerate(roots)
        for b in roots[n + 1 :]
    ):
        raise ModelBatchAdoptionRefused(
            "batch adoption operator and service selection directories must be disjoint"
        )
    for target in targets:
        if target.policy_sha256 != digest(policy) or not any(
            c.cohort_sha256 == request.adoption.cohort_sha256
            and c.authority_sha256 == request.adoption.authority_sha256
            for c in target.cohorts
        ):
            raise ModelBatchAdoptionRefused(
                "batch adoption targets differ on policy or cohort authority"
            )
        check_target_process(target.target)
    return targets, peers


async def run_model_batch_adoption(
    config,
    policy,
    history,
    *,
    client,
    publish=actor_publication,
    select=_selected_targets,
    peer_factory=ModelReviewPeer,
):
    """Prepare, retain votes and deliver selections idempotently; owner is last."""
    request = ModelBatchAdoptionReviewRequest(
        adoption=prepare_model_batch_certification_adoption(
            history,
            policy,
            expected_tip_sha256=config.expected_tip_sha256,
            effective_at_block=config.effective_at_block,
        ),
        operator_request_reference=config.operator_request_reference,
    )
    targets, peers = await run_owned_thread(select, config, policy, request)
    state, cohort = Path(config.state_directory), request.adoption.cohort_sha256
    await run_owned_thread(ensure_private_directory, state)
    # Nonblocking flock and bounded local metadata only: acquire synchronously
    # so cancellation cannot discard a returned, still-locked descriptor.
    lock = lock_private_file(state / ".operator.lock")
    try:
        with (
            work_heartbeats(),
            WorkProgress(
                "model_batch_adoption",
                1 + len(targets) * 2 + len(peers),
                unit="steps",
                cohort=cohort,
                estimate=False,
                planning_range_seconds=(
                    0,
                    60 * len(targets) + sum(p.timeout_seconds for p in peers.values()),
                ),
                planning_basis="planning_configured_peer_timeouts_and_two_30_second_publications_per_target",
            ) as progress,
        ):
            plan = ModelBatchAdoptionOperatorPlan(
                config=config,
                policy_sha256=digest(policy),
                history_sha256=digest(history),
                request=request,
            )
            if not (state / "plan.json").exists() and any(
                path.exists() or path.is_symlink()
                for path in (
                    state / "signed.json",
                    *(state / ("vote-" + key + ".json") for key in peers),
                )
            ):
                raise ModelBatchAdoptionRefused(
                    "batch adoption retained votes lost their operator plan; repair required"
                )
            await run_owned_thread(publish_private_model, state / "plan.json", plan)
            progress.advance()
            signed_path = state / "signed.json"
            signed = None
            if signed_path.exists() or signed_path.is_symlink():
                signed = await run_owned_thread(
                    read_private_model, signed_path, SignedModelBatchCertificationAdoption
                )
                if signed.adoption != request.adoption:
                    raise ModelBatchAdoptionRefused(
                        "batch adoption retained certificate changed its original request"
                    )
                verify_model_batch_certification_adoption(
                    signed, history, policy, maximum_block=config.effective_at_block
                )
            for target in targets:
                receipt = await run_owned_thread(
                    lambda t=target: publish(t.target, request, signed, check_only=True)
                )
                if signed is None and receipt.get("selected_sha256") is not None:
                    raise ModelBatchAdoptionRefused(
                        "selected batch adoption lost operator certificate; repair required"
                    )
            for target in targets:
                await run_owned_thread(publish, target.target, request)
                progress.advance()
            votes = []
            for account, peer in sorted(peers.items()):
                path = state / ("vote-" + account + ".json")
                if path.exists() or path.is_symlink():
                    vote = await run_owned_thread(read_private_model, path, ModelBatchAdoptionVote)
                elif signed is not None:
                    raise ModelBatchAdoptionRefused(
                        "signed batch adoption lost a configured vote; repair required"
                    )
                else:
                    token = await run_owned_thread(
                        lambda p=peer: _credential(
                            _read_root_control_path(Path(p.token_file), 257, modes={0o400, 0o440})
                            .decode("ascii")
                            .removesuffix("\n")
                        )
                    )
                    remote = peer_factory(
                        client,
                        peer.origin,
                        policy=policy,
                        cohorts=targets[0].cohorts,
                        signer=peer.signer,
                        token=token,
                        timeout_seconds=peer.timeout_seconds,
                    )
                    vote = await remote.attest_batch_adoption(request)
                    check_model_batch_adoption_vote(vote, request, policy, signer=peer.signer)
                    await run_owned_thread(publish_private_model, path, vote)
                check_model_batch_adoption_vote(vote, request, policy, signer=peer.signer)
                votes.append(vote)
                progress.advance()
            groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
            chosen, seen = [], set()
            for vote in votes:
                group = groups[identity(vote.signature.hotkey)]
                if group not in seen:
                    chosen.append(vote.signature)
                    seen.add(group)
            expected = SignedModelBatchCertificationAdoption(
                adoption=request.adoption, signatures=tuple(chosen)
            )
            verify_model_batch_certification_adoption(
                expected, history, policy, maximum_block=config.effective_at_block
            )
            if signed is not None and signed != expected:
                raise ModelBatchAdoptionRefused(
                    "batch adoption certificate differs from retained configured votes"
                )
            signed = expected
            await run_owned_thread(publish_private_model, signed_path, signed)
            # Reviewers first. An interrupted delivery cannot enable the owner
            # before every selected independent reviewer has the exact envelope.
            for target in (*targets[1:], targets[0]):
                receipt = await run_owned_thread(publish, target.target, request, signed)
                if receipt.get("selected_sha256") != digest(signed):
                    raise ModelBatchAdoptionRefused(
                        "batch adoption publication failed its exact readback"
                    )
                progress.advance()
            completion = ModelBatchAdoptionOperatorCompletion(
                cohort_sha256=cohort,
                adoption_sha256=digest(request.adoption),
                signed_sha256=digest(signed),
                reviewer_votes=len(votes),
                selected_consumers=len(targets),
            )
            await run_owned_thread(publish_private_model, state / "completion.json", completion)
            return completion.model_dump(mode="json")
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
