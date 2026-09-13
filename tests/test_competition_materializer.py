from __future__ import annotations

import os
import shutil
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_chain_state as chain
from umi import competition_host_activation as activation
from umi import competition_host_anchor as anchor_module
from umi import competition_materialization as material
from umi import competition_materializer as adapter
from umi.competition_supervisor_adapters import SuccessorArtifactFiles
from umi.competition_supervisor_runtime import SuccessorWorkerSelection
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_materialization import (
    _test_exchange,
)
from .test_competition_materialization import (
    activation_case as activation_case,
)
from .test_competition_materialization import (
    anchor_case as anchor_case,
)
from .test_competition_materialization import (
    chain_config as chain_config,
)
from .test_competition_materialization import (
    explicit as explicit,
)
from .test_competition_materialization import (
    limits as limits,
)
from .test_competition_materialization import (
    package_case as package_case,
)
from .test_competition_materialization import (
    package_limits as package_limits,
)
from .test_competition_materialization import (
    policy as policy,
)
from .test_competition_materialization import (
    release_identity as release_identity,
)
from .test_competition_materialization import (
    replay_limits as replay_limits,
)
from .test_competition_materialization import (
    successor_release as successor_release,
)
from .test_competition_materialization import (
    trusted_ports as trusted_ports,
)
from .test_competition_materialization import (
    worker_capacity as worker_capacity,
)


@pytest.fixture
def case(request, monkeypatch, tmp_path):
    from . import test_competition_host_activation as activation_tests

    original = activation_tests.v3_config
    monkeypatch.setattr(
        activation_tests,
        "v3_config",
        lambda **kw: original(**kw).model_copy(
            update={"state_root": str(tmp_path / "service-private-state")}
        ),
    )
    item = request.getfixturevalue("anchor_case")
    anchor = anchor_module.materialize_successor_anchor(**item.kwargs)
    base = item.base
    selection = SuccessorWorkerSelection(base.signed)
    files = SuccessorArtifactFiles(
        release_bundle_path=tmp_path / "verified-separately.bundle",
        package_path=base.package.path,
        worker_execution_bytes=canonical_json_bytes(base.execution),
        current_directive_page_bytes=canonical_json_bytes(base.current_page),
        authorization_bytes=None,
    )
    limits = material.SuccessorCurrentMaterializationLimits(
        maximum_stages=5,
        maximum_cache_bytes=20_000_000,
        maximum_tree_entries=100,
        maximum_tree_depth=4,
    )
    staged = material.stage_successor_current(
        selection=selection,
        files=files,
        config=base.config,
        operator_consent=base.consent,
        worker_limits=base.limits,
        limits=limits,
    )
    item.source_root.chmod(0o755)
    shutil.copytree(staged.path, item.source_root / "current")
    item.source_root.chmod(0o555)
    # Explicit filesystem ports only. Real signed anchor, package, receipt,
    # rolling history and activation capabilities are verified below.
    monkeypatch.setattr(activation, "ACTIVATION_MOUNT_ROOT", item.source_root)
    if sys.platform != "linux":
        monkeypatch.setattr(material, "_exchange", _test_exchange)
    installation = activation.load_successor_worker_inputs()
    issued, fetches = [], []
    next_values = dict(
        block=180,
        block_hash="0x" + "18" * 32,
        genesis_hash=base.receipt.checkpoint_genesis_hash,
        validator_hotkey=base.config.validator_hotkey,
        validator_permit=True,
        live=True,
    )

    def mint():
        value = SimpleNamespace(**next_values)
        issued.append(value)
        return value

    def validate(value):
        # Ownership/finality verifier port uses fresh process-local identity,
        # never deserializes booleans as production observation authority.
        if not any(value is item for item in issued) or not value.live:
            raise ValueError("unowned or expired proof")

    monkeypatch.setattr(adapter, "validate_owned_weight_observation", validate)
    monkeypatch.setattr(chain, "validate_owned_weight_observation", validate)

    async def fetch(selected):
        fetches.append(selected)
        return files

    async def observe_for(selected, artifacts):
        assert selected == selection and artifacts == files
        return mint()

    delivery = SimpleNamespace(
        config=base.config, consent=base.consent, worker_limits=base.limits, fetch=fetch
    )
    observer = SimpleNamespace(observe_for=observe_for)
    value = adapter.AuthenticatedSuccessorArtifactMaterializer(
        installation=installation,
        delivery=delivery,
        observer=observer,
        config_path=item.paths.config,
        limits=limits,
    )
    return SimpleNamespace(
        item=item,
        base=base,
        anchor=anchor,
        selection=selection,
        files=files,
        staged=staged,
        installation=installation,
        value=value,
        limits=limits,
        issued=issued,
        fetches=fetches,
        mint=mint,
        next_values=next_values,
    )


async def test_fetch_never_selects_or_observes_and_reuses_stage(case):
    current = case.item.source_root / "current"
    before = current.stat().st_ino
    for _ in range(2):
        assert await case.value.fetch(case.selection) == case.files
    assert current.stat().st_ino == before
    assert case.issued == []
    assert len(case.fetches) == 2
    assert len(list(case.staged.path.parent.glob("stage-*"))) == 1
    activation.validate_authenticated_successor_installation(case.installation)


async def test_activate_returns_real_capability_after_selection_and_fresh_reload(case, monkeypatch):
    old = (case.item.source_root / "current").stat().st_ino
    initial = case.mint()
    load = adapter.load_successor_worker_inputs

    def slow_load():
        inputs = load()
        for proof in case.issued:
            proof.live = False
        return inputs

    monkeypatch.setattr(adapter, "load_successor_worker_inputs", slow_load)
    result = await case.value.activate(case.selection, case.files, owned_observation=initial)
    assert type(result) is activation.AuthenticatedSuccessorActivation
    result.recheck()
    assert result.directive_sha256 == case.selection.directive_sha256
    assert result._observation is case.issued[-1]
    assert result._observation.live and not initial.live
    assert (case.item.source_root / "current").stat().st_ino != old
    assert case.staged.path.stat().st_ino == old
    assert not hasattr(case.value, "submit")


async def test_unowned_incoming_floor_cannot_select(case):
    old = (case.item.source_root / "current").stat().st_ino
    with pytest.raises(ValueError, match="unowned"):
        await case.value.activate(
            case.selection, case.files, owned_observation=SimpleNamespace(**case.next_values)
        )
    assert (case.item.source_root / "current").stat().st_ino == old


@pytest.mark.parametrize("fault", ["permit", "rollback", "fork", "genesis", "expiry", "future"])
async def test_new_owned_observation_can_veto_before_selection(case, fault):
    old = (case.item.source_root / "current").stat().st_ino
    initial = case.mint()
    if fault == "permit":
        case.next_values["validator_permit"] = False
    elif fault == "rollback":
        case.next_values["block"] = 179
    elif fault == "fork":
        case.next_values["block_hash"] = "0x" + "99" * 32
    elif fault == "genesis":
        case.next_values["genesis_hash"] = "0x" + "99" * 32
    elif fault == "expiry":
        case.next_values["block"] = 270
    else:
        case.next_values["block"] = 170
        initial.block = 169
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        await case.value.activate(case.selection, case.files, owned_observation=initial)
    assert (case.item.source_root / "current").stat().st_ino == old


async def test_malformed_readonly_view_never_returns_authority_after_selection(case, monkeypatch):
    monkeypatch.setattr(adapter, "load_successor_worker_inputs", lambda: case.installation)
    with pytest.raises(ValueError):
        await case.value.activate(case.selection, case.files, owned_observation=case.mint())
    assert case.staged.path.exists()  # Previous current remains available for diagnosis.


async def test_stale_incoming_proof_is_not_revived(case):
    initial = case.mint()
    initial.live = False
    with pytest.raises(ValueError, match="expired"):
        await case.value.activate(case.selection, case.files, owned_observation=initial)


async def test_slow_staging_uses_new_proof_without_extending_old_lifetime(case, monkeypatch):
    stage = case.value._stage
    initial = case.mint()

    def slow(*args):
        result = stage(*args)
        initial.live = False
        return result

    monkeypatch.setattr(case.value, "_stage", slow)
    result = await case.value.activate(case.selection, case.files, owned_observation=initial)
    result.recheck()
    assert result._observation is not initial and not initial.live


async def test_slow_replay_finishes_before_final_proof_and_is_not_repeated(case, monkeypatch):
    replay = activation.load_bound_successor_replay_package
    replay_calls = []

    def slow_replay(*args, **kwargs):
        result = replay(*args, **kwargs)
        replay_calls.append(result.package_sha256)
        # Simulate the verifier clock advancing beyond all current proofs'
        # TTL during a valid, expensive replay. Do not extend any proof.
        for proof in case.issued:
            proof.live = False
        return result

    monkeypatch.setattr(activation, "load_bound_successor_replay_package", slow_replay)
    initial = case.mint()
    result = await case.value.activate(case.selection, case.files, owned_observation=initial)
    assert replay_calls == [case.files.package_path.name]
    assert not initial.live
    assert result._observation is case.issued[-1] and result._observation.live
    result.recheck()
    result.validate_retained_recovery(
        result.checkpoint_sha256,
        result.validator_hotkey,
        result.directive.previous_directive_sha256,
    )
    from umi import competition_worker_cli

    worker_activation = competition_worker_cli._activate(result._inputs, result._observation)
    worker_activation.recheck()
    assert len(replay_calls) == 1
    result._observation.live = False
    with pytest.raises(activation.HostActivationError, match="expired"):
        result.recheck()


async def test_content_mutation_during_final_capture_cannot_activate(case, monkeypatch):
    observe = case.value.observer.observe_for
    calls = 0

    async def mutate_after_capture(selection, files):
        nonlocal calls
        proof = await observe(selection, files)
        calls += 1
        if calls == 2:
            path = case.item.source_root / "current" / "package" / "policy.json"
            before = path.stat()
            body = path.read_bytes()
            path.chmod(0o600)
            path.write_bytes(b"x" * len(body))
            path.chmod(before.st_mode & 0o777)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return proof

    monkeypatch.setattr(case.value.observer, "observe_for", mutate_after_capture)
    with pytest.raises(activation.HostActivationError, match="tree changed"):
        await case.value.activate(case.selection, case.files, owned_observation=case.mint())
    assert calls == 2


async def test_activation_refresh_uses_new_proof_without_rebinding_old_one(case):
    active = await case.value.activate(case.selection, case.files, owned_observation=case.mint())
    active._observation.live = False
    fresh = case.mint()
    renewed = active.refresh(owned_observation=fresh)
    renewed.recheck()
    assert renewed._inputs is active._inputs and renewed._observation is fresh
    with pytest.raises(activation.HostActivationError, match="expired"):
        active.recheck()
    # Replacing the observation is not the same as reminting active authority.
    with pytest.raises(activation.HostActivationError, match="absent or altered"):
        replace(active, _observation=fresh).recheck()


@pytest.mark.parametrize(
    "fault", ["rollback", "fork", "expired_proof", "expired_directive", "tree"]
)
async def test_activation_refresh_cannot_bypass_freshness_or_immutable_inputs(case, fault):
    active = await case.value.activate(case.selection, case.files, owned_observation=case.mint())
    if fault == "rollback":
        case.next_values["block"] = active.finalized_block - 1
    elif fault == "fork":
        case.next_values["block_hash"] = "0x" + "99" * 32
    elif fault == "expired_proof":
        case.next_values["live"] = False
    elif fault == "expired_directive":
        case.next_values["block"] = 300
    else:
        path = case.item.source_root / "current" / "package" / "policy.json"
        path.chmod(0o600)
        path.write_bytes(b"x" * path.stat().st_size)
        path.chmod(0o400)
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        active.refresh(owned_observation=case.mint())


def test_mismatched_delivery_cannot_replace_root_controls(case):
    case.value.delivery.worker_limits = None
    with pytest.raises(adapter.SuccessorMaterializerError, match="root controls"):
        case.value._recheck()


def test_plain_document_is_not_an_installation(case):
    with pytest.raises(ValueError):
        adapter.AuthenticatedSuccessorArtifactMaterializer(
            installation=SimpleNamespace(config=case.base.config),
            delivery=case.value.delivery,
            observer=case.value.observer,
            config_path=case.item.paths.config,
            limits=case.limits,
        )
