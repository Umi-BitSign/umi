"""Run the real signed-host preflight in systemd with a synthetic OCI release.

Opt in only in the wallet-free Linux rehearsal VM. Unlike the smaller transient
unit probes, this executes the production child, verifies every signed host
file, stages a signed OCI bundle and runs the actual Podman sandbox check. It
does not stop a legacy service, collect finality, publish an anchor or run a
weight worker. Those later migration steps still need combined coverage.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as activation
from umi import competition_host_artifacts as artifacts
from umi import competition_initial_upgrade as upgrade
from umi import competition_release as releases
from umi.competition_host_bundle import HOST_BUNDLE_MAGIC, stage_successor_host_bundle
from umi.competition_package import CompetitionReleaseIdentity
from umi.competition_supervisor import (
    SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SuccessorSupervisorChainTarget,
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorReleaseTarget,
)
from umi.competition_supervisor_observer import SuccessorHostObserverConfig
from umi.competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
)
from umi.crypto import sign_response_digest
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import advance_supervisor_directive_state

from .test_competition_chain import chain_config as chain_config
from .test_competition_host_artifacts import sign as sign_host
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_service_linux import (
    _ROOT,
    _USER,
    _account,
    _as_user,
    _command,
    _owned_directory,
    _show_unit,
    _write,
)
from .test_competition_supervisor import _consent, _directive, _exact_package_target, _signed
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy
from .test_validator_supervisor import _config, _wallets
from .test_validator_supervisor import _directive as legacy_directive
from .test_validator_supervisor import _signed as legacy_signed

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("UMI_RUN_INITIAL_PREFLIGHT") != "1",
    reason="requires explicit opt-in to the wallet-free signed-host/Podman rehearsal",
)


@pytest.fixture
def oci_release():
    archive_path = Path(os.environ["UMI_REHEARSAL_OCI_ARCHIVE"])
    assert archive_path.is_absolute() and not archive_path.is_symlink()
    assert 0 < archive_path.stat().st_size < releases.MAX_SUPERVISOR_RELEASE_BUNDLE_BYTES
    archive = archive_path.read_bytes()
    with tarfile.open(archive_path) as tar:

        def document(name):
            entry = tar.getmember(name)
            assert entry.isfile() and 0 < entry.size < 1024**2
            return json.loads(tar.extractfile(entry).read())

        (descriptor,) = document("index.json")["manifests"]
        image_digest = descriptor["digest"].removeprefix("sha256:")
        image = document("blobs/sha256/" + image_digest)
        config = document("blobs/sha256/" + image["config"]["digest"].removeprefix("sha256:"))
    labels = config["config"]["Labels"]
    manifest = releases.SuccessorOCIReleaseManifest(
        schema=releases.SUCCESSOR_RELEASE_SCHEMA,
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256=image_digest,
        oci_archive_sha256=hashlib.sha256(archive).hexdigest(),
        oci_archive_size_bytes=len(archive),
        target_platform="linux/" + config["architecture"],
        umi_git_revision=labels["org.opencontainers.image.revision"],
        umi_source_tree_sha256=labels["vision.umi.source-tree-sha256"],
        entrypoint_profile=labels["vision.umi.entrypoint-profile"],
        state_schema_minimum=4,
        state_schema_maximum=4,
    )
    assert manifest.target_platform == artifacts._current_platform()
    authority = _wallets()[0]
    signature = bytes.fromhex(
        sign_response_digest(authority, releases.successor_release_signature_digest(manifest))[1][
            2:
        ]
    )
    payload = canonical_json_bytes(manifest)
    bundle = releases._header(payload, signature) + archive
    triple = {"linux/arm64": "aarch64", "linux/amd64": "x86_64"}[manifest.target_platform]
    identity = CompetitionReleaseIdentity(
        schema="umi-competition-replay-release-identity/1",
        umi_revision=manifest.umi_git_revision,
        release_manifest_sha256=hashlib.sha256(payload).hexdigest(),
        release_bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        target_triple=triple + "-unknown-linux-gnu",
    )
    target = SuccessorSupervisorReleaseTarget(
        schema="umi-successor-supervisor-release-target/1",
        release_bundle_url="https://releases.umi.vision/rehearsal/release.bundle",
        release_bundle_sha256=identity.release_bundle_sha256,
        release_bundle_size_bytes=len(bundle),
        release_manifest_sha256=identity.release_manifest_sha256,
        release_authority_hotkey=authority.hotkey.ss58_address,
        release_authority_signature_scheme="sr25519",
        replay_release_identity=identity,
        **{name: getattr(manifest, name) for name in releases._BOUND_FIELDS},
    )
    return SimpleNamespace(bundle=bundle, target=target, identity=identity)


@pytest.fixture
def release_identity(oci_release):
    return oci_release.identity


def _host_bundle(run, config):
    """Build a complete test host with no editable imports or symlinks."""
    project = Path(__file__).parents[1]
    candidate = run / "candidate"
    final = artifacts._STAGE_PARENT / secrets.token_hex(20)
    shutil.copytree(
        project / "src", candidate / "src", ignore=shutil.ignore_patterns("__pycache__")
    )
    environment = candidate / ".venv"
    _command("/usr/bin/python3", "-m", "venv", "--copies", "--without-pip", environment)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site = environment / "lib" / version / "site-packages"
    shutil.copytree(
        Path(sys.prefix) / "lib" / version / "site-packages",
        site,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "_editable*", "*.pth"),
    )
    _write(site / "umi.pth", str(final / "src") + "\n", 0o444)
    # venv creates lib64 as a convenience symlink; the signed tree never needs it.
    if (environment / "lib64").is_symlink():
        (environment / "lib64").unlink()
    for executable, module in (
        ("umi-competition-supervisor", "umi.competition_supervisor_cli"),
        ("umi-competition-supervisor-cleanup", "umi.competition_supervisor_cleanup"),
    ):
        _write(
            environment / "bin" / executable,
            f"#!{final}/.venv/bin/python -I\nfrom {module} import main\nmain()\n",
            0o555,
        )
    helpers = {
        "artifacts/umi-grandpa-finality-observer": (b"unused finality helper", 0o555),
        "artifacts/umi-substrate-proof-verifier": (b"unused proof helper", 0o555),
        "artifacts/raw_spec_finney.json": (b"unused chain spec", 0o444),
    }
    for name, (body, mode) in helpers.items():
        _write(candidate / name, body, mode)
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copyfile(project / name, candidate / name)
    files = []
    for path in sorted(candidate.rglob("*"), key=lambda p: p.relative_to(candidate).as_posix()):
        assert not path.is_symlink()
        if path.is_file():
            payload = path.read_bytes()
            files.append(
                artifacts.HostArtifactFile(
                    path=str(path.relative_to(candidate)),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size_bytes=len(payload),
                    mode=0o555 if path.stat().st_mode & 0o111 else 0o444,
                )
            )
    manifest = artifacts.SuccessorHostArtifactManifest(
        schema=artifacts.HOST_ARTIFACT_SCHEMA,
        channel_id=config.channel_id,
        umi_git_revision=final.name,
        target_platform=config.target_platform,
        host_entrypoint_profile="umi-competition-supervisor-host/1",
        total_size_bytes=sum(r.size_bytes for r in files),
        files=files,
    )
    signed = sign_host(manifest)
    bundle_path = run / "host.bundle"
    with bundle_path.open("xb") as output:
        output.write(HOST_BUNDLE_MAGIC)
        for record in files:
            output.write((candidate / record.path).read_bytes())
    bundle_path.chmod(0o400)
    artifacts._STAGE_PARENT.mkdir(mode=0o755, exist_ok=True)
    tree = stage_successor_host_bundle(
        bundle_path, signed=signed, config=config, expected_manifest_sha256=signed.manifest_sha256
    )
    return signed, tree, helpers


def _signed_preflight_case(
    run, config, oci_release, package_case, package_limits, policy, worker_capacity, chain_config
):
    host, tree, helpers = _host_bundle(run, config)
    old = legacy_signed(
        legacy_directive(
            validator_hotkeys=[config.validator_hotkey],
            release={
                **legacy_directive().release.model_dump(mode="python"),
                "target_platform": config.target_platform,
            },
        )
    )
    predecessor = SimpleNamespace(
        config=config,
        signed=old,
        body=canonical_json_bytes(old),
        state=advance_supervisor_directive_state(
            old, config=config, finalized_block=120, prior_state=None
        ),
    )
    consent = _consent(predecessor, approved_host_manifest_sha256=host.manifest_sha256)
    finality_pin = chain_config.finality_pin.model_copy(
        update={
            "release_sha256_by_target": {
                oci_release.identity.target_triple: hashlib.sha256(
                    helpers["artifacts/umi-grandpa-finality-observer"][0]
                ).hexdigest()
            },
            "chain_spec_sha256": hashlib.sha256(
                helpers["artifacts/raw_spec_finney.json"][0]
            ).hexdigest(),
        }
    )
    observer = SuccessorHostObserverConfig(
        schema="umi-successor-host-observer-config/1",
        policy=policy,
        chain=chain_config.model_copy(
            update={
                "finality_pin": finality_pin,
                "target_triple": oci_release.identity.target_triple,
                "finality_binary": str(WORKER_FINALITY_BINARY),
                "chain_spec": str(WORKER_CHAIN_SPEC),
                "proof_binary": str(WORKER_PROOF_BINARY),
                "state_directory": str(WORKER_FINALITY_STATE_ROOT),
                "proof_binary_sha256": hashlib.sha256(
                    helpers["artifacts/umi-substrate-proof-verifier"][0]
                ).hexdigest(),
            }
        ),
    )
    chain = SuccessorSupervisorChainTarget(
        schema="umi-successor-supervisor-chain-target/1",
        network="finney",
        netuid=78,
        mechanism_id=0,
        chain_pin=chain_config.chain_pin,
    )
    signed = _signed(
        _directive(
            predecessor,
            _exact_package_target(package_case, package_limits, policy),
            oci_release.target,
            chain,
            consent,
        )
    )
    page = SuccessorSupervisorDirectivePage(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_version=3,
        after_sequence=predecessor.state.accepted_sequence,
        after_directive_sha256=predecessor.state.accepted_directive_sha256,
        directives=[signed],
        more=False,
        head=signed,
    )
    limits = activation.SuccessorWorkerExecutionLimits(
        schema="umi-successor-worker-execution-limits/1",
        replay_capacity_ceiling=worker_capacity,
        maximum_weight_attempts=20,
        maximum_weight_evidence_bytes=50_000_000,
        maximum_submission_timeout_seconds=30,
    )
    controls = run / "controls"
    controls.mkdir(mode=0o700)
    for name, value in (
        (activation.SOURCE_CONFIG_FILENAME, config),
        (activation.OPERATOR_CONSENT_FILENAME, consent),
        (activation.LEGACY_SIGNED_DIRECTIVE_FILENAME, old),
        (activation.INITIAL_SUCCESSOR_DIRECTIVE_PAGE_FILENAME, page),
        (activation.SIGNED_HOST_ARTIFACT_FILENAME, host),
        (activation.WORKER_LIMITS_FILENAME, limits),
        (activation.HOST_OBSERVER_FILENAME, observer),
    ):
        _write(controls / name, canonical_json_bytes(value), 0o400)
    control = upgrade._controls(controls / activation.SOURCE_CONFIG_FILENAME, controls)
    upgrade._prestop_host_requirements(control, tree)
    bundle = run / "release.bundle"
    _write(bundle, oci_release.bundle, 0o400)
    return SimpleNamespace(control=control, tree=tree, bundle=bundle, controls=controls)


def test_signed_host_child_stages_oci_and_rehearses_without_wallet_or_service_stop(
    tmp_path, oci_release, package_case, package_limits, policy, worker_capacity, chain_config
):
    assert os.geteuid() == 0 and Path("/var/lib") in tmp_path.parents
    _ROOT.mkdir(mode=0o755, exist_ok=True)
    user = _account()
    assert _show_unit().get("ActiveState") != "active"
    run = _ROOT / ("signed-initial-" + secrets.token_hex(8))
    run.mkdir(mode=0o755)
    run.chmod(0o755)
    state, release, wallet = (run / name for name in ("state", "release", "inert-wallet"))
    for path in (state, release, wallet):
        _owned_directory(path, user)
    _write(wallet / "inert-marker", b"not a key", 0o444)
    config = _config(
        target_platform=oci_release.target.target_platform,
        state_root=str(state),
        release_root=str(release),
        worker_state_root=str(run / "unused-worker"),
        operator_input_root=str(run / "unused-input"),
        worker_cpu_millis=1000,
        worker_memory_bytes=1024**3,
        wallet={"path": str(wallet), "name": "none", "hotkey": "none"},
    )
    case = _signed_preflight_case(
        run,
        config,
        oci_release,
        package_case,
        package_limits,
        policy,
        worker_capacity,
        chain_config,
    )
    fragment = run / "preflight-base.service"
    _write(
        fragment,
        "[Service]\nExecStart=/bin/false\nWorkingDirectory=/\n"
        "ProtectSystem=strict\nProtectHome=read-only\nDelegate=true\n"
        "PrivateTmp=true\nUMask=0077\n",
    )
    _command("/usr/bin/loginctl", "enable-linger", _USER)
    _command("/usr/bin/systemctl", "start", f"user@{user.pw_uid}.service")
    before = _show_unit()
    before_containers = set(
        _as_user(
            user, "/usr/bin/podman", "--cgroup-manager=systemd", "ps", "-aq", "--no-trunc"
        ).stdout.splitlines()
    )
    upgrade._rehearse_service(
        case.control,
        user,
        {"Id": "umi-validator-supervisor.service", "FragmentPath": str(fragment)},
        case.tree,
        case.bundle,
    )
    assert _show_unit() == before
    case.tree.recheck()
    assert (wallet / "inert-marker").read_bytes() == b"not a key"
    assert not (state / "successor-v4").exists()
    assert not Path(config.worker_state_root).exists()
    assert not (state / "supervisor-process.lock").exists()
    assert any(release.iterdir())
    containers = _as_user(
        user, "/usr/bin/podman", "--cgroup-manager=systemd", "ps", "-aq", "--no-trunc"
    ).stdout
    # Retained fixtures from other interruption tests are unrelated. The probe
    # must remove its own container and leave every pre-existing one untouched.
    assert set(containers.splitlines()) == before_containers
