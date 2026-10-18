"""Actual retained signed C5 history/approval with explicitly synthetic native ports."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_validator_supervisor_adapters import _config
from umi import validator_supervisor_cli as cli
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
    COMMON_SUPERVISOR_CHANNELS,
    COMMON_SUPERVISOR_RELEASE_ORIGIN,
    SupervisorAuthority,
    parse_canonical_supervisor_directive_page,
)
from umi.validator_supervisor_adapters import ValidatorSupervisorAdapterError
from umi.validator_supervisor_preflight import prepare_common_activation

FIXTURES = Path(__file__).parent / "fixtures/validator-supervisor"
HISTORY = (FIXTURES / "c5-reference-history24-amd64.json").read_bytes()
APPROVAL = (FIXTURES / "c5-reference-approval.json").read_bytes()
PAGE = parse_canonical_supervisor_directive_page(HISTORY)


class ApprovalHTTP:
    def __init__(self, raw=APPROVAL):
        self.raw = raw
        self.requests = []

    async def fetch_bytes(self, url, *, maximum_bytes):
        self.requests.append((url, maximum_bytes))
        return self.raw


@pytest.mark.asyncio
async def test_actual_retained_translation_approval_and_original_clocks_are_supported():
    http = ApprovalHTTP()
    activation = await prepare_common_activation(PAGE.head, https=http)
    assert activation.mode == "translation_weights" and activation.sequence == 24
    assert activation.directive_sha256 == PAGE.head.directive_sha256
    assert activation.valid_from_block == PAGE.head.directive.valid_from_block
    assert activation.valid_through_block == 9317800
    assert activation.operator_inputs is None
    assert http.requests == [
        (
            COMMON_SUPERVISOR_RELEASE_ORIGIN
            + "/validator-supervisor/translation-reference-policies/"
            + PAGE.head.directive.policy_sha256
            + ".json",
            16384,
        )
    ]


@pytest.mark.asyncio
async def test_retained_registration_bridge_remains_supported_without_reference_fetch():
    http = ApprovalHTTP()
    activation = await prepare_common_activation(PAGE.directives[-2], https=http)
    assert activation.mode == "bootstrap_service_weights" and activation.sequence == 23
    assert activation.operator_inputs == PAGE.directives[-2].directive.operator_inputs
    assert http.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["body", "signature", "malformed"])
async def test_invalid_reference_approval_never_becomes_a_preflight_activation(change):
    data = json.loads(APPROVAL)
    if change == "body":
        data["policy"]["expected_row_sha256"] = "f" * 64
    if change == "signature":
        data["signature"] = "0x" + "00" * 64
    http = ApprovalHTTP(b"{" if change == "malformed" else canonical_json_bytes(data))
    with pytest.raises(
        ValidatorSupervisorAdapterError, match="common_switch_reference_approval_invalid"
    ):
        await prepare_common_activation(PAGE.head, https=http)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "hold"),
        ("policy_sha256", None),
        ("release", None),
        ("operator_inputs", PAGE.directives[-2].directive.operator_inputs),
    ],
)
async def test_unsupported_profile_mixtures_refuse_before_network(field, value):
    signed = PAGE.head.model_copy(
        update={"directive": PAGE.head.directive.model_copy(update={field: value})}
    )
    http = ApprovalHTTP()
    with pytest.raises(ValidatorSupervisorAdapterError, match="common_switch_release_required"):
        await prepare_common_activation(signed, https=http)
    assert http.requests == []


def install_ports(monkeypatch, tmp_path, *, approval=APPROVAL, active=False, refresh=None):
    config = _config(tmp_path).model_copy(
        update={
            "channel_id": COMMON_SUPERVISOR_CHANNELS["linux/amd64"],
            "trusted_authorities": [
                SupervisorAuthority(
                    hotkey=COMMON_SUPERVISOR_AUTHORITY_HOTKEY, signature_scheme="sr25519"
                )
            ],
            "release_origins": [COMMON_SUPERVISOR_RELEASE_ORIGIN],
        }
    )
    events = []
    http = ApprovalHTTP(approval)
    height = PAGE.head.directive.valid_from_block + 10
    native = iter([height, height + 1 if refresh is None else refresh])

    class Adapter:
        def __init__(self, _config):
            self.https = http

        async def check_host(self):
            events.append("host")

        async def public_status(self):
            return {"managed_container_present": active}

        async def preflight_activation(self, *, activation):
            assert http.requests and activation.sequence == 24
            events.append("stage")

        async def stop_worker(self):
            raise AssertionError("preflight cannot stop a worker")

    class Fetcher:
        def __init__(self, _config):
            pass

        async def fetch_directive_page(self, *, after_sequence, after_directive_sha256):
            assert after_sequence == 0 and after_directive_sha256 is None
            events.append("history")
            return HISTORY

    class Native:
        def __init__(self, _config):
            pass

        async def read_finalized_block(self):
            events.append("native")
            return next(native)

        async def stop(self):
            events.append("native_closed")

    monkeypatch.setattr(cli, "load_validator_supervisor_config", lambda _path: config)
    monkeypatch.setattr(cli, "_validate_linux_systemd_profile", lambda _config: None)
    monkeypatch.setattr(cli, "RootlessPodmanWorkerAdapter", Adapter)
    monkeypatch.setattr(cli, "HTTPSDirectiveFetcher", Fetcher)
    monkeypatch.setattr(cli, "FinneyFinalizedBlockReader", Native)

    def never(*_args, **_kwargs):
        raise AssertionError("preflight cannot write state or load signer")

    monkeypatch.setattr("umi.validator_supervisor.store_supervisor_directive_state", never)
    monkeypatch.setattr(cli, "_load_signer", never)
    return events, http


@pytest.mark.asyncio
async def test_complete_actual_signed_prefix_preflights_translation_without_state_or_signing(
    monkeypatch,
    tmp_path,
    capsys,
):
    events, _http = install_ports(monkeypatch, tmp_path)
    result = await cli._preflight_common_switch(tmp_path / "unused-config")
    assert result["sequence"] == 24 and result["status"] == "common_switch_preflight_ok"
    assert result["mode"] == "translation_weights"
    assert result["directive_sha256"] == PAGE.head.directive_sha256
    assert events == ["host", "native", "history", "stage", "native", "native_closed"]
    progress = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    history = [v for v in progress if v["stage"] == "common_switch_directive_history"]
    assert history[-1]["completed"] == history[-1]["total"] == 24
    assert history[-1]["percent"] == 100 and history[-1]["eta_seconds"] == 0
    assert progress[-1]["stage"] == "common_switch_finality_refresh"
    assert all("elapsed_seconds" in v and "eta_basis" in v and "stalled" in v for v in progress)


@pytest.mark.asyncio
async def test_forged_approval_refuses_before_image_staging_and_closes_native_owner(
    monkeypatch, tmp_path
):
    events, _http = install_ports(monkeypatch, tmp_path, approval=b"{}")
    with pytest.raises(
        ValidatorSupervisorAdapterError, match="common_switch_reference_approval_invalid"
    ):
        await cli._preflight_common_switch(tmp_path / "unused")
    assert events == ["host", "native", "history", "native_closed"]


@pytest.mark.asyncio
async def test_existing_managed_worker_is_not_stopped_or_replaced(monkeypatch, tmp_path):
    events, http = install_ports(monkeypatch, tmp_path, active=True)
    with pytest.raises(
        ValidatorSupervisorAdapterError, match="common_switch_managed_container_present"
    ):
        await cli._preflight_common_switch(tmp_path / "unused")
    assert events == ["host"] and http.requests == []


@pytest.mark.asyncio
async def test_slow_staging_does_not_bypass_original_signed_horizon(monkeypatch, tmp_path):
    events, _http = install_ports(
        monkeypatch, tmp_path, refresh=PAGE.head.directive.valid_through_block + 1
    )
    with pytest.raises(
        ValidatorSupervisorAdapterError, match="common_switch_release_headroom_invalid"
    ):
        await cli._preflight_common_switch(tmp_path / "unused")
    assert events[-1] == "native_closed"


@pytest.mark.parametrize(
    "mode,legacy,revision,allowed",
    [
        ("translation_weights", "", "f" * 40, True),
        ("translation_weights", "old-writer.service", "f" * 40, False),
        ("bootstrap_service_weights", "old-writer.service", "f" * 40, True),
        (None, "old-writer.service", "5f9d189f819f5fca7572dd830ab080730edefe7e", True),
        (None, "", "f" * 40, False),
        ("hold", "", "f" * 40, False),
    ],
)
def test_installer_refuses_foreign_translation_retirement_with_old_result_compatibility(
    tmp_path,
    mode,
    legacy,
    revision,
    allowed,
):
    receipt = tmp_path / "preflight.json"
    value = dict(status="common_switch_preflight_ok", initial_hold_verified=True, sequence=24)
    if mode is not None:
        value["mode"] = mode
    receipt.write_text(json.dumps(value))
    receipt.chmod(0o600)
    script = (
        Path(__file__).resolve().parents[1]
        / "deploy/linux-validator-supervisor/preflight-cutover.py"
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--preflight",
            str(receipt),
            "--release-revision",
            revision,
            "--legacy-unit",
            legacy,
        ],
        capture_output=True,
    )
    assert completed.returncode == (0 if allowed else 2)
    if mode == "translation_weights" and legacy:
        assert b"translation_legacy_retirement_requires_preserving_migration" in completed.stderr


def test_installer_guard_precedes_any_legacy_retirement_or_runtime_smoke():
    script = (
        Path(__file__).resolve().parents[1] / "deploy/linux-validator-supervisor/install.sh"
    ).read_text()
    guard = script.index("preflight-cutover.py")
    assert guard < script.index('systemctl disable --now "$legacy_unit"')
    assert guard < script.index("# Rehearse the exact production unit name")
