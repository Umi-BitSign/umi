"""Retained common bootstrap and bridge history through the native host reader."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_initial_upgrade as upgrade
from umi import competition_recovery as recovery
from umi.protocol import canonical_json_bytes
from umi.simple_bootstrap_validator import SignedSimpleBootstrapLease

from .test_competition_bridge_recovery import add_attempt, retain_old_journal
from .test_competition_host_observer import (
    chain as chain,
)
from .test_competition_host_observer import (
    chain_config as chain_config,
)
from .test_competition_host_observer import (
    inputs as inputs,
)
from .test_competition_host_observer import (
    installed as base_installed,
)
from .test_competition_host_observer import (
    observer_case as observer_case,
)
from .test_competition_host_observer import (
    owned_chain as owned_chain,
)
from .test_competition_host_observer import (
    policy as policy,
)
from .test_competition_recovery import limits as limits
from .test_registration_bridge import BLOCK, replace_participant
from .test_registration_bridge import signed_policy as signed_policy
from .test_registration_bridge_runtime import old_applied, writer_observation
from .test_simple_bootstrap_validator import _production_manifest

__all__ = ["base_installed"]


@pytest.fixture
def installed(base_installed, signed_policy, fault):
    item = base_installed
    hotkey = item.config.validator_hotkey
    wallet = SimpleNamespace(hotkey=SimpleNamespace(ss58_address=hotkey))
    signed = _production_manifest()
    # Public, expired authority bytes. Verification remains at the historical
    # preflight; this fixture grants no present-day submission permission.
    lease = SignedSimpleBootstrapLease.model_validate_json(
        (Path(__file__).parent / "fixtures/historical-simple-bootstrap-lease.json").read_bytes()
    )
    if fault == "lease_signature":
        lease = lease.model_copy(update={"signature": "0x" + "00" * 64})
    old = old_applied(wallet).model_copy(
        update={"lease_sha256": hashlib.sha256(canonical_json_bytes(lease)).hexdigest()}
    )
    files = {"service.lock": b""}
    first = add_attempt(files, signed_policy, writer_observation(wallet))
    current = add_attempt(
        files,
        signed_policy,
        replace_participant(
            writer_observation(
                wallet, block_number=BLOCK + 250, validator_row=first.attempt.expected_row
            ),
            54,
            last_update=first.weight_call.block_number,
        ),
    )
    retain_old_journal(SimpleNamespace(files=files), old)
    root = Path(item.config.worker_state_root)
    root.mkdir(mode=0o700, exist_ok=True)
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)
    item.history = SimpleNamespace(
        files=files, signed=signed, lease=lease, old=old, current=current
    )
    return item


@pytest.mark.parametrize(
    "fault", [None, "missing_anchor", "wrong_anchor", "missing_context", "lease_signature"]
)
async def test_common_receipt_and_bridge_history_require_owned_historical_anchor(
    observer_case, limits, fault
):
    item = observer_case
    hotkey = item.stopped.validator_hotkey
    history = item.installed.history
    files, signed, lease, old, current = (
        getattr(history, name) for name in ("files", "signed", "lease", "old", "current")
    )
    root = item.stopped.worker_state_root
    item.chain.finality.ref = replace(
        item.chain.finality.ref, block_number=BLOCK + 300, block_hash="0x" + "de" * 32
    )
    item.chain.rpc.values[("SubtensorModule", "LastUpdate", (78,))][54] = (
        current.weight_call.block_number
    )
    item.chain.rpc.values[("SubtensorModule", "Weights", (78, 54))] = current.attempt.expected_row
    commitment = {
        "block": old.manifest_anchor_block,
        "info": {
            "fields": [
                {
                    "Sha256": "0x"
                    + ("ff" * 32 if fault == "wrong_anchor" else signed.manifest_sha256)
                }
            ]
        },
    }
    item.chain.rpc.values[("Commitments", "CommitmentOf", (78, hotkey))] = (
        None if fault == "missing_anchor" else commitment
    )
    manifests, leases = ((), ()) if fault == "missing_context" else ((signed,), (lease,))
    observer = item.build()
    try:
        if fault == "lease_signature":
            with pytest.raises(ValueError, match="lease signature is invalid"):
                await upgrade._observe_stopped_history(
                    item.stopped, observer, limits, manifests, leases
                )
            assert not item.providers
            return
        observation, bridge_observation = await upgrade._observe_stopped_history(
            item.stopped, observer, limits, manifests, leases
        )
        # V1 terminal bridge history needs the fresh current row. No v2 receipt
        # capability or synthetic owned observation is injected in this test.
        assert bridge_observation is None
        with recovery.snapshot_legacy_bootstrap(
            root, **recovery._snapshot_kwargs(item.stopped, limits, manifests, leases)
        ) as snapshot:
            effects, holds = recovery._reconcile_snapshot(snapshot, observation, manifests)
        if fault is None:
            assert observation.manifest_anchor_sha256 == signed.manifest_sha256
            assert observation.manifest_anchor_block == old.manifest_anchor_block
            assert not holds
            common = next(effect for effect in effects if effect.path == "journal.json")
            assert common.classification == "proven_superseded_weight"
            assert common.reason == "terminal_common_receipt_precedes_proven_bridge_history"
        else:
            assert observation.manifest_anchor_sha256 is None
            assert (
                "common_historical_context_missing"
                if fault == "missing_context"
                else "historical_manifest_anchor_not_proven"
            ) in holds
        assert files == {name: (root / name).read_bytes() for name in files}
    finally:
        await observer.aclose()
