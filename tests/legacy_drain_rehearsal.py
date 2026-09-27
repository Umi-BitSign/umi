"""Synthetic chain ports for the real stopped-host v1 migration rehearsal.

Only call this in the forked fixture host with public development keys. Systemd, source signatures,
private file access, original locks, checkpoint archives and host switching are
real. Finality, transaction encoding and network submission are substituted;
this fixture cannot establish a live-chain drain or authorize real weights.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from umi import competition_legacy_drain as drain
from umi import competition_legacy_marker as marker
from umi import competition_recovery_observation as recovery_observation
from umi.bridge.drain import VerifiedLegacyDrain
from umi.chain_evidence import FinalizedSnapshotRef
from umi.protocol import canonical_json_bytes


def install_legacy_marker_ports(item, case, provider_type, check_owned):
    """Keep paid-marker and archive orchestration, substitute only chain ports."""
    drain._AUDITED_DIRECTIVES = frozenset({item.signed.directive_sha256})
    drain.FinalizedCompetitionWeightProvider = provider_type
    marker.validate_owned_weight_observation = check_owned
    recovery_observation.validate_owned_weight_observation = check_owned
    item.owned.validator_nonce = 0
    item.owned.runtime = object()
    item.marker_sends = 0
    emitted = {}

    def encode(call, **kwargs):
        assert call.module == "System" and call.function == "remark"
        assert kwargs["validator_hotkey"] == item.config.validator_hotkey
        assert kwargs["nonce"] == item.owned.validator_nonce
        assert kwargs["mortality_period"] == 64
        payload = bytes.fromhex(call.params["remark"][2:])
        # Public development key only; these bytes are deliberately not a
        # valid chain extrinsic. No network transport exists in this fixture.
        encoded = b"synthetic-marker/1" + kwargs["signer"].sign(payload) + payload
        emitted.update(marker=payload, encoded=encoded, birth=item.owned.block)
        return encoded

    async def submit(transport, encoded, signer):
        assert signer.ss58_address == item.config.validator_hotkey
        root = case.controls / "legacy-marker-outbox"
        attempt = json.loads((root / "attempt-1.json").read_bytes())
        intent = json.loads((root / "attempt-1.send.json").read_bytes())
        assert bytes.fromhex(attempt["signed_extrinsic"]) == encoded == emitted["encoded"]
        assert intent["attempt_sha256"] == hashlib.sha256(canonical_json_bytes(attempt)).hexdigest()
        item.marker_sends += 1
        assert item.marker_sends == 1
        item.owned.block = emitted["birth"] + 9
        item.owned.block_hash = "0x" + "19" * 32
        item.owned.evidence = canonical_json_bytes(
            {"schema": "test-owned-chain-observation", "block": item.owned.block}
        )
        item.owned.evidence_sha256 = hashlib.sha256(item.owned.evidence).hexdigest()
        raise ConnectionError("synthetic lost marker submission reply")

    async def find(provider, *, marker, birth_block, birth_hash, period):
        assert marker == emitted["marker"] and birth_block == emitted["birth"]
        assert birth_hash == "0x" + "18" * 32 and period == 64
        assert item.marker_sends == 1
        included = FinalizedSnapshotRef(
            birth_block + 1, "0x" + "31" * 32, birth_hash, "0x" + "32" * 32
        )
        head = FinalizedSnapshotRef(
            item.owned.block, item.owned.block_hash, "0x" + "33" * 32, "0x" + "34" * 32
        )
        return VerifiedLegacyDrain(hashlib.sha256(marker).hexdigest(), included, (0,), head)

    marker.encode_mortal_call = encode
    marker.BittensorCompetitionWeightTransport.submit = submit
    provider_type.find_legacy_drain = find
    consent = marker.LegacyMarkerConsent(
        schema="umi-legacy-marker-consent/1",
        validator_hotkey=item.config.validator_hotkey,
        source_config_sha256=hashlib.sha256(canonical_json_bytes(item.config)).hexdigest(),
        accepted_directive_sha256=item.signed.directive_sha256,
        accept_marker_transaction_fees=True,
        all_other_hotkey_writers_stopped=True,
        maximum_marker_transactions=1,
    )
    path = Path(case.controls) / "legacy-marker-consent.json"
    path.write_bytes(canonical_json_bytes(consent))
    path.chmod(0o400)
    return path
