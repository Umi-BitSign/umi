"""Explicit historical bootstrap boundary for the first standing series.

The old manifest signature authenticates historical bytes, not present reward
authority. A selected recovery-quorum adoption must authorize this boundary;
native review still proves the exact current slot and every intervening effect.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .bootstrap_weights import (
    SignedBootstrapEligibilityManifest,
    verify_signed_bootstrap_eligibility_manifest,
)
from .competition_cohort_recovery import Block
from .open_competition import Hotkey, identity
from .protocol import StrictProtocolModel


class BootstrapRewardPredecessor(StrictProtocolModel):
    schema_: Literal["umi-bootstrap-reward-predecessor/1"] = Field(alias="schema")
    signed_manifest: SignedBootstrapEligibilityManifest
    control_hotkey: Hotkey
    committed_at_block: Block

    @property
    def control_sha256(self):
        return self.signed_manifest.manifest_sha256

    def check_series(self, series):
        # Verify at the original freeze time. The bootstrap service interval
        # is not renewed by recognition of its historical commitment.
        verify_signed_bootstrap_eligibility_manifest(self.signed_manifest)
        if (
            series.predecessor is not None
            or identity(self.control_hotkey) != identity(series.control_hotkey)
            or not self.signed_manifest.manifest.frozen_at_block
            <= self.committed_at_block
            < series.recovery.authority.issued_at_block
        ):
            raise ValueError("bootstrap predecessor differs from the initial standing boundary")
        return self

    def check_control(self, control):
        if (
            identity(control.control_hotkey) != identity(self.control_hotkey)
            or control.control_sha256 != self.control_sha256
            or control.committed_at_block != self.committed_at_block
        ):
            raise ValueError("native control differs from the adopted bootstrap predecessor")
