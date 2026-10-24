"""Private handoff of a successful original-owner history checkpoint.

Only the native checkpoint readers issue this capability, after checking the
original journal, verifier semantics, source generations and migration origin.
It is not a wire format or a proof import path. A fresh owned finalized head and
a source recheck remain required before the history owner applies any effects.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .chain_evidence import FinalizedSnapshotRef
from .open_competition import digest

_ISSUER = object()


@dataclass(frozen=True, slots=True)
class OwnedCheckpointTip:
    snapshot: FinalizedSnapshotRef
    encoded_header: str
    chain_config_sha256: str
    control_hotkey: str
    semantics: str
    owner: object = field(repr=False, compare=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(tip):
    return digest(
        {
            "snapshot": asdict(tip.snapshot),
            "header": tip.encoded_header,
            "chain_config_sha256": tip.chain_config_sha256,
            "control_hotkey": tip.control_hotkey,
            "semantics": tip.semantics,
            "owner": tip.owner.owner,
        }
    )


def _issue_checkpoint_tip(owner, value):
    """Called only with the native reader's freshly validated local result."""
    tip = OwnedCheckpointTip(
        FinalizedSnapshotRef(**value["snapshot"]),
        value["header"],
        owner.binding["chain_config_sha256"],
        owner.binding["control_hotkey"],
        owner.semantics,
        owner,
        _issuer=_ISSUER,
    )
    object.__setattr__(tip, "_binding", _binding(tip))
    return tip


def validate_checkpoint_tip(tip, *, snapshot, encoded_header, chain_config_sha256):
    if (
        type(tip) is not OwnedCheckpointTip
        or tip._issuer is not _ISSUER
        or tip._binding != _binding(tip)
        or tip.snapshot != snapshot
        or tip.encoded_header != encoded_header
        or tip.chain_config_sha256 != chain_config_sha256
        or tip.semantics != tip.owner.semantics
        or tip.chain_config_sha256 != tip.owner.binding["chain_config_sha256"]
        or tip.control_hotkey != tip.owner.binding["control_hotkey"]
    ):
        raise ValueError("checkpoint tip lacks the original native owner result")
    tip.owner._check_storage_identity()
