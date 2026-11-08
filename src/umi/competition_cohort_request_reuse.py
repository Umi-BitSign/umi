"""Bounded private publication receipts; never evidence for a remote reviewer.

Only a successful native export can produce a receipt. The exporter may reuse
that local result while the policy, verification interval, capacity and every
published file identity still agree. Missing established state and unavailable
storage require explicit repair; they never silently repeat completed replay.
"""

import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .private_files import (
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_RECEIPT_BYTES = 16 * 1024**2
StampNumber = Annotated[str, Field(pattern=r"^-?[0-9]{1,30}$")]


class PublicationFileStamp(StrictProtocolModel):
    relative_path: Annotated[
        str,
        Field(
            pattern=(
                r"^(objects/[0-9a-f]{64}|(orders|terminals)/[0-9a-f]{64}/[0-9a-f]{64}"
                r"|partials/[0-9a-f]{64}/[0-9a-f]{64}/[0-9a-f]{64}/[0-9]{5})\.json$"
            )
        ),
    ]
    # Nanosecond timestamps need decimal strings to remain exact canonical JSON.
    stamp: Annotated[tuple[StampNumber, ...], Field(min_length=9, max_length=9)]


class PublicationVerificationReceipt(StrictProtocolModel):
    schema_: Literal["umi-private-request-publication/1"] = Field(alias="schema")
    terminal_sha256: Hex32
    policy_sha256: Hex32
    maximum_bytes: Annotated[int, Field(gt=0)]
    opened_at_block: Annotated[int, Field(ge=0)]
    completed_by_block: Annotated[int, Field(ge=0)]
    files: Annotated[tuple[PublicationFileStamp, ...], Field(min_length=1, max_length=65536)]


def _path(root: Path, terminal_sha: str, policy_sha: str) -> Path:
    if any(re.fullmatch(r"[0-9a-f]{64}", key) is None for key in (terminal_sha, policy_sha)):
        raise ValueError("invalid private publication identity")
    return root / ".publication-verification" / (policy_sha + "-" + terminal_sha + ".json")


def load_publication_verification(root, terminal_sha, policy_sha):
    """Read indexed state first, importing an unchanged legacy receipt once."""
    from .competition_publication_receipt_store import PublicationReceiptStore

    path = _path(root, terminal_sha, policy_sha)
    store = PublicationReceiptStore(path.parent)
    raw = store.load(path.stem)
    if raw is not None:
        try:
            receipt = PublicationVerificationReceipt.model_validate_json(raw)
            if receipt.terminal_sha256 != terminal_sha or receipt.policy_sha256 != policy_sha:
                raise ValueError("publication receipt identity differs")
            return receipt
        except ValueError as error:
            raise store.failure("publication_receipt_invalid") from error
    try:
        receipt = read_private_model(
            path, PublicationVerificationReceipt, maximum_bytes=MAX_RECEIPT_BYTES
        )
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        raise store.failure("legacy_publication_receipt_repair_required") from error
    if receipt.terminal_sha256 != terminal_sha or receipt.policy_sha256 != policy_sha:
        raise store.failure("legacy_publication_receipt_identity_changed")
    # The original /1 verdict and file stamps are unchanged. No native replay,
    # output reads or payload hashes are needed to migrate this local metadata.
    store.remember(path.stem, canonical_json_bytes(receipt))
    return receipt


def remember_publication_verification(root: Path, receipt: PublicationVerificationReceipt):
    """Checkpoint successful native work before reporting the export current."""
    from .competition_publication_receipt_store import PublicationReceiptStore

    path = _path(root, receipt.terminal_sha256, receipt.policy_sha256)
    PublicationReceiptStore(path.parent).remember(path.stem, canonical_json_bytes(receipt))
