"""Checkpointed routing repair for already signed supervisor history.

Only unsigned pagination changes. A cursor page must lead clients to its terminal
page before they attempt execution; otherwise an expired intermediate head can
strand an offline installation. These receipts confer no finality or authority.
"""

import hashlib
import time
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import (
    SignedSupervisorDirective,
    verify_signed_supervisor_directive_history,
)

CURSOR_KIND = "reference_channel_forward_cursor"
PAGES_PER_PASS = 32


class ReferenceForwardCursor(StrictProtocolModel):
    schema_: Literal["umi-reference-forward-cursor/1"] = Field(alias="schema")
    anchor: SignedSupervisorDirective
    successor: SignedSupervisorDirective
    page_sha256: Hex32
    page_etag: Annotated[str, Field(min_length=3, max_length=255)]

    @model_validator(mode="after")
    def linked(self):
        if (
            self.successor.directive.sequence != self.anchor.directive.sequence + 1
            or self.successor.directive.previous_directive_sha256 != self.anchor.directive_sha256
        ):
            raise ValueError("retained forward cursor requires original linked signatures")
        return self


def repair_forward_cursors(owner, head, *, block, key_for, conflict):
    """Resume bounded legacy routing repair without replacing a signed byte."""
    started = time.monotonic()
    initial_key = key_for(owner.config, 0, None)
    initial_value = owner.store.read(initial_key)
    if initial_value is None:
        raise ValueError("forward cursor repair needs original initial history")
    initial = owner._page(initial_value, sequence=0, sha=None, block=block)
    if initial.head.directive.sequence > head.directive.sequence:
        raise conflict("reference head advanced during cursor repair")
    if initial.head.directive.sequence == head.directive.sequence:
        if initial.head != head:
            raise ValueError("reference initial history conflicts with selected head")
    elif not initial.more:
        # Once the initial prefix is full, an installed client must traverse its
        # cursor rather than execute that prefix's now historical final item.
        owner._write(
            initial_key,
            initial_value,
            canonical_json_bytes(initial.model_copy(update={"more": True})),
        )
    keys = owner.journal.keys(CURSOR_KIND)
    if keys:
        previous = ReferenceForwardCursor.model_validate(owner.journal.get(CURSOR_KIND, keys[-1]))
        if keys[-1] != f"{previous.anchor.directive.sequence:016d}":
            raise ValueError("retained forward cursor checkpoint has changed identity")
        for signed in (previous.anchor, previous.successor):
            verify_signed_supervisor_directive_history(
                signed, config=owner.config, finalized_block=block
            )
        anchor = previous.successor
    else:
        anchor = initial.directives[0]
    total = head.directive.sequence - 1
    for _ in range(PAGES_PER_PASS):
        if anchor.directive.sequence >= head.directive.sequence:
            if anchor != head:
                raise ValueError("retained forward cursor conflicts with selected history")
            owner._event("reference_channel_cursor_repair", started, completed=total, total=total)
            return
        key = key_for(owner.config, anchor.directive.sequence, anchor.directive_sha256)
        value = owner.store.read(key)
        if value is None:
            raise ValueError("missing original forward cursor needs explicit restoration")
        page = owner._page(
            value, sequence=anchor.directive.sequence, sha=anchor.directive_sha256, block=block
        )
        if not page.directives:
            raise ValueError("missing original forward edge needs explicit restoration")
        if page.head.directive.sequence > head.directive.sequence:
            raise conflict("reference head advanced during cursor repair")
        if page.head.directive.sequence == head.directive.sequence and page.head != head:
            raise ValueError("forward cursor conflicts with selected signed head")
        if not page.more:
            value = owner._write(
                key, value, canonical_json_bytes(page.model_copy(update={"more": True}))
            )
        successor = page.directives[0]
        owner.journal.put(
            CURSOR_KIND,
            f"{anchor.directive.sequence:016d}",
            ReferenceForwardCursor(
                schema="umi-reference-forward-cursor/1",
                anchor=anchor,
                successor=successor,
                page_sha256=hashlib.sha256(value.payload).hexdigest(),
                page_etag=value.etag,
            ),
        )
        owner._event(
            "reference_channel_cursor_repair",
            started,
            completed=anchor.directive.sequence,
            total=total,
        )
        anchor = successor
    if anchor == head:
        return
    owner._event(
        "reference_channel_cursor_repair",
        started,
        completed=anchor.directive.sequence - 1,
        total=total,
        retrying=True,
    )
    raise conflict("reference forward cursor repair needs another bounded pass")
