"""Private durable outbound intent/outcome spool; recovery never transmits."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from pydantic import Field

from .competition_authorization import EndpointAssignment
from .competition_round_journal import RecordReservation, RoundJournal
from .competition_scheduling import AssignmentClaim
from .open_competition import digest
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes


class DispatchSpoolConfig(StrictProtocolModel):
    directory: Directory
    maximum_assignments: Annotated[int, Field(ge=1, le=65536)] = 4096
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 8 * 1024**3


class DispatchTranscriptSpool:
    def __init__(self, config, journal, evaluator_hotkey):
        self.outcome_bytes = journal.maximum_outcome_bytes * 2 + 65536
        self.journal = RoundJournal(
            Path(config.directory),
            dict(
                schema="umi-dispatch-transcript-spool/1",
                journal=str(journal.path),
                policy_sha256=digest(journal.policy),
                evaluator_hotkey=evaluator_hotkey,
                maximum_outcome_bytes=journal.maximum_outcome_bytes,
            ),
            maximum_rounds=config.maximum_assignments,
            maximum_bytes=config.maximum_bytes,
            maximum_record_bytes=max(self.outcome_bytes, 512 * 1024),
        )

    def reserve(self, key):
        # Reserve before claiming or transmitting, so a full spool cannot start
        # an HTTP request whose outcome has no logical retention allowance.
        self.journal.reserve_records(
            key,
            (
                RecordReservation("intent", key, 512 * 1024),
                RecordReservation("outcome", key, self.outcome_bytes),
                RecordReservation("acknowledged", key, 128),
            ),
        )

    def retain_intent(self, claim, prepared, *, origin_sha256, origin_block):
        self.journal.put(
            "intent",
            claim.assignment_key,
            dict(
                claim=dict(
                    assignment_key=claim.assignment_key,
                    claim_id=claim.claim_id,
                    publication_sha256=claim.publication_sha256,
                    assignment=claim.assignment.model_dump(mode="json", by_alias=True),
                    miner_hotkey=claim.miner_hotkey,
                    serving_origin=claim.serving_origin,
                    no_weight=claim.no_weight,
                ),
                request_hex=prepared.request_bytes.hex(),
                auth_headers=dict(prepared.auth_headers),
                origin_evidence_sha256=origin_sha256,
                origin_block=origin_block,
            ),
        )

    def retain_outcome(self, key, evidence):
        intent = self.journal.get("intent", key)
        transcript = json.loads(evidence)
        if (
            intent is None
            or canonical_json_bytes(transcript) != evidence
            or (
                transcript.get("schema") != "umi-endpoint-dispatch-transcript/1"
                or transcript.get("assignment_key") != key
                or transcript.get("publication_sha256") != intent["claim"]["publication_sha256"]
                or any(
                    transcript.get(k) != intent[k]
                    for k in (
                        "request_hex",
                        "auth_headers",
                        "origin_evidence_sha256",
                        "origin_block",
                    )
                )
            )
        ):
            raise ValueError("spooled outcome differs from its durable outbound intent")
        self.journal.put("outcome", key, {"transcript_hex": evidence.hex()})

    def acknowledge(self, key):
        self.journal.put("acknowledged", key, {"completed": True})

    def recover(self, scheduling, *, limit=100):
        """Complete original claims only from durable actual outcomes, no I/O to miners."""
        with self.journal.transaction() as db:
            keys = [
                row[0]
                for row in db.execute(
                    "SELECT id FROM records r WHERE kind='outcome' AND NOT EXISTS "
                    "(SELECT 1 FROM records a WHERE a.kind='acknowledged' AND a.id=r.id) "
                    "ORDER BY id LIMIT ?",
                    (limit,),
                )
            ]
        for key in keys:
            value = self.journal.get("intent", key)["claim"]
            claim = AssignmentClaim(
                **{
                    **value,
                    "assignment": EndpointAssignment.model_validate_json(
                        canonical_json_bytes(value["assignment"])
                    ),
                }
            )
            evidence = bytes.fromhex(self.journal.get("outcome", key)["transcript_hex"])
            # Recheck exact immutable intent before consuming it after restart.
            self.retain_outcome(key, evidence)
            scheduling.complete(claim, evidence=evidence)
            self.acknowledge(key)
        return len(keys)
