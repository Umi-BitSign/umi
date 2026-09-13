"""Bounded assignment discovery for the existing weight-disabled miner transport.

Feed availability is not authorization. Each installed publication passes the
static quorum, identity, revision, origin and quota checks. The miner's durable
nonce/resource/response ledgers and owned-finality admission remain in force.
"""

from __future__ import annotations

import asyncio
import re
import time
from contextlib import suppress

from .competition_authorization import (
    EndpointAuthorizationAuthority,
    SignedEndpointAuthorization,
    _origin,
    validate_runtime_binding,
)
from .competition_client import validate_intake_origin
from .competition_feed import (
    AssignmentFeedQuery,
    SignedAssignmentFeedQuery,
    query_assignment_feed,
)
from .miner_admission import MinerAdmissionError
from .open_competition import CompetitionPolicy, digest, identity, sign_object
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import canonical_json_bytes
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS


class FeedEndpointAuthorizationAuthority:
    def __init__(
        self,
        *,
        policy,
        legacy_policy,
        finalized_blocks,
        miner_hotkey,
        model_revision,
        serving_origin,
        origin,
        wallet,
        poll_seconds=5,
        transport=None,
    ):
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.legacy_policy = ScoringPolicy.model_validate_json(canonical_json_bytes(legacy_policy))
        identity(miner_hotkey)
        if not isinstance(model_revision, str) or not re.fullmatch(r"[0-9a-f]{64}", model_revision):
            raise ValueError("model revision must be a lowercase SHA-256 digest")
        _origin(serving_origin)
        self.origin = validate_intake_origin(origin)
        if type(poll_seconds) is not int or not 5 <= poll_seconds <= 60:
            raise ValueError("assignment polling interval must be 5 to 60 seconds")
        self.miner_hotkey = miner_hotkey
        self.model_revision = model_revision
        self.serving_origin = serving_origin
        self.finalized_blocks = finalized_blocks
        self.wallet = wallet
        self.poll_seconds = poll_seconds
        self.transport = transport
        self._runtime = None
        self._publications = {}
        self._cursor = None
        self._pending = []
        self._pending_cursor = None
        self._nonce = 0
        self._last_clock = 0
        self._held = False
        self._poll_lock = asyncio.Lock()
        self._reason = "awaiting_assignment_discovery"

    @property
    def policy_sha256(self):
        return digest(self.policy)

    @property
    def publication_sha256(self):
        # No single publication represents an ongoing feed.
        return None

    def validate_runtime(self, **runtime):
        validate_runtime_binding(
            policy=self.policy,
            legacy_policy=self.legacy_policy,
            expected_miner=self.miner_hotkey,
            expected_revision=self.model_revision,
            required_validators=frozenset(),
            **runtime,
        )
        for authority, _expires in self._publications.values():
            authority.validate_runtime(**runtime)
        self._runtime = runtime

    def _now(self):
        now = time.time_ns() // 1_000_000
        if self._held or now < self._last_clock:
            self._held = True
            self._reason = "assignment_clock_rollback"
            raise ValueError("assignment discovery clock moved backwards")
        self._last_clock = now
        return now

    def _prune(self):
        now = self._now()
        self._publications = {
            sha: item for sha, item in self._publications.items() if now < item[1]
        }

    def install(self, publication):
        if self._runtime is None:
            raise ValueError("runtime binding must precede assignment installation")
        self._prune()
        authority = EndpointAuthorizationAuthority(
            policy=self.policy,
            legacy_policy=self.legacy_policy,
            publication=publication,
            finalized_blocks=self.finalized_blocks,
            miner_hotkey=self.miner_hotkey,
            model_revision=self.model_revision,
            serving_origin=self.serving_origin,
        )
        authority.validate_runtime(**self._runtime)
        sha = authority.publication_sha256
        if sha in self._publications:
            return False  # Retain the first authority's usable-window observation.
        if len(self._publications) >= 4:
            raise ValueError("active assignment publication capacity reached")
        if {identity(s.submission.hotkey) for s in publication.publication.submissions} != {
            identity(self.miner_hotkey)
        }:
            raise ValueError("feed publication must have one miner audience")
        close = max(a.request.response_close_round for a in publication.publication.assignments)
        expires = QUICKNET_GENESIS_MS + (close - 1) * QUICKNET_PERIOD_MS
        # Fixed memory ceiling: at most four bounded, quorum-verified publications.
        self._publications = {**self._publications, sha: (authority, expires)}
        return True

    async def _query(self, **parameters):
        self._now()
        self._nonce = max(self._nonce + 1, time.time_ns())
        query = AssignmentFeedQuery(
            schema="umi-assignment-feed-query/1",
            policy_sha256=self.policy_sha256,
            miner_hotkey=self.miner_hotkey,
            nonce_unix_ns=str(self._nonce),
            **parameters,
        )
        signed = SignedAssignmentFeedQuery(query=query, signature=sign_object(query, self.wallet))
        return await query_assignment_feed(
            origin=self.origin,
            signed=signed,
            policy=self.policy,
            legacy_policy=self.legacy_policy,
            transport=self.transport,
        )

    async def poll_once(self):
        async with self._poll_lock:
            self._prune()
            if not self._pending:
                result = await self._query(operation="list", after=self._cursor, limit=100)
                publications = []
                for item in result["items"]:
                    sha = item.get("publication_sha256") if isinstance(item, dict) else None
                    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                        raise ValueError("invalid assignment publication identifier")
                    if sha not in self._publications and sha not in publications:
                        publications.append(sha)
                cursor = result.get("next_cursor")
                if cursor is not None and (
                    not isinstance(cursor, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", cursor)
                    or (self._cursor is not None and cursor <= self._cursor)
                ):
                    raise ValueError("assignment feed cursor did not advance")
                self._pending, self._pending_cursor = publications, cursor
            unavailable = False
            for _ in range(min(2, len(self._pending))):
                sha = self._pending[0]
                try:
                    reply = await self._query(operation="publication", publication_sha256=sha)
                    self.install(
                        SignedEndpointAuthorization.model_validate_json(
                            canonical_json_bytes(reply["publication"])
                        )
                    )
                except ValueError:
                    unavailable = True
                # A rejected/expired item cannot starve later publications. It
                # can be retried on the next scan, but never installs authority.
                self._pending.pop(0)
            if not self._pending:
                self._cursor = self._pending_cursor
            self._reason = (
                "assignment_publication_unavailable" if unavailable else "assignment_feed_current"
            )

    async def run(self, stop):
        while not stop.is_set():
            try:
                await self.poll_once()
            except Exception:
                self._reason = (
                    "assignment_clock_rollback" if self._held else "assignment_feed_unavailable"
                )
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.poll_seconds)

    async def authorize(self, request, *, validator_hotkey):
        try:
            self._prune()
            identity(validator_hotkey)
        except (TypeError, ValueError) as error:
            raise MinerAdmissionError("endpoint_assignment_not_authorized") from error
        for authority, _expires in tuple(self._publications.values()):
            if authority.contains(request, validator_hotkey=validator_hotkey):
                return await authority.authorize(request, validator_hotkey=validator_hotkey)
        raise MinerAdmissionError("endpoint_assignment_not_authorized")

    def status(self):
        return {
            "reason_code": self._reason,
            "cached_publications": len(self._publications),
            "no_weight": True,
            "chain_submission_authorized": False,
            "publication_timing_proven": False,
            "transport_policy_sha256": scoring_policy_hash(self.legacy_policy),
        }
