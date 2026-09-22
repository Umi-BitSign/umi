"""Poll completed coordinator packages and recover signed delivery in order.

The descriptor index is a local discovery source, never signing authority.
The current publisher still replays and checks its owned head and intake state
at each signing boundary. No HTTP request can invoke this service.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_package import (
    CompetitionPackageManifest,
    PreparedCompetitionPackage,
    _check_exact_tree,
    _opened_sealed_directory,
    _read_sealed_file,
    competition_package_digest,
)
from .competition_successor_publication import (
    PublicationWindowUnavailable,
    SuccessorRoundPublicationIntent,
    publication_valid_through,
)
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import Directory
from .private_files import ensure_private_directory as _private
from .private_files import read_private_model as _read
from .protocol import StrictProtocolModel, canonical_json_bytes

_DESCRIPTOR = re.compile(r"([0-9a-f]{64})\.package\.json")


class SuccessorFollowConfig(StrictProtocolModel):
    schema_: Literal["umi-successor-follow-config/1"] = Field(alias="schema")
    certificate_directory: Directory
    package_directory: Directory
    maximum_rounds: Annotated[int, Field(ge=1, le=65536)] = 1024
    poll_interval_seconds: Annotated[int, Field(ge=2, le=60)] = 15

    @model_validator(mode="after")
    def separate_sources(self):
        left, right = Path(self.certificate_directory), Path(self.package_directory)
        if left == right or left in right.parents or right in left.parents:
            raise ValueError("completed-round source directories must be separate")
        return self


class CompletedRoundSource:
    def __init__(self, config, plan):
        self.config = SuccessorFollowConfig.model_validate_json(canonical_json_bytes(config))
        self.plan = plan
        self._binding = (digest(self.config), digest(plan))

    def check_binding(self):
        if (digest(self.config), digest(self.plan)) != self._binding:
            raise ValueError("completed-round source configuration changed")

    def scan(self):
        """Bounded descriptor/manifest discovery; selected packages replay later."""
        self.check_binding()
        directory = Path(self.config.certificate_directory)
        root = Path(self.config.package_directory)
        for path in (directory, root):
            if not path.is_dir():
                raise ValueError("completed-round source directory is missing")
            _private(path)
        rounds, entries = {}, 0
        with os.scandir(directory) as files:
            for entry in files:
                entries += 1
                if entries > self.config.maximum_rounds * 2 + 1:
                    raise ValueError("completed-round directory exceeds its scan bound")
                match = _DESCRIPTOR.fullmatch(entry.name)
                if match is None:
                    # Certificate and atomic-publication lock files carry no
                    # package-selection authority. Temporary files are ignored.
                    continue
                prepared = _read(directory / entry.name, PreparedCompetitionPackage)
                if (
                    prepared.policy_sha256 != self.plan.policy_sha256
                    or prepared.package_path != str(root / prepared.package_sha256)
                ):
                    raise ValueError("completed package escapes its fixed source or policy")
                with _opened_sealed_directory(Path(prepared.package_path)) as fd:
                    _check_exact_tree(fd)
                    raw = _read_sealed_file(
                        fd,
                        "manifest.json",
                        maximum_bytes=self.plan.package_limits.maximum_manifest_bytes,
                    )
                manifest = CompetitionPackageManifest.model_validate_json(raw)
                if (
                    raw != canonical_json_bytes(manifest)
                    or hashlib.sha256(raw).hexdigest() != prepared.manifest_sha256
                    or competition_package_digest(manifest) != prepared.package_sha256
                    or manifest.policy_sha256 != prepared.policy_sha256
                    or manifest.settlement_publication_sha256 != match[1]
                ):
                    raise ValueError("completed descriptor and sealed manifest differ")
                previous = rounds.setdefault(manifest.round_sequence, prepared)
                if previous != prepared:
                    raise ValueError("conflicting completed packages for one round")
                if len(rounds) > self.config.maximum_rounds:
                    raise ValueError("completed-round capacity exceeded")
        return rounds

    def prepared_for(self, target):
        return PreparedCompetitionPackage(
            schema="umi-prepared-competition-replay-package/1",
            package_path=str(Path(self.config.package_directory) / target.package_sha256),
            package_sha256=target.package_sha256,
            manifest_sha256=target.manifest_sha256,
            policy_sha256=target.policy_sha256,
        )


class AutomaticSuccessorPublisher:
    """One local serialized tick; no wallet or provider is created implicitly."""

    def __init__(self, publisher, feed, config, *, authorization_wallet, directive_wallets):
        if publisher.builder.plan != feed.config.plan:
            raise ValueError("automatic signing and delivery plans differ")
        self.publisher, self.feed = publisher, feed
        self.source = CompletedRoundSource(config, publisher.builder.plan)
        if self.source.config.maximum_rounds > min(
            publisher.builder.journal.maximum_rounds, feed.config.maximum_rounds
        ):
            raise ValueError("automatic source exceeds retained-history capacity")
        self.authorization_wallet = authorization_wallet
        self.directive_wallets = tuple(directive_wallets)
        self._serial = asyncio.Lock()
        publisher.builder.journal.put(
            "source", "completed_rounds", self.source.config.model_dump(mode="json", by_alias=True)
        )

    def _histories(self):
        builder = self.publisher.builder
        with builder._locked():
            signed = tuple(builder.history())
        delivered = self.feed.history()
        if len(delivered) > len(signed) or signed[: len(delivered)] != delivered:
            raise ValueError("delivery history is not an exact prefix of signing history")
        return signed, delivered

    def _select(self, signed, block):
        builder = self.publisher.builder
        rounds = self.source.scan()
        verified_sequences = set()
        if builder.plan.continuity is not None:
            latest = signed[-1].intent.round_sequence if signed else 0
            verified_sequences.add(latest)
            for number in sorted((n for n in rounds if n > latest), reverse=True):
                try:
                    # Only candidate replacements need full native validation
                    # during selection. Existing round replay happens when due.
                    candidate = builder._load(rounds[number])
                except ValueError:
                    with builder._locked():
                        builder.journal.put(
                            "rejected_continuity_candidate",
                            digest(rounds[number]),
                            {
                                "package_sha256": rounds[number].package_sha256,
                                "round_sequence": number,
                                "reason": "native_package_verification_failed",
                            },
                        )
                    del rounds[number]
                    continue
                if signed:
                    from .competition_reward_continuity import validate_admission_candidate

                    with builder._locked():
                        admitted = builder.journal.get(
                            "continuity_admission", candidate.package_sha256
                        )
                    if admitted is None:
                        try:
                            validate_admission_candidate(builder.plan.continuity, candidate, block)
                        except ValueError:
                            # An unusable replacement cannot starve the last
                            # admitted allocation. Its original admission
                            # deadline and authority scope remain unchanged.
                            with builder._locked():
                                builder.journal.put(
                                    "unavailable_continuity_admission",
                                    digest(rounds[number]),
                                    {
                                        "package_sha256": rounds[number].package_sha256,
                                        "round_sequence": number,
                                        "reason": "native_admission_not_available",
                                    },
                                )
                            del rounds[number]
                            continue
                verified_sequences.add(number)
                break
        with builder._locked():
            builder.journal.observe(block)
            # Retain discovered identities across restarts, including rounds
            # skipped after expiry. A rewritten descriptor cannot change them.
            for sequence, prepared in sorted(rounds.items()):
                if builder.plan.continuity is None or sequence in verified_sequences:
                    builder.journal.put("completed_round", str(sequence), prepared)
            last_round = signed[-1].intent.round_sequence if signed else 0
            sequence = (
                signed[-1].intent.sequence if signed else builder.plan.consent.predecessor_sequence
            ) + 1
            pending = []
            for slot in builder.journal.keys("intent"):
                item = SuccessorRoundPublicationIntent.model_validate(
                    builder.journal.get("intent", slot)
                )
                if item.sequence == sequence and block <= item.authorization.valid_through_block:
                    pending.append(item)
            if len(pending) > 1:
                raise ValueError("multiple unexpired publication intents")
            if pending:
                item = pending[0]
                prepared = rounds.get(item.round_sequence)
                if prepared != self.source.prepared_for(item.package):
                    raise ValueError("unfinished publication has lost its completed package")
                return prepared
            newer = [number for number in rounds if number > last_round]
            if newer:
                return rounds[max(newer)]
            interval = builder.plan.renewal_interval_blocks
            if (
                signed
                and interval is not None
                and (block >= signed[-1].intent.authorization.signed_at_block + interval)
            ):
                prepared = rounds.get(last_round)
                if prepared != self.source.prepared_for(signed[-1].intent.package):
                    raise ValueError("renewal has lost its original completed package")
                return prepared
            return None

    async def tick(self):
        async with self._serial:
            self.source.check_binding()
            if await run_owned_thread(self.publisher.builder.revoked):
                return self._status("continuity_revoked")
            signed, delivered = await run_owned_thread(self._histories)
            if len(delivered) < len(signed):
                # A crash after signing never causes another signature or a
                # newer export to jump over the missing predecessor. Recover
                # one exact historical record per tick, even after expiry.
                missing = signed[len(delivered)]
                await self.feed.retain_async(
                    missing, self.source.prepared_for(missing.intent.package)
                )
                return self._status("recovered_signed_history", missing.intent.round_sequence)
            head = await self.publisher._head()
            prepared = await run_owned_thread(self._select, signed, head.block)
            if prepared is None:
                return self._status("waiting_for_completed_round")
            package = await run_owned_thread(self.publisher.builder._load, prepared)
            try:
                publication_valid_through(self.publisher.builder.plan, package, head.block)
            except PublicationWindowUnavailable:
                return self._status("waiting_for_current_round", package.manifest.round_sequence)
            publication = await self.publisher.build(
                prepared,
                authorization_wallet=self.authorization_wallet,
                directive_wallets=self.directive_wallets,
                renew=bool(
                    signed and prepared == self.source.prepared_for(signed[-1].intent.package)
                ),
            )
            await self.feed.retain_async(publication, prepared)
            return self._status("published", publication.intent.round_sequence)

    @staticmethod
    def _status(status, round_sequence=None):
        return {
            "schema": "umi-successor-follow-status/1",
            "status": status,
            "round_sequence": round_sequence,
            "validator_activation_proven": False,
        }
