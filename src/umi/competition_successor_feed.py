"""Wallet-free delivery of retained signed successor rounds and exact packages.

Local publication is explicit. GET requests cannot sign, select packages, read
arbitrary paths, fetch remote objects, or claim that a historical row is current.
Validators retain their own signature, finality and activation checks.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from pydantic import Field
from starlette.responses import Response

from .competition_evaluator import Directory, _read
from .competition_host_activation import (
    SuccessorWorkerExecutionLimits,
    _parse_worker_execution_config,
    _validate_worker_execution_bindings,
)
from .competition_package import (
    CompetitionPackageManifest,
    PreparedCompetitionPackage,
    _check_exact_tree,
    _limit_for,
    _opened_sealed_directory,
    _read_sealed_file,
)
from .competition_rounds import RoundJournal
from .competition_successor_publication import (
    SignedSuccessorRoundPublication,
    SuccessorRoundPublicationPlan,
    publication_round_advances,
    verify_successor_round_publication,
)
from .competition_supervisor import (
    MAX_SUCCESSOR_DOCUMENT_BYTES,
    SuccessorSupervisorDirectivePage,
    load_bound_successor_replay_package,
)
from .competition_worker_cli import SuccessorWorkerExecutionConfig
from .open_competition import digest
from .protocol import StrictProtocolModel, canonical_json_bytes

_HEX = r"[0-9a-f]{64}"
_CURSOR = re.compile(rf"after/(3|4)/([1-9][0-9]{{0,15}})/({_HEX})\.json")
_CONTROL = re.compile(rf"directives/({_HEX})/(page|execution)\.json")
_AUTH = re.compile(rf"authorizations/({_HEX})\.json")
_PACKAGE = re.compile(rf"packages/({_HEX})/([a-z-]+\.json)")


class SuccessorFeedConfig(StrictProtocolModel):
    schema_: Literal["umi-successor-feed-config/1"] = Field(alias="schema")
    directory: Directory
    plan: SuccessorRoundPublicationPlan
    worker_limits: SuccessorWorkerExecutionLimits
    execution: SuccessorWorkerExecutionConfig
    maximum_rounds: Annotated[int, Field(ge=1, le=65536)] = 1024
    maximum_journal_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3


class _Record(StrictProtocolModel):
    publication: SignedSuccessorRoundPublication
    prepared: PreparedCompetitionPackage
    manifest: CompetitionPackageManifest


def _page(items, cursor, *, more=False):
    signed = [r.publication.signed for r in items]
    return SuccessorSupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/4",
        after_version=cursor[0],
        after_sequence=cursor[1],
        after_directive_sha256=cursor[2],
        directives=signed,
        more=more,
        head=signed[-1],
    )


async def _drained_thread(function, *args):
    """Keep the operation owned until its disk worker has actually stopped."""
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not task.cancelled():
            task.exception()
        raise


class SuccessorPublicationFeed:
    def __init__(self, config):
        self.config = SuccessorFeedConfig.model_validate_json(canonical_json_bytes(config))
        self._config_digest = digest(self.config)
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(mode="json", by_alias=True),
            maximum_rounds=self.config.maximum_rounds,
            maximum_bytes=self.config.maximum_journal_bytes,
        )

    @contextmanager
    def _locked(self):
        if digest(self.config) != self._config_digest:
            raise ValueError("successor feed configuration changed")
        self.journal._check_files()
        fd = os.open(self.journal.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.journal._check_files()
            if os.fstat(fd).st_ino != self.journal.path.stat().st_ino:
                raise ValueError("successor feed journal changed")
            yield
        finally:
            os.close(fd)

    def _initial(self):
        consent = self.config.plan.consent
        return (3, consent.predecessor_sequence, consent.predecessor_directive_sha256)

    @staticmethod
    def _cursor(record):
        signed = record.publication.signed
        return (4, signed.directive.sequence, signed.directive_sha256)

    def _verify_record(self, record):
        publication = verify_successor_round_publication(self.config.plan, record.publication)
        target = publication.intent.package
        prepared = record.prepared
        if (
            prepared.package_sha256 != target.package_sha256
            or prepared.manifest_sha256 != target.manifest_sha256
            or prepared.policy_sha256 != target.policy_sha256
            or hashlib.sha256(canonical_json_bytes(record.manifest)).hexdigest()
            != target.manifest_sha256
        ):
            raise ValueError("successor feed package binding differs")
        _validate_worker_execution_bindings(
            _parse_worker_execution_config(canonical_json_bytes(self.config.execution)),
            directive=publication.signed.directive,
            release_identity=self.config.plan.release.replay_release_identity,
            authorization_body=publication.authorization.authorization,
            limits=self.config.worker_limits,
        )

    def _history(self):
        cursor, records = self._initial(), []
        keys = self.journal.keys("delivery")
        if len(keys) > self.config.maximum_rounds:
            raise ValueError("successor feed round capacity exceeded")
        for key in sorted(keys, key=int):
            record = _Record.model_validate_json(
                canonical_json_bytes(self.journal.get("delivery", key))
            )
            self._verify_record(record)
            item = record.publication
            if (
                key != str(item.intent.sequence)
                or item.intent.sequence != cursor[1] + 1
                or item.intent.predecessor_version != cursor[0]
                or item.signed.directive.previous_directive_sha256 != cursor[2]
                or not publication_round_advances(
                    self.config.plan, records[-1].publication if records else None, item
                )
            ):
                raise ValueError("successor feed history is discontinuous")
            cursor = self._cursor(record)
            records.append(record)
        return records

    def retain(self, publication, prepared):
        """Export a locally signed round after complete package replay.

        Expired records remain useful history. This method never renews their
        window. The current publisher must gate signatures against its owned
        head and source conflicts before calling this method.
        """
        publication = SignedSuccessorRoundPublication.model_validate_json(
            canonical_json_bytes(publication)
        )
        prepared = PreparedCompetitionPackage.model_validate_json(canonical_json_bytes(prepared))
        with self._locked():
            package = load_bound_successor_replay_package(
                Path(prepared.package_path),
                directive=publication.signed.directive,
                observed_release=self.config.plan.release.replay_release_identity,
            )
            verify_successor_round_publication(self.config.plan, publication, package)
            record = _Record(publication=publication, prepared=prepared, manifest=package.manifest)
            self._verify_record(record)
            history = self._history()
            for old in history:
                if old.publication.intent.sequence == publication.intent.sequence:
                    # RoundJournal retains a durable hold on conflicting retries.
                    self.journal.put("delivery", str(publication.intent.sequence), record)
                    return
            cursor = self._cursor(history[-1]) if history else self._initial()
            if (
                publication.intent.sequence != cursor[1] + 1
                or publication.intent.predecessor_version != cursor[0]
                or publication.signed.directive.previous_directive_sha256 != cursor[2]
                or not publication_round_advances(
                    self.config.plan, history[-1].publication if history else None, publication
                )
                or len(history) >= self.config.maximum_rounds
            ):
                raise ValueError("successor feed cannot skip or replace history")
            self.journal.put("delivery", str(publication.intent.sequence), record)

    async def retain_async(self, publication, prepared):
        await _drained_thread(self.retain, publication, prepared)

    def history(self):
        """Read verified signed history for local delivery-outbox recovery."""
        with self._locked():
            return tuple(record.publication for record in self._history())

    def read(self, route):
        """Return only protocol objects. No request string becomes a file path."""
        if not isinstance(route, str) or len(route) > 256:
            raise KeyError("unknown successor object")
        cursor_match, control, auth, package_match = (
            pattern.fullmatch(route) for pattern in (_CURSOR, _CONTROL, _AUTH, _PACKAGE)
        )
        if not any((cursor_match, control, auth, package_match)):
            raise KeyError("unknown successor object")
        with self._locked():
            history = self._history()
            if not history:
                raise KeyError("successor feed is empty")
            if cursor_match:
                cursor = (int(cursor_match[1]), int(cursor_match[2]), cursor_match[3])
                index = 0 if cursor == self._initial() else None
                for position, record in enumerate(history, 1):
                    if cursor == self._cursor(record):
                        index = position
                if index is None:
                    raise KeyError("unknown successor cursor")
                if index == len(history):
                    page = SuccessorSupervisorDirectivePage(
                        schema="umi-validator-supervisor-directive-page/4",
                        after_version=4,
                        after_sequence=cursor[1],
                        after_directive_sha256=cursor[2],
                        directives=[],
                        more=False,
                        head=history[-1].publication.signed,
                    )
                else:
                    page = _page(
                        history[index : index + 16], cursor, more=index + 16 < len(history)
                    )
                body = canonical_json_bytes(page)
                if len(body) > MAX_SUCCESSOR_DOCUMENT_BYTES:
                    raise ValueError("successor page exceeds transport bound")
                return body, False
            for position, record in enumerate(history):
                item = record.publication
                if control and control[1] == item.signed.directive_sha256:
                    if control[2] == "execution":
                        return canonical_json_bytes(self.config.execution), True
                    # Exact one-hop history is independent of the requesting
                    # host's locally retained activation anchor.
                    cursor = self._cursor(history[position - 1]) if position else self._initial()
                    return canonical_json_bytes(_page([record], cursor)), True
                if (
                    auth
                    and auth[1]
                    == item.signed.directive.chain_authorization.signed_authorization_sha256
                ):
                    return canonical_json_bytes(item.authorization), True
                if package_match and package_match[1] == record.prepared.package_sha256:
                    name = package_match[2]
                    manifest = record.manifest
                    if name == "manifest.json":
                        expected_size = len(canonical_json_bytes(manifest))
                        expected_sha = record.prepared.manifest_sha256
                        maximum = self.config.plan.package_limits.maximum_manifest_bytes
                    else:
                        entry = next((e for e in manifest.files if e.name == name), None)
                        if entry is None:
                            raise KeyError("unknown package object")
                        expected_size, expected_sha = entry.size_bytes, entry.sha256
                        maximum = _limit_for(name, self.config.plan.package_limits)
                    with _opened_sealed_directory(Path(record.prepared.package_path)) as fd:
                        _check_exact_tree(fd)
                        body = _read_sealed_file(
                            fd,
                            name,
                            maximum_bytes=maximum,
                            expected_size=expected_size,
                            expected_sha256=expected_sha,
                        )
                    return body, True
            raise KeyError("unknown successor object")


def create_successor_feed_app(feed):
    """Mount behind TLS at the already-installed directive origin."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    prefix = urlsplit(feed.config.plan.supervisor.directive_url).path.rstrip("/") + "/successor"
    serial = asyncio.Lock()

    @app.get(prefix + "/{route:path}")
    async def get(route: str):
        if serial.locked():
            raise HTTPException(503, "successor delivery busy", headers={"Retry-After": "1"})
        async with serial:
            try:
                body, immutable = await _drained_thread(feed.read, route)
            except KeyError:
                raise HTTPException(404, "successor object unavailable") from None
            except (OSError, ValueError, RuntimeError):
                raise HTTPException(503, "successor delivery unavailable") from None
            return Response(
                body,
                media_type="application/json",
                headers={
                    "Cache-Control": "public, max-age=31536000, immutable"
                    if immutable
                    else "no-store",
                    "X-Content-Type-Options": "nosniff",
                },
            )

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8094)
    parser.add_argument("--publication", type=Path)
    parser.add_argument("--prepared-package", type=Path)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    if (args.publication is None) != (args.prepared_package is None):
        parser.error("publication and prepared-package must be supplied together")
    try:
        feed = SuccessorPublicationFeed(_read(args.config, SuccessorFeedConfig))
        if args.publication is not None:
            feed.retain(
                _read(args.publication, SignedSuccessorRoundPublication),
                _read(args.prepared_package, PreparedCompetitionPackage),
            )
            print('{"status":"retained_signed_history"}')
            return
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"successor feed rejected ({type(error).__name__})\n")
    import uvicorn

    uvicorn.run(
        create_successor_feed_app(feed),
        host="127.0.0.1",
        port=args.port,
        access_log=False,
        limit_concurrency=8,
    )


if __name__ == "__main__":
    main()
