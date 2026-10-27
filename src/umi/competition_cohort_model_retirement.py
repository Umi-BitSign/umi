"""Automatic, checkpointed retirement of verified legacy upload payloads.

Only payload directories are reclaimed. Signed manifests, upload requests,
admission evidence, model leases and journals remain in place. Remote ownership,
every live consumer declaration and local transfer leases precede fencing and
unlink. The ordinary intake background task resumes interrupted items.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import time
from contextlib import ExitStack
from pathlib import Path

from .competition_artifacts import (
    _directory,
    _file_identity,
    _has_preserved_verification,
    _preserved_verification_record,
)
from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS
from .competition_model_storage_leases import model_storage_consumer_release
from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import lock_private_file
from .protocol import canonical_json_bytes

logger = logging.getLogger("umi.competition.progress")

_FAILURES = dict(
    [
        ("model storage consumer declaration is no longer live", "consumer_not_live"),
        (
            "model storage consumer has not selected this preserved remote model",
            "consumer_model_binding_missing",
        ),
        (
            "released model awaits its authenticated remote retry owner",
            "remote_retry_owner_missing",
        ),
        (
            "shared file migration requires completed native bytes and documents",
            "completed_remote_bytes_missing",
        ),
        ("owned model byte verification requires repair", "completed_remote_bytes_damaged"),
        ("retained model chunk is unavailable", "remote_object_missing"),
        (
            "local archive verification requires explicit repair before retirement",
            "completed_local_verification_missing",
        ),
        ("retirement waits for native completed staging release", "staging_payload_still_present"),
        (
            "original upload inventory advanced; use the next native background scan",
            "upload_inventory_advanced",
        ),
        (
            "remote retry requires its retained original participation",
            "original_participation_missing",
        ),
        ("remote retry requires its original admission certificate", "original_admission_missing"),
    ]
)


def retirement_failure_reason(operation, error):
    """Expose stable native diagnostics without paths, tokens or exception text."""
    if str(error) in _FAILURES:
        return _FAILURES[str(error)]
    if isinstance(error, FileNotFoundError):
        return operation + "_file_missing"
    if isinstance(error, BlockingIOError):
        return operation + "_lease_busy"
    status = getattr(error, "http_status", None)
    if type(status) is int and 400 <= status <= 599:
        return operation + "_http_" + str(status)
    return operation + "_" + type(error).__name__


class ModelUploadRetirement:
    def __init__(self, uploads, delivery, *, series):
        self.uploads, self.delivery, self.series = uploads, delivery, series
        self.config = uploads.config.retirement
        if self.config is None or delivery.preserved is None:
            raise ValueError(
                "automatic retirement requires configured consumers and remote payload ownership"
            )
        self.journal = RoundJournal(
            uploads.root / "retirement-journal",
            dict(
                schema="umi-local-model-retirement-owner/1",
                uploads=str(uploads.journal.root),
                archive=str(uploads.archive),
            ),
            maximum_rounds=65536,
            maximum_bytes=uploads.config.maximum_metadata_bytes,
            maximum_record_bytes=16 * 1024**2,
        )
        self.started, self.completed_samples = time.monotonic(), 0
        self.cursor = 0
        self.latest = {}
        self.released_bytes = 0

    def _protected_models(self):
        """Seal non-remote cohort membership once; an open local intake blocks release."""
        protected = set(self.config.protected_models)
        intake = self.uploads.intake
        remote = self.delivery.preserved.sources.authenticated
        for cohort in intake.bindings:
            if cohort in remote:
                continue
            with intake._connection(prefer_history=True) as (db, store):
                history = store.published_history(cohort)
                state, _ = store.status(cohort)
                if state.phase == "intake":
                    raise OSError("local model consumer still has open intake")
                # The intake closure, unlike later lifecycle tips, fixes all
                # possible model membership. Keep this native result durably.
                closure = next(
                    (
                        digest(s.transition)
                        for s in history.transitions
                        if s.transition.phase == "intake"
                        and s.transition.operation == "close_phase"
                    ),
                    None,
                )
                if closure is None:
                    raise ValueError("closed local cohort lacks its retained intake closure")
                key = digest([cohort, closure])
                saved = self.journal.get("protected_membership", key)
                if saved is None:
                    if self.journal.get("protected_membership_done", key) is not None:
                        raise ValueError(
                            "retirement membership result is missing; explicit repair required"
                        )
                    models = sorted(
                        {
                            digest(record.request.signed_submission.submission.model_bundle)
                            for _, _, record in intake._parsed_records(db, history, track="model")
                        }
                    )
                    saved = dict(cohort=cohort, closure=closure, models=models)
                    self.journal.put_many(
                        (
                            ("protected_membership", key, saved),
                            ("protected_membership_done", key, dict(result=digest(saved))),
                        )
                    )
                if (
                    saved["cohort"] != cohort
                    or saved["closure"] != closure
                    or self.journal.get("protected_membership_done", key)
                    != dict(result=digest(saved))
                ):
                    raise ValueError("retirement membership result requires explicit repair")
                protected.update(saved["models"])
        return protected

    def _report(
        self,
        cohorts,
        *,
        completed,
        total,
        state="running",
        reason=None,
        model=None,
        operation="inventory",
        error_type=None,
    ):
        elapsed = time.monotonic() - self.started
        eta = (
            (total - completed) * elapsed / self.completed_samples
            if self.completed_samples
            else None
        )
        body = dict(
            stage="local_model_retirement",
            status=state,
            completed=completed,
            total=total,
            percent=100 * completed / total if total else 100.0,
            elapsed_seconds=elapsed,
            eta_seconds=0 if completed == total else eta if state == "running" else None,
            planning_eta_seconds=[max(0, total - completed), 300 * max(0, total - completed)]
            if not self.completed_samples and state == "running"
            else None,
            eta_basis="completed"
            if completed == total
            else "current_process_completed_models_per_elapsed_second"
            if self.completed_samples
            else "planning_remote_metadata_and_journaled_unlink; no_payload_reverification",
            eta_scope="eligible_local_model_retirement_only_excludes_evaluation_certification_rewards",
            stalled_or_retrying=state != "running",
            blocked_count=int(reason is not None),
            reason_code=reason,
            model_sha256=model,
            operation=operation,
            error_type=error_type,
            released_local_bytes=self.released_bytes,
            certification_authority=False,
        )
        self.latest = body
        for cohort in cohorts:
            PUBLIC_COHORT_PROGRESS.record("storage_retirement", dict(body, cohort_sha256=cohort))
        logger.info("cohort_model_retirement %s", canonical_json_bytes(body).decode("ascii"))
        return body

    def blocked_inventory(self, groups):
        return self._report(
            self.delivery.preserved.sources.authenticated,
            completed=0,
            total=len(groups) + 1,
            state="repair_required",
            reason="original_upload_inventory_incomplete",
        )

    async def poll_once(self, groups, generation):
        """Consume the existing upload poll's grouped originals, not a second scan."""
        try:
            protected = await run_owned_thread(self._protected_models)
        except (OSError, ValueError) as error:
            return self._report(
                self.delivery.preserved.sources.authenticated,
                completed=0,
                total=len(groups),
                state="waiting",
                reason="local_membership_unavailable_" + type(error).__name__,
            )
        models = sorted(model for model in groups if model not in protected)
        completed_models = [
            model for model in models if self.uploads.allocations.state(model) == "released"
        ]
        completed = len(completed_models)
        self.released_bytes = sum(
            record["allocated_bytes"]
            for model in completed_models
            for record in (self.journal.get("model_layout", model) or {}).get("files", ())
        )
        cohorts = self.delivery.preserved.sources.authenticated
        self._report(cohorts, completed=completed, total=len(models))
        if not models or completed == len(models):
            return self.latest
        # The upload journal can contain partial models from before the selected
        # remote preservation inventory was signed. Their original upload must
        # remain available for its retry/expiry path. Check the already
        # authenticated metadata before decoding any original requests.
        remote_models = {
            item.model_sha256 for source in cohorts.values() for item in source.preservation.models
        }
        attempted = 0
        for offset in range(len(models)):
            model = models[(self.cursor + offset) % len(models)]
            if self.uploads.allocations.state(model) == "released":
                continue
            if model not in remote_models:
                self._report(
                    cohorts,
                    completed=completed,
                    total=len(models),
                    state="waiting",
                    reason="preserved_model_selection_pending",
                    model=model,
                    operation="remote_selection",
                )
                attempted += 1
                if attempted >= self.config.batch_models:
                    self.cursor = (self.cursor + offset + 1) % len(models)
                    break
                continue
            operation = "retained_requests"

            def report_operation(stage, completed=completed, model=model):
                self._report(
                    cohorts, completed=completed, total=len(models), model=model, operation=stage
                )

            try:
                report_operation(operation)
                # The inventory already has durable native request-to-model facts.
                # Decode only this batch's originals, never every historical row.
                selected = [
                    await run_owned_thread(self.uploads.retained, key) for key in groups[model]
                ]
                operation = "consumer_release"
                report_operation(operation)
                # Fail on absent consumers before doing any remote metadata work.
                with model_storage_consumer_release(
                    self.config,
                    policy=self.uploads.intake.policy,
                    series=self.series,
                    requests=selected,
                    sources=self.delivery.preserved.sources,
                ):
                    pass
                operation = "remote_payload_ownership"
                report_operation(operation)
                availability = set()
                for request in selected:
                    owner = self.delivery._payload_owner(request)
                    try:
                        await run_owned_thread(owner.require_owned_payload, request)
                    except OSError:
                        if digest(request) in owner.verified:
                            raise  # Damage is repair, never an implicit payload hash pass.
                        await owner.ensure_owned(request, completed_only=True)
                    await self.delivery.confirm_retirement_availability(request, availability)
                operation = "local_payload_retirement"
                report_operation(operation)
                released = await run_owned_thread(self._retire, model, selected, generation)
                self.completed_samples += 1
                completed += 1
                self.released_bytes += released
                self._report(
                    cohorts,
                    completed=completed,
                    total=len(models),
                    model=model,
                    operation="model_retired",
                )
            except (OSError, ValueError) as error:
                self._report(
                    cohorts,
                    completed=completed,
                    total=len(models),
                    state="waiting",
                    reason=retirement_failure_reason(operation, error),
                    model=model,
                    operation=operation,
                    error_type=type(error).__name__,
                )
            attempted += 1
            if attempted >= self.config.batch_models:
                self.cursor = (self.cursor + offset + 1) % len(models)
                break
        return self.latest

    def _layout(self, model, bundle, stage):
        saved = self.journal.get("model_layout", model)
        if saved is not None:
            return saved
        if self.uploads.allocations.state(model) != "local_reserved":
            raise ValueError(
                "retirement layout is missing after preparation; explicit repair required"
            )
        raw = _preserved_verification_record(bundle, self.uploads.archive)
        if not _has_preserved_verification(bundle, self.uploads.archive, raw):
            receipt = self.uploads.archive / (".verified-" + model + ".json")
            if os.path.lexists(receipt):
                # A retained but mismatched receipt signals changed or damaged
                # local content. Never turn that into an ordinary cache miss.
                raise OSError(
                    "local archive verification requires explicit repair before retirement"
                )
            # No local receipt is needed to discard this scoped archive. The
            # caller already holds current consumer-release declarations and
            # authenticated remote ownership for every original request; the
            # manifest/tree check above and the identities below fence unlink.
            # Avoid hashing local bytes solely to delete their last copy.
        if list((stage / "model").iterdir()) or any(stage.glob("partial-*")):
            raise OSError("retirement waits for native completed staging release")
        root = self.uploads.archive / model / "model"
        dirs, files = [], []
        for path in [root, *root.rglob("*")]:
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                dirs.append(dict(path=relative, identity=_file_identity(info)))
            elif stat.S_ISREG(info.st_mode):
                files.append(
                    dict(
                        path=relative,
                        identity=_file_identity(info),
                        allocated_bytes=info.st_blocks * 512,
                    )
                )
            else:
                raise ValueError("retirement refuses an unverified special payload entry")
        saved = dict(model=model, verification=json.loads(raw), files=files, directories=dirs)
        self.journal.put("model_layout", model, saved)
        return saved

    @staticmethod
    def _open_directory(root, relative, directories):
        """Resolve original ancestors through held no-follow descriptors."""
        fd = os.dup(root)
        traversed = []
        try:
            for part in [] if relative in ("", ".") else Path(relative).parts:
                traversed.append(part)
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
                )
                os.close(fd)
                fd = child
                expected = directories["/".join(traversed)]
                actual = _file_identity(os.fstat(fd))
                if actual[:2] != expected[:2] or actual[6:8] != expected[6:8]:
                    raise ValueError("retiring payload directory identity changed")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _retire(self, model, requests, generation):
        uploads = self.uploads
        bundle = requests[0].signed_submission.submission.model_bundle
        if any(r.signed_submission.submission.model_bundle != bundle for r in requests):
            raise ValueError("retirement requests differ from their shared model")
        stage = uploads.root / "files" / model
        with ExitStack() as stack:
            stack.enter_context(
                model_storage_consumer_release(
                    self.config,
                    policy=uploads.intake.policy,
                    series=self.series,
                    requests=requests,
                    sources=self.delivery.preserved.sources,
                )
            )
            for path in (stage / "upload.lock", uploads.archive / (".preserve-" + model + ".lock")):
                stack.callback(os.close, lock_private_file(path))
            stack.enter_context(uploads.journal.locked())
            if uploads._model_references.versions.inventory_identity() != generation:
                raise OSError(
                    "original upload inventory advanced; use the next native background scan"
                )
            for request in requests:
                self.delivery.require_owned_payload(request)
            phase = uploads.allocations.state(model)
            if phase == "released":
                return 0
            layout = self._layout(model, bundle, stage)
            if phase == "local_reserved":
                uploads.allocations._transition(
                    model,
                    "remote_qualified",
                    evidence=dict(requests=sorted(digest(r) for r in requests), model=model),
                )
                phase = "remote_qualified"
            if phase == "remote_qualified":
                uploads.allocations._transition(
                    model, "release_prepared", evidence=dict(layout_sha256=digest(layout))
                )
            self._unlink(model, layout)
            payload = stage / "model"
            if payload.exists():
                with _directory(stage) as parent:
                    os.rmdir("model", dir_fd=parent)
                    os.fsync(parent)
            uploads.allocations._complete_release(model)
            return sum(record["allocated_bytes"] for record in layout["files"])

    def _unlink(self, model, layout):
        parent = self.uploads.archive / model
        root = parent / "model"
        if not os.path.lexists(root):
            if self.journal.get("payload_removal_intent", model) != dict(layout=digest(layout)):
                raise OSError(
                    "missing retirement payload needs explicit interrupted-operation repair"
                )
            if any(
                self.journal.get("unlink_done", digest([model, r["path"]])) is None
                for r in layout["files"]
            ):
                raise ValueError("removed retirement payload lost its completed unlink records")
            with _directory(parent) as archive:
                os.fsync(archive)
            self.journal.put("payload_removed", model, dict(layout=digest(layout)))
            return 0
        directories = {d["path"]: d["identity"] for d in layout["directories"]}
        released = 0
        with _directory(parent) as archive:
            fd = os.open(
                "model", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=archive
            )
            try:
                if _file_identity(os.fstat(fd))[:2] != directories["."][:2]:
                    raise ValueError("retirement root changed")
                # Permission changes are confined to these exact original
                # directories, after the durable allocation fence above.
                files_done = all(
                    self.journal.get("unlink_done", digest([model, r["path"]])) is not None
                    for r in layout["files"]
                )
                if not files_done:
                    for relative in sorted(directories, key=lambda p: len(Path(p).parts)):
                        child = self._open_directory(fd, relative, directories)
                        try:
                            os.fchmod(child, 0o700)
                        finally:
                            os.close(child)
                with TransferProgress(
                    "local_model_payload_unlink", len(layout["files"]), unit="files"
                ) as progress:
                    for record in layout["files"]:
                        key = digest([model, record["path"]])
                        if self.journal.get("unlink_done", key) is not None:
                            # A completed deletion must not silently authorize
                            # a newly created object at its old pathname.
                            if os.path.lexists(root / record["path"]):
                                raise ValueError("retired model payload file reappeared")
                            progress.advance(1, restored=True)
                            continue
                        relative = Path(record["path"])
                        folder = self._open_directory(fd, str(relative.parent), directories)
                        try:
                            intent = self.journal.get("unlink_intent", key)
                            try:
                                current = os.stat(
                                    relative.name, dir_fd=folder, follow_symlinks=False
                                )
                            except FileNotFoundError:
                                if intent != record:
                                    raise OSError(
                                        "unrecorded payload disappearance requires repair"
                                    ) from None
                            else:
                                if _file_identity(current) != record["identity"]:
                                    raise ValueError("retiring payload file changed")
                                if intent is None:
                                    self.journal.put("unlink_intent", key, record)
                                elif intent != record:
                                    raise ValueError("retirement unlink intent changed")
                                os.unlink(relative.name, dir_fd=folder)
                            os.fsync(folder)
                            self.journal.put(
                                "unlink_done", key, dict(model=model, path=record["path"])
                            )
                            released += record["allocated_bytes"]
                        finally:
                            os.close(folder)
                        progress.advance(1)
                # Every unlink is durable before removing empty ancestors.
                # Missing empty directories after interruption are harmless;
                # unexpected contents or changed inodes still refuse.
                for relative in sorted(
                    (p for p in directories if p != "."),
                    key=lambda p: len(Path(p).parts),
                    reverse=True,
                ):
                    directory_key = digest([model, relative, "directory"])
                    if self.journal.get("directory_removed", directory_key) is not None:
                        if os.path.lexists(root / relative):
                            raise ValueError("retired model payload directory reappeared")
                        continue
                    path = Path(relative)
                    folder = self._open_directory(fd, str(path.parent), directories)
                    try:
                        try:
                            current = os.stat(path.name, dir_fd=folder, follow_symlinks=False)
                        except FileNotFoundError:
                            if self.journal.get("directory_removal_intent", directory_key) is None:
                                raise ValueError(
                                    "retirement directory disappeared without an intent"
                                ) from None
                        else:
                            if _file_identity(current)[:2] != directories[relative][:2]:
                                raise ValueError("retiring empty directory changed")
                            self.journal.put(
                                "directory_removal_intent",
                                directory_key,
                                dict(model=model, path=relative),
                            )
                            os.rmdir(path.name, dir_fd=folder)
                        os.fsync(folder)
                        self.journal.put(
                            "directory_removed", directory_key, dict(model=model, path=relative)
                        )
                    finally:
                        os.close(folder)
                self.journal.put("payload_removal_intent", model, dict(layout=digest(layout)))
                os.rmdir("model", dir_fd=archive)
                os.fsync(archive)
                self.journal.put("payload_removed", model, dict(layout=digest(layout)))
            finally:
                os.close(fd)
        return released
