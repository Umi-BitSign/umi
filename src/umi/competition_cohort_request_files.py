"""Immutable evaluator exports consumed by the request owner after delivery.

Indexes name original signed orders, terminals and partial-work snapshots. All
referenced objects are copied before an index becomes visible. Missing delivery stays pending;
readers never open an evaluator's live database or infer a failed outcome.
"""

import os
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from threading import Lock

from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    JournalEndpointObjects,
    read_endpoint_object,
)
from .competition_cohort_execution_journal import (
    CohortExecutionAssignment,
    CohortExecutionJournal,
    step_count,
)
from .competition_cohort_orders import SignedRecoverableEvaluationOrder
from .competition_cohort_request_inventory import RequestInventory, read_request_inventory
from .competition_cohort_request_partial import (
    MAX_PARTIAL_ITEMS,
    PartialRequestManifest,
    collect_partial_request,
    review_partial_request,
)
from .competition_cohort_request_reuse import (
    PublicationFileStamp,
    PublicationVerificationReceipt,
    load_publication_verification,
    remember_publication_verification,
)
from .competition_cohort_request_terminal import SignedRequestTerminal, read_request_terminal
from .competition_cohort_reward_package import DEFAULT_PACKAGE_BYTES, ReplayObjectCollector
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .open_competition import CompetitionPolicy, digest, identity
from .private_files import ensure_private_directory, private_path, publish_private_model
from .private_files import read_private_model as read
from .protocol import Hex32, StrictProtocolModel


class _Reference(StrictProtocolModel):
    sha256: Hex32


class RequestCompletionFiles:
    def __init__(self, root: Path, *, maximum_bytes=DEFAULT_PACKAGE_BYTES):
        self.root = Path(private_path(str(root)))
        ensure_private_directory(self.root)
        self.objects = SettlementEvidenceFiles(self.root / "objects")
        self.maximum_bytes = maximum_bytes
        ReplayObjectCollector(self.objects, maximum_bytes)
        self._published = OrderedDict()
        self._cached_paths = 0
        self._cache_lock = Lock()
        self._publication_lock = Lock()
        self._pid = os.getpid()

    @staticmethod
    def _stamp(path):
        info = path.lstat()
        return (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def current(
        self,
        terminal_sha: str,
        *,
        policy_sha256: str,
        opened_at_block: int,
        completed_by_block: int,
    ) -> bool:
        """Reuse a successful local publication while every output is unchanged.

        A private receipt preserves this result after restart. A missing, changed
        or replaced output, another policy, or a narrower verification interval
        requires replay. Closure reviewers still verify their own evidence.
        """
        if os.getpid() != self._pid:
            return False
        key = (terminal_sha, policy_sha256)
        with self._cache_lock:
            record = self._published.get(key)
            if record is None:
                record = load_publication_verification(self.root, terminal_sha, policy_sha256)
            if record is None or (
                record.maximum_bytes != self.maximum_bytes
                or opened_at_block > record.opened_at_block
                or completed_by_block < record.completed_by_block
            ):
                return False
            try:
                unchanged = all(
                    tuple(
                        str(v)
                        for v in self._stamp(Path(private_path(str(self.root / f.relative_path))))
                    )
                    == f.stamp
                    for f in record.files
                )
            except (OSError, ValueError):
                unchanged = False
            if unchanged:
                self._remember_cached(key, record)
            else:
                old = self._published.pop(key, None)
                if old is not None:
                    self._cached_paths -= len(old.files)
            return unchanged

    def _remember_cached(self, key, receipt):
        old = self._published.pop(key, None)
        if old is not None:
            self._cached_paths -= len(old.files)
        while self._published and self._cached_paths + len(receipt.files) > 65536:
            _, old = self._published.popitem(last=False)
            self._cached_paths -= len(old.files)
        self._published[key] = receipt
        self._cached_paths += len(receipt.files)

    def _remember(self, receipt):
        if os.getpid() != self._pid:
            return
        with self._cache_lock:
            self._remember_cached((receipt.terminal_sha256, receipt.policy_sha256), receipt)
            # Concurrent exports share one nonblocking private cache mutex.
            # Serialize our own writes so a successful publication also keeps
            # its restart receipt instead of treating local contention as a miss.
        with self._publication_lock:
            remember_publication_verification(self.root, receipt)

    def _order_path(self, round_sha: str, submission: str) -> Path:
        # Both keys are derived from validated native objects by callers.
        return self.root / "orders" / round_sha / (submission + ".json")

    def _terminal_path(self, order, evaluator) -> Path:
        return self.root / "terminals" / digest(order) / (identity(evaluator) + ".json")

    def _partial_directory(self, order, evaluator) -> Path:
        return (
            self.root
            / "partials"
            / digest(order.order.round)
            / digest(order.order.submission.submission)
            / identity(evaluator)
        )

    def publish_partial(
        self, owner: CohortExecutionJournal, slot: str, *, completed_by_block: int
    ) -> str:
        """Deliver original partial work without sealing or signing a terminal."""
        collected = ReplayObjectCollector(JournalEndpointObjects(owner.journal), self.maximum_bytes)
        manifest = collect_partial_request(owner, slot, collected)
        key = collected.retain(manifest)
        if self.current(
            key,
            policy_sha256=digest(owner.policy),
            opened_at_block=0,
            completed_by_block=completed_by_block,
        ):
            return key
        assignment = owner.assignment(slot)
        review_partial_request(
            key,
            collected,
            owner.policy,
            assignment.certificate,
            opened_at_block=0,
            completed_by_block=completed_by_block,
        )
        order = assignment.certificate
        for sha in sorted(collected.values):
            with self._publication_lock:
                self.objects.publish(sha, collected.values.__getitem__)
        order_path = self._order_path(
            digest(order.order.round), digest(order.order.submission.submission)
        )
        index = self._partial_directory(order, assignment.delivery.receipt.evaluator_hotkey) / (
            f"{manifest.item_count:05d}.json"
        )
        with self._publication_lock:
            publish_private_model(order_path, _Reference(sha256=digest(order)), maximum_bytes=1024)
            publish_private_model(index, _Reference(sha256=key), maximum_bytes=1024)
        paths = (order_path, index, *(self.objects._path(sha) for sha in sorted(collected.values)))
        with suppress(OSError, ValueError):
            if len(paths) <= 65536:
                self._remember(
                    PublicationVerificationReceipt(
                        schema="umi-private-request-publication/1",
                        terminal_sha256=key,
                        policy_sha256=digest(owner.policy),
                        maximum_bytes=self.maximum_bytes,
                        opened_at_block=0,
                        completed_by_block=completed_by_block,
                        files=tuple(
                            PublicationFileStamp(
                                relative_path=str(path.relative_to(self.root)),
                                stamp=tuple(str(v) for v in self._stamp(path)),
                            )
                            for path in paths
                        ),
                    )
                )
        return key

    def partial(self, roster: RecoverableRosterEvidence, submission_sha256: str) -> tuple[str, ...]:
        """Select immutable latest snapshots; closure reviewers replay every object."""
        if submission_sha256 not in {p.submission_sha256 for p in roster.round.participants}:
            raise ValueError("partial request is outside its original roster")
        try:
            ref = read(
                self._order_path(digest(roster.round), submission_sha256),
                _Reference,
                maximum_bytes=1024,
            )
        except FileNotFoundError:
            return ()
        order = SignedRecoverableEvaluationOrder.model_validate_json(
            read_endpoint_object(self.objects, ref.sha256)
        )
        if (
            order.order.round != roster.round
            or digest(order.order.submission.submission) != submission_sha256
        ):
            raise ValueError("partial request changed its original selected order")
        selected = []
        for evaluator in order.order.evaluators:
            if self.terminal(order, evaluator) is not None:
                continue
            directory = self._partial_directory(order, evaluator)
            private_path(str(directory))
            latest = None
            try:
                with os.scandir(directory) as entries:
                    count = 0
                    for entry in entries:
                        if entry.name.startswith("."):
                            continue
                        count += 1
                        number = entry.name.removesuffix(".json")
                        if (
                            count > MAX_PARTIAL_ITEMS + 1
                            or len(number) != 5
                            or not number.isascii()
                            or not number.isdigit()
                            or not entry.name.endswith(".json")
                            or int(number) > MAX_PARTIAL_ITEMS
                        ):
                            raise ValueError("partial request index exceeds its bounded inventory")
                        if latest is None or entry.name > latest:
                            latest = entry.name
            except FileNotFoundError:
                raise FileNotFoundError(
                    "original evaluator partial inventory is not delivered"
                ) from None
            if latest is None:
                raise FileNotFoundError("original evaluator partial inventory is not delivered")
            ref = read(directory / latest, _Reference, maximum_bytes=1024)
            manifest = PartialRequestManifest.model_validate_json(
                read_endpoint_object(self.objects, ref.sha256)
            )
            assignment = CohortExecutionAssignment.model_validate_json(
                read_endpoint_object(self.objects, manifest.assignment_sha256)
            )
            if (
                manifest.item_count != int(latest.removesuffix(".json"))
                or assignment.certificate != order
                or identity(assignment.delivery.receipt.evaluator_hotkey) != identity(evaluator)
            ):
                raise ValueError(
                    "partial request index changed its original assignment or progress"
                )
            selected.append(ref.sha256)
        return tuple(sorted(selected))

    def collect_inventory(self, owner, slot, observation):
        """Read the owning journal consistently, without a job lock or network I/O.

        A short native writer reservation prevents independently owned case
        workers from changing the inventory between its immutable record reads.
        It ends before export, proof delivery or signing and changes no records.
        """
        collected = ReplayObjectCollector(JournalEndpointObjects(owner.journal), self.maximum_bytes)
        with owner.journal.transaction() as db:
            if any(
                owner.journal.get(kind, slot, db=db) is not None
                for kind in ("request_terminal", "request_terminal_intent")
            ):
                raise FileNotFoundError("completed request awaits original terminal delivery")
            assignment, job = owner.assignment_and_job(slot)
            for index in range(step_count(job)):
                if owner.step(job, index, db=db) is None:
                    attempt = owner.head(job, index, db=db)
                    if attempt is not None and owner.result(job, attempt, db=db) is not None:
                        raise FileNotFoundError(
                            "completed execution awaits its original finish observation"
                        )
            manifest = collect_partial_request(owner, slot, collected)
            key = collected.retain(manifest)
            review_partial_request(
                key,
                collected,
                owner.policy,
                assignment.certificate,
                opened_at_block=0,
                completed_by_block=observation.block,
            )
        return (
            RequestInventory(
                schema="umi-cohort-request-inventory/1",
                assignment_sha256=digest(assignment),
                policy_sha256=digest(owner.policy),
                manifest_sha256=key,
                observation=observation,
            ),
            assignment,
            manifest,
            collected,
        )

    def publish_inventory(self, signed, assignment, manifest, collected):
        """Publish originals first and an immutable signed inventory index last."""
        key = collected.retain(signed)
        body = signed.inventory
        if (
            body.assignment_sha256 != digest(assignment)
            or body.manifest_sha256 != digest(manifest)
            or identity(signed.signature.hotkey)
            != identity(assignment.delivery.receipt.evaluator_hotkey)
        ):
            raise ValueError("request inventory publication changed its original assignment")
        order = assignment.certificate
        directory = (
            self.root
            / "inventories"
            / digest(order.order.round)
            / digest(order.order.submission.submission)
            / identity(assignment.delivery.receipt.evaluator_hotkey)
        )
        name = f"{body.observation.block:016d}-{manifest.item_count:05d}-{key}.json"
        self.publish_inventory_objects(collected)
        with self._publication_lock:
            publish_private_model(
                self._order_path(
                    digest(order.order.round), digest(order.order.submission.submission)
                ),
                _Reference(sha256=digest(order)),
                maximum_bytes=1024,
            )
            publish_private_model(directory / name, _Reference(sha256=key), maximum_bytes=1024)
        return key

    def publish_inventory_objects(self, collected):
        for sha in sorted(collected.values):
            with self._publication_lock:
                self.objects.publish(sha, collected.values.__getitem__)

    def recover_inventory(self, body, policy):
        """Recover exact exported originals before retrying a retained signature."""
        collected = ReplayObjectCollector(self.objects, self.maximum_bytes)
        assignment = CohortExecutionAssignment.model_validate_json(
            collected(body.assignment_sha256)
        )
        manifest = PartialRequestManifest.model_validate_json(collected(body.manifest_sha256))
        reviewed = review_partial_request(
            body.manifest_sha256,
            collected,
            policy,
            assignment.certificate,
            opened_at_block=0,
            completed_by_block=body.observation.block,
        )
        if reviewed != assignment or body.policy_sha256 != digest(policy):
            raise ValueError("retained inventory changed its original assignment or policy")
        return assignment, manifest, collected

    def inventories(
        self, roster, submission_sha256, *, selected_at_block, completed_by_block
    ) -> tuple[str, ...]:
        """Select each missing evaluator's authenticated post-cutoff snapshot."""
        if submission_sha256 not in {p.submission_sha256 for p in roster.round.participants}:
            raise ValueError("request inventory is outside its original roster")
        ref = read(
            self._order_path(digest(roster.round), submission_sha256),
            _Reference,
            maximum_bytes=1024,
        )
        order = SignedRecoverableEvaluationOrder.model_validate_json(
            read_endpoint_object(self.objects, ref.sha256)
        )
        if (
            order.order.round != roster.round
            or digest(order.order.submission.submission) != submission_sha256
        ):
            raise ValueError("request inventory changed its original selected order")
        selected = []
        for evaluator in order.order.evaluators:
            if self.terminal(order, evaluator) is not None:
                continue
            directory = (
                self.root
                / "inventories"
                / digest(roster.round)
                / submission_sha256
                / identity(evaluator)
            )
            private_path(str(directory))
            latest = None
            try:
                with os.scandir(directory) as entries:
                    count = 0
                    for entry in entries:
                        if entry.name.startswith("."):
                            continue
                        count += 1
                        parts = entry.name.removesuffix(".json").split("-")
                        if (
                            count > 65536
                            or len(parts) != 3
                            or not entry.name.endswith(".json")
                            or len(parts[0]) != 16
                            or not parts[0].isascii()
                            or not parts[0].isdigit()
                            or len(parts[1]) != 5
                            or not parts[1].isascii()
                            or not parts[1].isdigit()
                            or int(parts[1]) > MAX_PARTIAL_ITEMS
                            or len(parts[2]) != 64
                            or any(c not in "0123456789abcdef" for c in parts[2])
                        ):
                            raise ValueError("request inventory index exceeds its bounded identity")
                        if selected_at_block < int(parts[0]) <= completed_by_block and (
                            latest is None or entry.name > latest
                        ):
                            latest = entry.name
            except FileNotFoundError:
                pass
            if latest is None:
                raise FileNotFoundError("post-cutoff evaluator inventory is not delivered")
            ref = read(directory / latest, _Reference, maximum_bytes=1024)
            signed = read_request_inventory(ref.sha256, self.objects)
            manifest = PartialRequestManifest.model_validate_json(
                read_endpoint_object(self.objects, signed.inventory.manifest_sha256)
            )
            assignment = CohortExecutionAssignment.model_validate_json(
                read_endpoint_object(self.objects, signed.inventory.assignment_sha256)
            )
            expected = (
                f"{signed.inventory.observation.block:016d}-"
                f"{manifest.item_count:05d}-{ref.sha256}.json"
            )
            if (
                latest != expected
                or assignment.certificate != order
                or manifest.assignment_sha256 != digest(assignment)
                or identity(assignment.delivery.receipt.evaluator_hotkey) != identity(evaluator)
            ):
                raise ValueError(
                    "request inventory index changed its original assignment or progress"
                )
            selected.append(ref.sha256)
        return tuple(sorted(selected))

    def publish(
        self,
        signed: SignedRequestTerminal,
        source: EndpointObjectSource,
        policy: CompetitionPolicy,
        *,
        opened_at_block: int,
        completed_by_block: int,
    ) -> None:
        collected = ReplayObjectCollector(source, self.maximum_bytes)
        assignment = read_request_terminal(
            signed,
            collected,
            policy,
            opened_at_block=opened_at_block,
            completed_by_block=completed_by_block,
        )
        order = assignment.certificate
        collected.retain(order)
        collected.retain(signed)
        for key in sorted(collected.values):
            # Native verification can run concurrently, but the private file
            # publisher owns one nonblocking mutex per destination directory.
            # Queue each small publication locally instead of turning our own
            # concurrent exports into cross-process contention retries.
            with self._publication_lock:
                self.objects.publish(key, collected.values.__getitem__)
        order_path = self._order_path(
            digest(order.order.round), digest(order.order.submission.submission)
        )
        terminal_path = self._terminal_path(order, assignment.delivery.receipt.evaluator_hotkey)
        with self._publication_lock:
            publish_private_model(
                order_path,
                _Reference(sha256=digest(order)),
                maximum_bytes=1024,
            )
            publish_private_model(
                terminal_path,
                _Reference(sha256=digest(signed)),
                maximum_bytes=1024,
            )
        paths = (
            order_path,
            terminal_path,
            *(self.objects._path(key) for key in sorted(collected.values)),
        )
        # Cache bookkeeping cannot turn a durable successful publication into
        # a failed export. A missing receipt simply requires native replay.
        with suppress(OSError, ValueError):
            if len(paths) > 65536:
                return
            self._remember(
                PublicationVerificationReceipt(
                    schema="umi-private-request-publication/1",
                    terminal_sha256=digest(signed),
                    policy_sha256=digest(policy),
                    maximum_bytes=self.maximum_bytes,
                    opened_at_block=opened_at_block,
                    completed_by_block=completed_by_block,
                    files=tuple(
                        PublicationFileStamp(
                            relative_path=str(path.relative_to(self.root)),
                            stamp=tuple(str(v) for v in self._stamp(path)),
                        )
                        for path in paths
                    ),
                )
            )

    def orders(
        self, roster: RecoverableRosterEvidence
    ) -> Iterator[SignedRecoverableEvaluationOrder]:
        for participant in roster.round.participants:
            try:
                ref = read(
                    self._order_path(digest(roster.round), participant.submission_sha256),
                    _Reference,
                    maximum_bytes=1024,
                )
            except FileNotFoundError:
                continue
            order = SignedRecoverableEvaluationOrder.model_validate_json(
                read_endpoint_object(self.objects, ref.sha256)
            )
            if (
                order.order.round != roster.round
                or digest(order.order.submission.submission) != participant.submission_sha256
            ):
                raise ValueError("delivered request order differs from its selected participant")
            yield order

    def terminal(
        self, order: SignedRecoverableEvaluationOrder, evaluator: str
    ) -> SignedRequestTerminal | None:
        try:
            ref = read(self._terminal_path(order, evaluator), _Reference, maximum_bytes=1024)
        except FileNotFoundError:
            return None
        signed = SignedRequestTerminal.model_validate_json(
            read_endpoint_object(self.objects, ref.sha256)
        )
        if identity(signed.signature.hotkey) != identity(evaluator):
            raise ValueError("delivered request terminal changed its evaluator")
        # The native closure replays the assignment, signature and full read set.
        return signed
