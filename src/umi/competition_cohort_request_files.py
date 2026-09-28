"""Immutable evaluator exports consumed by the request owner after delivery.

Indexes name the original signed order and terminal. All referenced objects are
copied before either index becomes visible. Missing delivery stays pending;
readers never open an evaluator's live database or infer a failed outcome.
"""

from collections import OrderedDict
from collections.abc import Iterator
from pathlib import Path
from threading import Lock

from .competition_cohort_endpoint_archive import EndpointObjectSource, read_endpoint_object
from .competition_cohort_orders import SignedRecoverableEvaluationOrder
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

    def current(self, terminal_sha: str) -> bool:
        """Reuse an in-process publication only while every output is unchanged.

        Restart always replays native originals. A missing, replaced or changed
        file invalidates reuse and the next export repairs or rejects it.
        This optimization never supplies evidence to the closure reviewer.
        """
        with self._cache_lock:
            record = self._published.get(terminal_sha)
            if record is None:
                return False
            try:
                unchanged = all(self._stamp(path) == stamp for path, stamp in record)
            except OSError:
                unchanged = False
            if unchanged:
                self._published.move_to_end(terminal_sha)
            else:
                self._cached_paths -= len(self._published.pop(terminal_sha))
            return unchanged

    def _remember(self, terminal_sha, paths):
        with self._cache_lock:
            self._cached_paths -= len(self._published.pop(terminal_sha, ()))
            if len(paths) > 65536:
                return
            while self._published and self._cached_paths + len(paths) > 65536:
                _, old = self._published.popitem(last=False)
                self._cached_paths -= len(old)
            self._published[terminal_sha] = tuple((p, self._stamp(p)) for p in paths)
            self._cached_paths += len(paths)

    def _order_path(self, round_sha: str, submission: str) -> Path:
        # Both keys are derived from validated native objects by callers.
        return self.root / "orders" / round_sha / (submission + ".json")

    def _terminal_path(self, order, evaluator) -> Path:
        return self.root / "terminals" / digest(order) / (identity(evaluator) + ".json")

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
            self.objects.publish(key, collected.values.__getitem__)
        order_path = self._order_path(
            digest(order.order.round), digest(order.order.submission.submission)
        )
        terminal_path = self._terminal_path(order, assignment.delivery.receipt.evaluator_hotkey)
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
        self._remember(
            digest(signed),
            (
                order_path,
                terminal_path,
                *(self.objects._path(key) for key in sorted(collected.values)),
            ),
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
