"""Per-item audit checkpoints over an immutable, ordered native inventory."""

from .competition_evidence_codec import checked_digest
from .competition_reward_handoff_reuse import repair_required
from .competition_work_progress import WorkProgress, check_work_cancelled, work_heartbeats


class EvidenceAuditProgress:
    """Keep one atomic ordered-prefix receipt per evidence kind, not per object.

    The native owner binds the source snapshot, limits and verifier semantics and
    holds its verification lock. A prefix is reusable only within that exact
    immutable inventory. Each newly verified item advances durable completion.
    """

    def __init__(self, verification, context, recheck):
        self.verification, self.context, self.recheck = verification, context, recheck

    def run(self, kind, total, items, verify):
        if kind not in {"legacy", "objects", "records", "continuity"}:
            raise ValueError("unsupported native evidence audit kind")
        if type(total) is not int or total < 0:
            raise ValueError("invalid native evidence audit count")
        context = {"inventory": self.context, "kind": kind, "total": total, "order": "key_asc/1"}
        saved = self.verification.load("evidence_frontier", kind, context)
        if saved is None:
            saved = {"completed": 0, "last_key": None}
            self.recheck()
            self.verification.remember("evidence_frontier", kind, context, saved)
        if (
            set(saved) != {"completed", "last_key"}
            or type(saved["completed"]) is not int
            or not 0 <= saved["completed"] <= total
            or (saved["last_key"] is None) != (saved["completed"] == 0)
        ):
            raise repair_required("evidence_frontier_invalid")
        if saved["last_key"] is not None:
            checked_digest(saved["last_key"])
        self.recheck()
        iterator = iter(items)
        previous = None
        with (
            work_heartbeats(),
            WorkProgress(
                "legacy_evidence_" + kind + "_restore", saved["completed"], unit="items"
            ) as meter,
        ):
            for _ in range(saved["completed"]):
                check_work_cancelled()
                try:
                    key, _ = next(iterator)
                except StopIteration:
                    raise repair_required("evidence_frontier_inventory_missing") from None
                checked_digest(key)
                if previous is not None and key <= previous:
                    raise repair_required("evidence_frontier_order_changed")
                previous = key
                meter.advance()
        if previous != saved["last_key"]:
            raise repair_required("evidence_frontier_key_changed")
        self.recheck()
        completed = saved["completed"]
        with (
            work_heartbeats(),
            WorkProgress(
                "legacy_evidence_" + kind + "_audit", total - completed, unit="items"
            ) as meter,
        ):
            for key, size in iterator:
                check_work_cancelled()
                checked_digest(key)
                if completed >= total or (previous is not None and key <= previous):
                    raise repair_required("evidence_frontier_inventory_changed")
                verify(key, size)
                self.recheck()
                completed += 1
                self.verification.remember(
                    "evidence_frontier",
                    kind,
                    context,
                    {"completed": completed, "last_key": key},
                )
                previous = key
                meter.advance()
        if completed != total:
            raise repair_required("evidence_frontier_inventory_missing")
        self.recheck()
