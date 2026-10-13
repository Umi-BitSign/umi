"""Bounded repair intent and outcome in the original owned history journal.

These are operator audit records, never verification receipts or native issuer
tokens. Every repeat still runs the history reader, which checks current source
identities and owned finality before returning a successful interval.
"""

from dataclasses import asdict

from .competition_reward_history import RewardControlHistoryReader, validate_control_history
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .open_competition import digest

INTENT = "control_history_repair_intent"
RESULT = "control_history_repair_result"
DONE = "control_history_repair_complete"


class HistoryRepairRequest:
    def __init__(self, reader: RewardControlHistoryReader, through_block: int, reason: str):
        if type(through_block) is not int or not reader.first_block <= through_block < 2**53:
            raise ValueError("repair request target differs from its finite history interval")
        if type(reason) is not str or not reason.strip():
            raise ValueError("repair request requires an explicit reason")
        self.reader, self.journal = reader, reader.journal
        self.intent = {
            "schema": "umi-owned-history-repair-intent/1",
            "owner": reader.checkpoints.owner,
            "semantics": reader.checkpoints.semantics,
            "chain_config_sha256": reader.config_sha256,
            "control_hotkey": reader.hotkey,
            "first_block": reader.first_block,
            "through_block": through_block,
            "reason": reason,
        }
        self.sha256 = digest(self.intent)
        self._check()
        self.journal.put(INTENT, self.sha256, self.intent)

    def _check(self, *, require_intent=False):
        try:
            with self.journal.read_transaction() as db:
                intent = self.journal.get(INTENT, self.sha256, db=db)
                result = self.journal.get(RESULT, self.sha256, db=db)
                done = self.journal.get(DONE, self.sha256, db=db)
            if intent not in (None, self.intent):
                raise ValueError("repair intent changed")
            if require_intent and intent is None:
                raise ValueError("repair intent disappeared during owned work")
            if (result is not None or done is not None) and (
                intent is None
                or not isinstance(result, dict)
                or set(result)
                != {
                    "schema",
                    "request_sha256",
                    "owner",
                    "semantics",
                    "status",
                    "first_block",
                    "tip",
                    "completed_blocks",
                }
                or result["schema"] != "umi-owned-history-repair-result/1"
                or result["request_sha256"] != self.sha256
                or result["owner"] != self.intent["owner"]
                or result["semantics"] != self.intent["semantics"]
                or result["status"] != "completed"
                or result["first_block"] != self.intent["first_block"]
                or result["completed_blocks"]
                != (self.intent["through_block"] - self.intent["first_block"] + 1)
                or not isinstance(result["tip"], dict)
                or result["tip"].get("block_number") != self.intent["through_block"]
                or done != {"request_sha256": self.sha256, "result_sha256": digest(result)}
            ):
                raise ValueError("completed repair audit metadata is missing or damaged")
        except ValueError as error:
            raise HistoryCheckpointRepairRequired(
                "repair request metadata requires original in-place recovery"
            ) from error

    def finish(self, history) -> None:
        validate_control_history(
            history,
            first_block=self.reader.first_block,
            tip=history.tip,
            control_hotkey=self.reader.hotkey,
            chain_config_sha256=self.reader.config_sha256,
        )
        if history.tip.block_number != self.intent["through_block"]:
            raise ValueError("repair result did not complete the selected interval")
        self._check(require_intent=True)
        # Repeated completion of the same fixed finalized interval is the same
        # audit outcome, even when this attempt restored more checkpoint facts.
        # Current source validity is always determined by the native reader.
        result = {
            "schema": "umi-owned-history-repair-result/1",
            "request_sha256": self.sha256,
            "owner": self.intent["owner"],
            "semantics": self.intent["semantics"],
            "status": "completed",
            "first_block": history.first_block,
            "tip": asdict(history.tip),
            "completed_blocks": history.tip.block_number - history.first_block + 1,
        }
        self.journal.put_many(
            (
                (RESULT, self.sha256, result),
                (
                    DONE,
                    self.sha256,
                    {"request_sha256": self.sha256, "result_sha256": digest(result)},
                ),
            )
        )
