"""Incremental diagnostic summaries of already verified forecast events."""

from bisect import bisect_left, insort
from dataclasses import dataclass, field
from heapq import heappop, heappush


@dataclass
class ForecastSummary:
    started: int | None = None
    completed: int | None = None
    last_clock: int | None = None
    regressed: bool = False
    first_finish: int | None = None
    forecasts: int = 0
    repeated: int = 0
    pending: list[int] = field(default_factory=list)
    expired: list[int] = field(default_factory=list)

    def accept(self, event):
        kind = event["kind"]
        now = event.get("observed_unix_ms")
        if kind == "scope_started":
            self.started = now
        if self.completed is None and now is not None:
            self.regressed |= self.last_clock is not None and now < self.last_clock
            self.last_clock = now
            if kind == "completed" or (
                kind == "attempt_terminal" and event["state"] == "completed"
            ):
                self.completed = now
        if kind == "forecast" and event["finish_unix_ms"] is not None:
            if self.completed is not None:
                self.repeated += 1
            else:
                finish = event["finish_unix_ms"]
                if self.first_finish is None:
                    self.first_finish = finish
                self.forecasts += 1
                heappush(self.pending, finish)

    def status(self, scope, now):
        if self.started is None:
            raise ValueError("forecast scope has no retained start")
        terminal = self.completed if self.completed is not None else now
        # Each deadline crosses the heap once. Ordinary forward observation is
        # O(log n) per expired forecast, with no JSON or original-event reread.
        # A historical query can use the sorted expired prefix without changing
        # event chronology or rescanning it. Its earlier timestamp is not a
        # claimed backward clock correction by the owner.
        while self.pending and self.pending[0] < terminal:
            value = heappop(self.pending)
            if not self.expired or value >= self.expired[-1]:
                self.expired.append(value)
            else:
                # Only needed after an out-of-order query or backward clock.
                insort(self.expired, value)
        missed = bisect_left(self.expired, terminal)
        regressed = self.regressed or (
            self.completed is None and self.last_clock is not None and now < self.last_clock
        )
        return {
            "status": "retained",
            "scope_sha256": scope,
            "elapsed_including_gaps_seconds": None
            if regressed
            else (terminal - self.started) / 1000,
            "elapsed_basis": "since_first_retained_observation_including_restart_gaps",
            "outcome": "completed" if self.completed is not None else "unfinished",
            "completion_examples": int(self.completed is not None),
            "sample_kind": (
                "prediction_outcome"
                if self.completed is not None and self.forecasts
                else "duration_only"
                if self.completed is not None
                else "pending"
            ),
            "issued_forecasts": self.forecasts,
            "repeat_attempt_forecasts_excluded": self.repeated,
            "missed_forecasts": None if regressed else missed if self.completed is not None else 0,
            "overdue_unfinished_forecasts": None
            if regressed
            else missed
            if self.completed is None
            else 0,
            "first_forecast_error_seconds": (
                (terminal - self.first_finish) / 1000
                if self.completed is not None and self.first_finish is not None and not regressed
                else None
            ),
            "clock_regression": regressed,
            "certification_authority": False,
        }
