"""Incremental diagnostic summaries of already verified forecast events."""

from bisect import bisect_left, insort
from dataclasses import dataclass, field
from heapq import heappop, heappush

from .competition_forecast_scoring import completion_interval, retained_forecast, score_forecast


@dataclass
class ForecastSummary:
    started: int | None = None
    completed: int | None = None
    completion_sequence: int | None = None
    completion_range: tuple[int, int] | None = None
    first_point: dict | None = None
    first_range: dict | None = None
    last_clock: int | None = None
    regressed: bool = False
    first_finish: int | None = None
    forecasts: int = 0
    repeated: int = 0
    pending: list[int] = field(default_factory=list)
    expired: list[int] = field(default_factory=list)

    def prepare(self, event):
        """Validate additions before their transaction commits or summary mutates."""
        point = range_ = completion = None
        now = event.get("observed_unix_ms")
        timed = event["kind"] in {
            "scope_started",
            "attempt_started",
            "forecast",
            "completed",
            "attempt_terminal",
        }
        if (timed or now is not None) and (type(now) is not int or now < 0):
            raise ValueError("forecast observation requires a nonnegative integer timestamp")
        if event["kind"] == "forecast":
            point, range_ = (retained_forecast(event, metric) for metric in ("point", "range"))
        if event["kind"] == "completed" or (
            event["kind"] == "attempt_terminal" and event["state"] == "completed"
        ):
            completion = completion_interval(event)
            if (
                event.get("completion_range_unix_ms") is not None
                and self.started is not None
                and completion[0] < self.started
            ):
                raise ValueError("observed completion bracket precedes retained scope start")
        return point, range_, completion

    def accept(self, event, *, sequence, prepared=None):
        point, range_, completion = self.prepare(event) if prepared is None else prepared
        kind = event["kind"]
        now = event.get("observed_unix_ms")
        if kind == "scope_started" and self.started is None:
            self.started = now
        if self.completed is None and now is not None:
            self.regressed |= self.last_clock is not None and now < self.last_clock
            self.last_clock = now
            if kind == "completed" or (
                kind == "attempt_terminal" and event["state"] == "completed"
            ):
                self.completed = now
                self.completion_range = completion
                self.completion_sequence = sequence
        if kind == "forecast" and self.completed is None:
            if self.first_point is None:
                self.first_point = point
            if self.first_range is None:
                self.first_range = range_
        if kind == "forecast" and event.get("finish_unix_ms") is not None:
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
        terminal = self.completion_range[0] if self.completion_range is not None else now
        exact = (
            self.completion_range is None or self.completion_range[0] == self.completion_range[1]
        )
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
            if regressed or not exact
            else (terminal - self.started) / 1000,
            "elapsed_including_gaps_range_seconds": None
            if regressed or self.completion_range is None
            else [(value - self.started) / 1000 for value in self.completion_range],
            "completion_range_unix_ms": self.completion_range,
            "elapsed_basis": "since_first_retained_observation_including_restart_gaps",
            "outcome": "completed" if self.completed is not None else "unfinished",
            "completion_examples": int(self.completed is not None),
            "sample_kind": (
                "prediction_outcome"
                if self.completed is not None and self.forecasts
                else "range_prediction_outcome"
                if self.completed is not None and self.first_range is not None
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
                if self.completed is not None
                and self.first_finish is not None
                and not regressed
                and exact
                else None
            ),
            "clock_regression": regressed,
            "certification_authority": False,
        }

    def comparison(self, metric, *, observed_unix_ms, coverage_complete):
        if metric not in {"point", "range"}:
            raise ValueError("forecast comparison metric must be point or range")
        forecast = self.first_point if metric == "point" else self.first_range
        if forecast is None:
            return None
        regressed = self.regressed or (
            self.completed is None
            and self.last_clock is not None
            and observed_unix_ms < self.last_clock
        )
        return score_forecast(
            forecast,
            self.completion_range,
            observed_unix_ms=observed_unix_ms,
            metric=metric,
            coverage_complete=coverage_complete,
            clock_regression=regressed,
        )
