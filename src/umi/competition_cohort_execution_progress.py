"""Advisory model-execution counts from delivered immutable export metadata.

The lifecycle background worker owns sampling. HTTP readers only see its cached
snapshot. This never opens a journal, replays proofs, reads model payloads or
provides closure authority. Persisted small facts avoid rereading unchanged
orders and manifests on subsequent samples or after an owner restart.
"""

import json
import os
import re
import time
from pathlib import Path

from pydantic import JsonValue, RootModel

from .competition_public_results_directory import atomic_write
from .open_competition import digest, identity
from .private_files import (
    _read_private_bytes,
    ensure_private_directory,
    private_path,
    publish_private_model,
    read_private_model,
)
from .protocol import canonical_json_bytes

_Facts = RootModel[dict[str, JsonValue]]
_MAX_BYTES = 16 * 1024**2
_SCHEMA = "umi-private-execution-progress/1"
_COUNTS = (
    "completed",
    "total",
    "exported_executions",
    "exported_inferences",
    "reused_incumbent_observations",
    "exported_comparisons",
    "delivered_orders",
    "delivered_order_executions",
    "projected_executions",
    "projection_basis",
)


class _PendingExport(Exception):
    """A new delivered reference precedes its not-yet-delivered object."""


def _hex(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("execution progress contains an invalid object identity")
    return value


class ExecutionExportProgress:
    def __init__(self, root, roster):
        self.root = Path(private_path(str(root)))
        self.round = digest(roster.round)
        self.cohort = roster.round.cohort_sha256
        self.selected = tuple(
            digest(p.record.request.signed_submission.submission)
            for p in roster.participants
            if p.record.request.signed_submission.submission.track == "model"
        )
        self.checkpoint = self.root / "diagnostics" / (self.round + ".json")
        self.initialized = self.root / "diagnostics" / (self.round + "-initialized.json")
        self.facts, self.loaded = {}, False
        self.started = time.monotonic()
        self.rate_origin = None
        self.rate_epoch = None
        try:
            self.clock_identity = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            self.clock_identity = None
        self.saved = None
        self.last_snapshot = {}
        self.required_producers = set()
        self.forecast = None
        self.forecast_epoch = None
        self.forecast_closed = False
        self.last_progress = (self.started, None)

    def _fact(self, relative, kind):
        path = self.root / relative
        private_path(str(path))
        stat = path.lstat()
        stamp = [
            str(v)
            for v in (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        ]
        key = kind + ":" + relative
        self.used.add(key)
        previous = self.facts.get(key)
        if previous is not None and previous["stamp"] == stamp:
            return previous["value"]
        raw = _read_private_bytes(path, maximum_bytes=_MAX_BYTES)
        self.read_bytes += len(raw)
        if self.read_bytes > 64 * 1024**2:
            raise ValueError("execution progress metadata exceeds its sample budget")
        value = json.loads(raw)
        if kind == "reference":
            value = _hex(value["sha256"])
        else:
            if value["sha256"] != path.stem:
                raise ValueError("execution progress object wrapper changed identity")
            value = value["value"]
            if kind == "order":
                body = value["order"]
                evaluators = body["evaluators"]
                if not 1 <= len(evaluators) <= 64 or len(set(evaluators)) != len(evaluators):
                    raise ValueError("execution progress evaluator count is invalid")
                if any(re.fullmatch(r"[A-Za-z0-9]{1,64}", e) is None for e in evaluators):
                    raise ValueError("execution progress evaluator path is invalid")
                value = dict(
                    round=digest(body["round"]),
                    submission=digest(body["submission"]["submission"]),
                    track=body["submission"]["submission"]["track"],
                    cases=len(body["cases"]),
                    evaluators=[identity(e) for e in evaluators],
                )
            elif kind == "terminal":
                value = _hex(value["terminal"]["execution_archive_sha256"])
            elif kind in {"partial", "archive"}:
                steps = value["steps"]
                indices = (
                    [s["index"] for s in steps] if kind == "partial" else list(range(len(steps)))
                )
                if len(indices) > 4096 or len(set(indices)) != len(indices):
                    raise ValueError("execution progress repeats a saved step")
                if any(type(i) is not int or not 0 <= i < 4096 for i in indices):
                    raise ValueError("execution progress step index is invalid")
                value = (
                    dict(indices=indices, reused=sum(index % 2 for index in indices))
                    if value.get("schema")
                    in {"umi-cohort-partial-request/2", "umi-request-execution-archive/2"}
                    else indices
                )
        self.facts[key] = dict(stamp=stamp, value=value)
        return value

    def _object(self, key, kind):
        relative = "objects/" + _hex(key) + ".json"
        try:
            return self._fact(relative, kind)
        except FileNotFoundError:
            if kind + ":" + relative in self.facts:
                raise  # Disappearance of an already checked original is repair.
            raise _PendingExport from None

    def _persist(self):
        origin = None
        if self.rate_origin is not None and self.rate_epoch is not None and self.clock_identity:
            origin = dict(
                epoch=self.rate_epoch,
                clock=self.clock_identity,
                monotonic_ms=round(self.rate_origin[0] * 1000),
                completed=self.rate_origin[1],
            )
        saved = dict(
            schema=_SCHEMA,
            round=self.round,
            facts=self.facts,
            last_snapshot=self.last_snapshot,
            rate_origin=origin,
        )
        if saved != self.saved:
            ensure_private_directory(self.checkpoint.parent)
            private_path(str(self.checkpoint))
            raw = canonical_json_bytes(_Facts(saved))
            if len(raw) > _MAX_BYTES:
                raise ValueError("execution progress checkpoint exceeds its byte budget")
            atomic_write(self.checkpoint, raw, immutable=False)
            self.saved = {**saved, "facts": dict(self.facts)}
        if not self.initialized.exists():
            publish_private_model(self.initialized, _Facts(dict(schema=_SCHEMA, round=self.round)))

    def _latest_partial(self, submission, evaluator):
        directory = self.root / "partials" / self.round / submission / evaluator
        private_path(str(directory))
        prefix = "reference:" + str(directory.relative_to(self.root)) + "/"
        try:
            with os.scandir(directory) as entries:
                names = []
                for entry in entries:
                    if entry.name.startswith("."):
                        continue
                    if re.fullmatch(r"[0-9]{5}\.json", entry.name) is None:
                        raise ValueError("execution progress partial index is invalid")
                    names.append(entry.name)
                    if len(names) > 8193:
                        raise ValueError("execution progress partial inventory exceeds its bound")
        except FileNotFoundError:
            if any(key.startswith(prefix) for key in self.facts):
                raise
            return []
        if not names:
            if any(key.startswith(prefix) for key in self.facts):
                raise ValueError("previously delivered partial export is missing")
            return []
        ref = str((directory / max(names)).relative_to(self.root))
        return self._object(self._fact(ref, "reference"), "partial")

    def _sample(self):
        completed = executions = comparisons = orders = delivered_total = reused = 0
        profiles = set()
        producers = set()
        for submission in self.selected:
            path = f"orders/{self.round}/{submission}.json"
            try:
                key = self._fact(path, "reference")
            except FileNotFoundError:
                if "reference:" + path in self.facts:
                    raise
                continue  # A not-yet-delivered order contributes no completed work.
            order = self._object(key, "order")
            if (
                order["round"] != self.round
                or order["submission"] != submission
                or order["track"] != "model"
            ):
                raise ValueError("execution progress order differs from its selected model")
            cases, evaluators = order["cases"], order["evaluators"]
            producers.update(evaluators)
            if not 3 <= cases <= 2048:
                raise ValueError("execution progress case count is invalid")
            orders += 1
            expected = cases * 2
            delivered_total += expected * len(evaluators)
            profiles.add((cases, len(evaluators)))
            sealed = 0
            for evaluator in evaluators:
                path = f"terminals/{key}/{evaluator}.json"
                try:
                    terminal = self._fact(path, "reference")
                except FileNotFoundError:
                    if "reference:" + path in self.facts:
                        raise
                    indices = self._latest_partial(submission, evaluator)
                else:
                    archive = self._object(terminal, "terminal")
                    indices = self._object(archive, "archive")
                    if (
                        len(indices["indices"] if isinstance(indices, dict) else indices)
                        != expected
                    ):
                        raise ValueError("execution progress terminal has incomplete steps")
                    sealed += 1
                if isinstance(indices, dict):
                    reused += indices["reused"]
                    indices = indices["indices"]
                if any(i >= expected for i in indices):
                    raise ValueError("execution progress exceeds its original order")
                executions += len(indices)
                saved = set(indices)
                comparisons += sum(i % 2 == 0 and i + 1 in saved for i in saved)
            completed += sealed == len(evaluators)
        self.facts = {key: value for key, value in self.facts.items() if key in self.used}
        self.required_producers = producers
        projection = delivered_total if orders == len(self.selected) else None
        if orders != len(self.selected) and len(profiles) == 1:
            cases, evaluators = next(iter(profiles))
            projection = len(self.selected) * cases * evaluators * 2
        return dict(
            completed=completed,
            total=len(self.selected),
            percent=round(100 * completed / len(self.selected), 3) if self.selected else None,
            exported_executions=executions,
            exported_inferences=executions - reused,
            reused_incumbent_observations=reused,
            exported_comparisons=comparisons,
            delivered_orders=orders,
            delivered_order_executions=delivered_total,
            projected_executions=projection,
            projection_basis="remaining_orders_assumed_to_match_delivered_case_and_evaluator_counts"
            if orders != len(self.selected)
            else "all_selected_orders_delivered",
        )

    def sample(self, *, producer_epochs=None):
        """Run only on the background owner thread; failures never stop evaluation."""
        now = time.monotonic()
        report = dict(
            cohort_sha256=self.cohort,
            phase="requests",
            stage="model_evaluation",
            status="running",
            unit="selected_models_with_all_evaluator_terminals",
            scope="confirmed_export_floor_not_live_execution_or_rewards",
            completed=None,
            total=len(self.selected),
            percent=None,
            elapsed_seconds=round(now - self.started, 3),
            eta_seconds=None,
            eta_basis="insufficient_completed_assignment_rate_samples",
            eta_scope="model_evaluation_exports_only_excludes_certification_and_rewards",
            stalled_or_retrying=False,
            repair_required=False,
        )
        self.used, self.read_bytes = set(), 0
        try:
            if not self.loaded:
                try:
                    saved = read_private_model(
                        self.checkpoint, _Facts, maximum_bytes=_MAX_BYTES
                    ).root
                except FileNotFoundError:
                    if self.initialized.exists():
                        raise ValueError(
                            "initialized execution progress checkpoint is missing"
                        ) from None
                    saved = dict(schema=_SCHEMA, round=self.round, facts={})
                if (
                    saved["schema"] != _SCHEMA
                    or saved["round"] != self.round
                    or not isinstance(saved["facts"], dict)
                ):
                    raise ValueError("execution progress checkpoint binding is invalid")
                self.facts = saved["facts"]
                self.saved = {**saved, "facts": dict(saved["facts"])}
                self.last_snapshot = saved.get("last_snapshot", {})
                if (
                    not isinstance(self.last_snapshot, dict)
                    or set(self.last_snapshot) - set(_COUNTS)
                    or any(
                        v is not None and (type(v) is not int or v < 0)
                        for k, v in self.last_snapshot.items()
                        if k != "projection_basis"
                    )
                ):
                    raise ValueError("execution progress retained counts are invalid")
                origin = saved.get("rate_origin")
                if origin is not None:
                    _hex(origin["epoch"])
                    if (
                        type(origin["monotonic_ms"]) is not int
                        or origin["monotonic_ms"] < 0
                        or type(origin["completed"]) is not int
                        or origin["completed"] < 0
                    ):
                        raise ValueError("execution progress rate origin is invalid")
                    if (
                        origin["clock"] == self.clock_identity
                        and origin["monotonic_ms"] <= now * 1000
                    ):
                        self.rate_epoch = origin["epoch"]
                        self.rate_origin = (origin["monotonic_ms"] / 1000, origin["completed"])
                self.loaded = True
            elif self.initialized.exists() and not self.checkpoint.exists():
                raise ValueError("initialized execution progress checkpoint is missing")
            report.update(self._sample())
            self.last_snapshot = {key: report[key] for key in _COUNTS if key in report}
        except _PendingExport:
            # Keep the confirmed floor and its unchanged producer rate origin.
            # Neither a newly arrived reference nor an absent new object erases
            # previous completions. Persist individually accepted metadata too.
            report.update(self.last_snapshot)
            if report["completed"] is not None and report["total"]:
                report["percent"] = round(100 * report["completed"] / report["total"], 3)
            report.update(
                status="pending",
                stalled_or_retrying=True,
                eta_basis="awaiting_new_execution_export_object_delivery",
            )
            try:
                self._persist()
            except (OSError, ValueError, KeyError, TypeError) as error:
                report.update(
                    status="repair_required",
                    repair_required=True,
                    eta_basis="execution_export_metadata_requires_repair",
                    error_type=type(error).__name__,
                )
            return report
        except (OSError, ValueError, KeyError, TypeError) as error:
            report.update(
                status="repair_required",
                repair_required=True,
                stalled_or_retrying=True,
                eta_basis="execution_export_metadata_requires_repair",
                error_type=type(error).__name__,
            )
            return report
        epochs = producer_epochs or {}
        known = bool(self.required_producers) and all(
            e in epochs
            and isinstance(epochs[e], str)
            and re.fullmatch(r"[0-9a-f]{64}", epochs[e]) is not None
            for e in self.required_producers
        )
        epoch = digest(sorted((e, epochs[e]) for e in self.required_producers)) if known else None
        if known and epoch != self.rate_epoch:
            self.rate_origin = None
        if known:
            self.rate_epoch = epoch
        report["rate_epoch_sha256"] = epoch
        report["rate_producers"] = len(self.required_producers)
        if not known:
            report["eta_basis"] = "awaiting_current_execution_producer_epochs"
        if self.rate_origin is None and known:
            self.rate_origin = (now, report["completed"])
        elapsed = 0 if self.rate_origin is None or not known else now - self.rate_origin[0]
        new = (
            0
            if self.rate_origin is None or not known
            else report["completed"] - self.rate_origin[1]
        )
        if new < 0:
            self.rate_origin = (now, report["completed"])
            elapsed = new = 0
            report["eta_basis"] = "execution_export_count_regression_rate_reset"
        report["rate_completed_models"] = new
        report["rate_sample_seconds"] = round(elapsed, 3)
        progress = (report["completed"], report["exported_executions"])
        if progress != self.last_progress[1]:
            self.last_progress = (now, progress)
        if report["completed"] == report["total"]:
            report.update(
                status="completed", eta_seconds=0, eta_basis="all_selected_model_terminals_exported"
            )
        elif known and new >= 3 and elapsed >= 300:
            report.update(
                eta_seconds=round((report["total"] - report["completed"]) * elapsed / new, 3),
                eta_basis="observed_completed_assignment_rate_current_producer_epoch",
                eta_assumptions=[
                    "remaining assignments have comparable cost",
                    "export delivery keeps up",
                    "current resources and error rate continue",
                    "observed evaluator processes remain unchanged",
                ],
            )
        if report["status"] != "completed" and now - self.last_progress[0] >= 900:
            report.update(
                eta_seconds=None,
                eta_basis="no_new_export_progress_for_15_minutes",
                stalled_or_retrying=True,
            )
        try:
            self._persist()
        except (OSError, ValueError, KeyError, TypeError) as error:
            report.update(
                status="repair_required",
                repair_required=True,
                stalled_or_retrying=True,
                eta_seconds=None,
                eta_basis="execution_export_metadata_requires_repair",
                error_type=type(error).__name__,
            )
        return report
