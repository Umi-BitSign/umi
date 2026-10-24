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
        self.forecast = None
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
                value = indices
        self.facts[key] = dict(stamp=stamp, value=value)
        return value

    def _object(self, key, kind):
        return self._fact("objects/" + _hex(key) + ".json", kind)

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
        completed = executions = comparisons = orders = delivered_total = 0
        profiles = set()
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
                    if len(indices) != expected:
                        raise ValueError("execution progress terminal has incomplete steps")
                    sealed += 1
                if any(i >= expected for i in indices):
                    raise ValueError("execution progress exceeds its original order")
                executions += len(indices)
                saved = set(indices)
                comparisons += sum(i % 2 == 0 and i + 1 in saved for i in saved)
            completed += sealed == len(evaluators)
        self.facts = {key: value for key, value in self.facts.items() if key in self.used}
        projection = delivered_total if orders == len(self.selected) else None
        if orders != len(self.selected) and len(profiles) == 1:
            cases, evaluators = next(iter(profiles))
            projection = len(self.selected) * cases * evaluators * 2
        return dict(
            completed=completed,
            total=len(self.selected),
            percent=round(100 * completed / len(self.selected), 3) if self.selected else None,
            exported_executions=executions,
            exported_comparisons=comparisons,
            delivered_orders=orders,
            delivered_order_executions=delivered_total,
            projected_executions=projection,
            projection_basis="remaining_orders_assumed_to_match_delivered_case_and_evaluator_counts"
            if orders != len(self.selected)
            else "all_selected_orders_delivered",
        )

    def sample(self):
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
                self.facts, self.loaded = saved["facts"], True
            elif self.initialized.exists() and not self.checkpoint.exists():
                raise ValueError("initialized execution progress checkpoint is missing")
            previous = dict(self.facts)
            report.update(self._sample())
            if self.facts != previous or not self.checkpoint.exists():
                ensure_private_directory(self.checkpoint.parent)
                private_path(str(self.checkpoint))
                raw = canonical_json_bytes(
                    _Facts(dict(schema=_SCHEMA, round=self.round, facts=self.facts))
                )
                if len(raw) > _MAX_BYTES:
                    raise ValueError("execution progress checkpoint exceeds its byte budget")
                atomic_write(self.checkpoint, raw, immutable=False)
            if not self.initialized.exists():
                publish_private_model(
                    self.initialized, _Facts(dict(schema=_SCHEMA, round=self.round))
                )
        except (OSError, ValueError, KeyError, TypeError) as error:
            self.rate_origin = None
            report.update(
                status="repair_required",
                repair_required=True,
                stalled_or_retrying=True,
                eta_basis="execution_export_metadata_requires_repair",
                error_type=type(error).__name__,
            )
            return report
        if self.rate_origin is None:
            self.rate_origin = (now, report["completed"])
        elapsed = now - self.rate_origin[0]
        new = report["completed"] - self.rate_origin[1]
        report["rate_completed_models"] = new
        report["rate_sample_seconds"] = round(elapsed, 3)
        progress = (report["completed"], report["exported_executions"])
        if progress != self.last_progress[1]:
            self.last_progress = (now, progress)
        if report["completed"] == report["total"]:
            report.update(
                status="completed", eta_seconds=0, eta_basis="all_selected_model_terminals_exported"
            )
        elif new >= 3 and elapsed >= 300:
            report.update(
                eta_seconds=round((report["total"] - report["completed"]) * elapsed / new, 3),
                eta_basis="observed_completed_assignment_rate_since_sampler_start",
                eta_assumptions=[
                    "remaining assignments have comparable cost",
                    "export delivery keeps up",
                    "current resources and error rate continue",
                ],
            )
        if report["status"] != "completed" and now - self.last_progress[0] >= 900:
            report.update(
                eta_seconds=None,
                eta_basis="no_new_export_progress_for_15_minutes",
                stalled_or_retrying=True,
            )
        return report
