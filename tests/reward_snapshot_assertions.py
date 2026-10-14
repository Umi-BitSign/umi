"""Bound warm replay reads to the native context, excluding bulk evidence."""

import pytest

from umi import competition_verification_snapshot as snapshot_module


class NativeContextReads:
    """Keep current native checks while forbidding another aggregate/evidence pass.

    Native replay still reconstructs intake, signed phase decisions, signed quality
    certificates, reveal pulses and the benchmark's terminal/assignment/archive references. These
    reference objects select the context of reusable expensive verdicts. They
    are distinct from case-review payloads, model execution steps and paid
    response contents, which must not be reopened on a warm unchanged replay.
    """

    def __init__(self, monkeypatch, package, snapshot):
        inventory = {item.sha256: item.value for item in package.objects}
        allowed = {item.record_sha256 for item in package.intake}
        allowed.update(item.pulse_sha256 for item in package.pulses)
        allowed.update(item.certificate_sha256 for item in package.benchmark.participants)
        for item in package.inputs.history.transitions:
            if item.transition.requires_progress_evidence:
                key = item.transition.evidence_sha256
                allowed.add(key)
                body = inventory[key]["progress"]["progress"]
                if body["phase"] == "requests":
                    allowed.add(body["evidence_sha256"])
        closure = package.inputs.closure
        if hasattr(closure, "benchmark_closure_sha256"):
            key = closure.benchmark_closure_sha256
            allowed.add(key)
            benchmark = inventory[key]
        else:
            benchmark = closure.model_dump(mode="json", by_alias=True)
        for member in benchmark["participants"]:
            for evaluator in member["evaluators"]:
                key = evaluator["terminal_sha256"]
                allowed.add(key)
                terminal = inventory[key]["terminal"]
                allowed.update(
                    terminal[name]
                    for name in (
                        "assignment_sha256",
                        "execution_archive_sha256",
                        "endpoint_archive_sha256",
                    )
                    if terminal[name] is not None
                )
        self.allowed = allowed
        self.snapshot = snapshot
        self.reads = []
        self.checks = []
        self.cursor = 0
        native_read = snapshot_module._read_bounded_private_bytes

        def bounded_read(path, **kwargs):
            assert str(path) != snapshot.record.original_path, "warm aggregate payload read"
            if path.suffix == ".bin":
                key = path.stem
                assert key in allowed, "warm expensive evidence read: " + key
                assert path == snapshot.store.object_path(key)
                assert kwargs["maximum_bytes"] == snapshot.records[key].size
                self.reads.append((key, snapshot.records[key].size))
            return native_read(path, **kwargs)

        def no_aggregate(*args, **kwargs):
            pytest.fail("warm native consumer reimported an unchanged aggregate")

        monkeypatch.setattr(snapshot_module, "_read_bounded_private_bytes", bounded_read)
        monkeypatch.setattr(snapshot_module, "read_aggregate_model", no_aggregate)

    def check(self):
        """Count each native pass separately; no cumulative stage-percent fiction."""
        current = self.reads[self.cursor :]
        self.cursor = len(self.reads)
        unique = {key: size for key, size in current}
        total_bytes = int(self.snapshot.record.original_stamp[6])
        # Regression bounds for the retained native fixture: context is a small
        # subset even counting repeated current-authority checks in one pass.
        assert sum(unique.values()) < total_bytes // 4
        assert sum(size for _, size in current) < total_bytes
        assert len(unique) < len(self.snapshot.records) // 2
        result = dict(
            reads=len(current),
            objects=len(unique),
            bytes=sum(size for _, size in current),
            unique_bytes=sum(unique.values()),
            package_bytes=total_bytes,
            keys=sorted(unique),
        )
        self.checks.append(result)
        return result


def forbid_expensive_native_replay(monkeypatch):
    """Economics revisions must reuse unchanged execution/decryption verdicts."""
    from umi import competition_cohort_endpoint_archive as archive_module
    from umi import competition_cohort_endpoint_quality as endpoint_module
    from umi import competition_cohort_request_terminal as terminal_module
    from umi import competition_cohort_service_quality as service_module

    for module, name in (
        (archive_module, "verify_case_decision"),
        (endpoint_module, "decrypt_endpoint_content"),
        (service_module, "decrypt_endpoint_content"),
        (terminal_module, "replay_execution_steps"),
    ):

        def repeated(*args, _name=name, **kwargs):
            pytest.fail("unchanged expensive native check repeated: " + _name)

        monkeypatch.setattr(module, name, repeated)
