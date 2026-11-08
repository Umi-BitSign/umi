"""Explicit local reviewer track migration; signed cohort records stay immutable."""

import hashlib
import json
import os
import sys
import time
from pathlib import Path


def selections(before, after, digest, identity):
    a, b = dict(before), dict(after)
    if (
        a.get("eligible_tracks") != ["endpoint", "model"]
        or b.get("eligible_tracks") != ["model"]
        or not a.get("endpoint")
        or "endpoint" in b
    ):
        raise ValueError("only explicit endpoint retirement is supported")
    a.pop("endpoint")
    a["eligible_tracks"] = ["model"]
    if a != b:
        raise ValueError("track retirement changes unrelated configuration")
    old = dict(
        series_sha256=digest(before["series"]),
        owner=identity(before["owner_hotkey"]),
        eligible_tracks=before["eligible_tracks"],
        maximum_sample_gap_blocks=before["maximum_sample_gap_blocks"],
    )
    return old, dict(old, eligible_tracks=["model"])


def repair(db, old, new, canonical, *, prepared=False):
    """Caller owns native service and journal transactions plus durable intent."""
    rows = db.execute("SELECT kind,body FROM records WHERE id='selection'").fetchall()
    if len(rows) != 1 or rows[0][0] != "phase_review_host":
        raise ValueError("selection key has missing or unrelated records")
    body = bytes(rows[0][1])
    held = db.execute("SELECT 1 FROM holds WHERE id='selection'").fetchone() is not None
    if body == canonical(new):
        if not prepared or held:
            raise ValueError("changed selection requires retained completed repair intent")
        return dict(reused=True, record_updates=0, holds_removed=0)
    if body != canonical(old) or not prepared:
        raise ValueError("original host selection or durable repair intent differs")
    # Only the unsigned local host-selection row changes. SQL triggers maintain
    # the installed journal's existing accounting; no signed row is rewritten.
    db.execute(
        "UPDATE records SET body=? WHERE kind='phase_review_host' AND id='selection'",
        (canonical(new),),
    )
    assert db.execute("SELECT changes()").fetchone()[0] == 1
    db.execute("DELETE FROM holds WHERE id='selection'")
    removed = db.execute("SELECT changes()").fetchone()[0]
    assert removed == int(held)
    return dict(
        reused=False,
        record_updates=1,
        holds_removed=removed,
        original_sha256=hashlib.sha256(body).hexdigest(),
        selected_sha256=hashlib.sha256(canonical(new)).hexdigest(),
    )


def main():
    request_path = Path(sys.argv[1])
    request_stat = request_path.lstat()
    assert (
        request_stat.st_uid == 0
        and request_stat.st_mode & 0o222 == 0
        and not request_path.is_symlink()
    )
    request = json.loads(request_path.read_bytes())
    assert sys.flags.isolated and sys.dont_write_bytecode
    sys.path.insert(0, request["source"] + "/src")
    from umi.competition_cohort_review_config import PhaseReviewServiceConfig
    from umi.competition_round_journal import RoundJournal
    from umi.open_competition import digest, identity
    from umi.private_files import lock_private_file
    from umi.protocol import canonical_json_bytes

    def checked(ref):
        raw = Path(ref["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == ref["sha256"]
        return raw

    before = json.loads(checked(request["before"]))
    raw = checked(request["after"])
    config = PhaseReviewServiceConfig.model_validate_json(raw)
    assert canonical_json_bytes(config) == raw
    after = json.loads(raw)
    old, new = selections(before, after, digest, identity)
    out = Path(request["output"])
    out.mkdir(mode=0o700, exist_ok=True)

    def put(name, value):
        path = out / name
        raw = canonical_json_bytes(value)
        if path.exists():
            assert path.read_bytes() == raw
            return
        tmp = path.with_suffix(".tmp")
        with tmp.open("wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(0o600)
        tmp.replace(path)

    started = time.monotonic()
    lease = None
    while lease is None:
        try:
            lease = lock_private_file(Path(config.signing.directory) / "service.lock")
        except (OSError, ValueError):
            elapsed = time.monotonic() - started
            if elapsed > 180:
                raise
            if int(elapsed) % 10 == 0:
                print(
                    json.dumps(
                        dict(
                            stage="reviewer_track_repair_waiting_for_failed_startup_exit",
                            elapsed_seconds=elapsed,
                            completed=0,
                            total=1,
                            eta_seconds=None,
                            eta_basis="existing_failed_startup_owns_service_lock",
                            stalled_or_retrying=True,
                        )
                    ),
                    flush=True,
                )
            time.sleep(0.5)
    try:
        journal = RoundJournal(
            Path(config.signing.directory),
            config.signing.model_dump(
                mode="json", by_alias=True, exclude={"maximum_bytes", "signing_timeout_seconds"}
            ),
            maximum_rounds=65536,
            maximum_bytes=config.signing.maximum_bytes,
        )
        intent = dict(
            request=request,
            original_host_selection=old,
            selected_host_selection=new,
            scope="Explicit unsigned local reviewer track retirement; no signed records changed.",
        )
        with journal.transaction() as db:
            current = db.execute(
                "SELECT body FROM records WHERE kind='phase_review_host' AND id='selection'"
            ).fetchone()
            if (
                current is not None
                and bytes(current[0]) == canonical_json_bytes(new)
                and not (out / "intent.json").exists()
            ):
                raise ValueError("completed migration intent is missing; explicit repair required")
            put("intent.json", intent)
            if journal._version(db) == 2:
                obligation = journal._obligation(db, "phase_review_host", "selection")
                assert obligation is None or (
                    obligation["value_sha256"] is None
                    and obligation["maximum_bytes"] >= len(canonical_json_bytes(new))
                )
            count = db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            result = repair(db, old, new, canonical_json_bytes, prepared=True)
            assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == count
            assert len(canonical_json_bytes(new)) < len(canonical_json_bytes(old))
            if journal._version(db) == 2:
                journal._check_capacity(db)
        assert journal.get("phase_review_host", "selection") == new
        put(
            "complete.json",
            dict(
                intent_sha256=hashlib.sha256((out / "intent.json").read_bytes()).hexdigest(),
                selected_host_selection=new,
                signed_records_unchanged=True,
                records=count,
            ),
        )
        print(
            json.dumps(
                dict(
                    stage="reviewer_track_selection_repaired",
                    completed=1,
                    total=1,
                    elapsed_seconds=time.monotonic() - started,
                    eta_seconds=0,
                    eta_basis="local_repair_complete_application_readiness_separate",
                    result=result,
                )
            ),
            flush=True,
        )
    finally:
        os.close(lease)


if __name__ == "__main__":
    main()
