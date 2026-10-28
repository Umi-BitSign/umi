"""Private native interval successes, never imported interval hints or elapsed credit.

The owner records exact endpoint verdict identities after credit succeeds. Native
source generations fence reuse; ordinary appends and exact source externalization
do not invalidate completed work. Current consumers still refresh authority,
history and shared model/package/runtime dependencies before restoring a group.
"""

import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field

from .competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from .competition_reward_coverage_intervals import CoveragePoint, RewardCoverageInterval
from .open_competition import digest
from .protocol import canonical_json_bytes

OWNER = "coverage_credit_owner"
FACT = "coverage_credit_verified"
GROUP = "coverage_credit_dependency_group"
TABLE = "coverage_credit_generation"
INDEX = "coverage_credit_index"
LEDGER = "coverage_credit_completion"
SCHEMA = {
    TABLE: (
        "CREATE TABLE coverage_credit_generation(owner TEXT NOT NULL,epoch TEXT NOT NULL,"
        "revision INTEGER NOT NULL)"
    ),
    INDEX: "CREATE TABLE coverage_credit_index(id TEXT PRIMARY KEY,result TEXT NOT NULL)",
    LEDGER: "CREATE TABLE coverage_credit_completion(id TEXT PRIMARY KEY,owner TEXT NOT NULL)",
}


class CoverageCreditRepairRequired(CoverageCheckpointRepairRequired):
    pass


class CreditReuseUnavailable(Exception):
    """An older owner lacks a qualified aggregate mutation witness."""


def triggers():
    values = {}
    change = "UPDATE coverage_credit_generation SET revision=revision+1;"
    for action in ("UPDATE", "DELETE"):
        suffix = action.lower()
        for table in ("coverage_source_identity", "coverage_checkpoint_index"):
            values[f"coverage_credit_{table}_{suffix}"] = (
                f"CREATE TRIGGER coverage_credit_{table}_{suffix} AFTER {action} ON {table} "
                + (
                    "WHEN OLD.result!=NEW.result "
                    if table.endswith("index") and action == "UPDATE"
                    else ""
                )
                + "BEGIN "
                + change
                + " END"
            )
        values["coverage_credit_records_" + suffix] = (
            f"CREATE TRIGGER coverage_credit_records_{suffix} AFTER {action} ON records "
            "WHEN OLD.kind IN ('coverage_verified','coverage_verified_done','coverage_interval',"
            "'coverage_credit_verified','coverage_credit_dependency_group') BEGIN "
            + change
            + " END"
        )
        values["coverage_credit_index_" + suffix] = (
            f"CREATE TRIGGER coverage_credit_index_{suffix} AFTER {action} ON {INDEX} BEGIN "
            + change
            + " END"
        )
        for table in (LEDGER,):
            values[f"coverage_credit_permanent_{table}_{suffix}"] = (
                f"CREATE TRIGGER coverage_credit_permanent_{table}_{suffix} "
                f"BEFORE {action} ON {table} "
                "BEGIN SELECT RAISE(ABORT,'native credit completion is permanent'); END"
            )
        values["coverage_credit_owner_" + suffix] = (
            f"CREATE TRIGGER coverage_credit_owner_{suffix} BEFORE {action} ON records "
            "WHEN OLD.kind='coverage_credit_owner' BEGIN SELECT "
            "RAISE(ABORT,'native credit owner is permanent'); END"
        )
    for action in ("INSERT", "UPDATE", "DELETE"):
        values["coverage_credit_holds_" + action.lower()] = (
            f"CREATE TRIGGER coverage_credit_holds_{action.lower()} AFTER {action} ON holds BEGIN "
            + change
            + " END"
        )
    return values


def remote_identity(remote):
    if remote is None:
        return None
    from .competition_remote_proof_generation import generation_identity

    indexes = []
    seen = set()
    for owner in (remote.journal, remote.receipt_source):
        if owner is None or owner.path in seen:
            continue
        seen.add(owner.path)
        info = owner.path.stat()
        try:
            with owner.read_transaction() as db:
                generation = generation_identity(db)
                if generation is None:
                    raise CreditReuseUnavailable(
                        "receipt owner upgrade required before durable credit reuse"
                    )
                if db.execute("SELECT 1 FROM holds LIMIT 1").fetchone():
                    raise CoverageCreditRepairRequired(
                        "native credit receipt owner has a conflict hold"
                    )
                damaged = db.execute(
                    "SELECT number FROM round_record_capacity_kinds "
                    "WHERE kind='remote_proof_damage'"
                ).fetchone()
                if damaged is not None and damaged[0]:
                    raise CoverageCreditRepairRequired(
                        "native credit receipt owner has observed damage"
                    )
        except CoverageCreditRepairRequired:
            raise
        except ValueError as error:
            raise CoverageCreditRepairRequired(
                "native credit receipt generation metadata requires original repair"
            ) from error
        indexes.append(
            dict(identity=[info.st_dev, info.st_ino, info.st_uid], generation=generation)
        )
    return dict(namespace=remote.namespace_sha256, indexes=indexes)


def history_identity(history):
    frontier = history.folded_frontier
    loaded = frontier.load(history._next - 1)
    state = None if loaded is None else loaded[2]
    if state is None or state[3] is None:
        raise CreditReuseUnavailable(
            "native history frontier must be established before durable credit reuse"
        )
    return dict(
        owner=state[0],
        revision=state[1],
        generation=state[4],
        semantics=frontier.blocks.semantics,
        remote=remote_identity(history.remote_store),
    )


def dependency_group(value):
    point = value["point"]
    return {
        k: value[k]
        for k in (
            "package_sha256",
            "policy_sha256",
            "requirement_sha256",
            "cohort_sha256",
            "model_dependencies",
            "activation",
        )
        if k in value
    } | dict(
        runtime_profile_sha256=point["runtime_profile_sha256"],
        effective_runtime_profile_sha256=point.get("effective_runtime_profile_sha256"),
        runtime_adoption_sha256=point.get("runtime_adoption_sha256"),
        activation_sha256=point["activation_sha256"],
        chain_config_sha256=point["chain_config_sha256"],
    )


class NativeCoverageCredits:
    def __init__(self, owner):
        self.owner, self.journal = owner, owner.journal
        self.marker = dict(
            schema="umi-native-coverage-credit-owner/1",
            owner=owner.checkpoints.owner,
            semantics=owner.checkpoints.semantics,
        )
        self.fences = triggers()
        self.groups = {}
        before = self.journal.get(OWNER, "owner")

        def initialize(db):
            installed = db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone()
            if installed is None:
                if (
                    before is not None
                    or db.execute(
                        "SELECT 1 FROM records WHERE kind IN (?,?) LIMIT 1", (FACT, GROUP)
                    ).fetchone()
                ):
                    raise CoverageCreditRepairRequired("native credit schema is missing")
                for sql in SCHEMA.values():
                    db.execute(sql)
                db.execute(
                    f"INSERT INTO {TABLE} VALUES (?,?,0)",
                    (self.marker["owner"], secrets.token_hex(16)),
                )
                for sql in self.fences.values():
                    db.execute(sql)
            elif before != self.marker:
                raise CoverageCreditRepairRequired("native credit owner is missing or changed")

        self.journal.put_many(((OWNER, "owner", self.marker),), index=initialize)

    def state(self, db):
        self.owner.checkpoints.check_schema(db)
        if self.journal.get(OWNER, "owner", db=db) != self.marker:
            raise CoverageCreditRepairRequired("native credit owner changed")
        actual = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='table' AND name IN (?,?,?)",
                tuple(SCHEMA),
            )
        )
        fences = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND name LIKE 'coverage_credit_%'"
            )
        )
        if actual != SCHEMA or fences != self.fences:
            raise CoverageCreditRepairRequired("native credit schema or mutation fences changed")
        rows = db.execute(f"SELECT owner,epoch,revision FROM {TABLE} LIMIT 2").fetchall()
        if len(rows) != 1 or rows[0][0] != self.marker["owner"]:
            raise CoverageCreditRepairRequired("native credit generation changed")
        return list(rows[0])

    def snapshot(self, history):
        with self.journal.read_transaction() as db:
            state = self.state(db)
        return dict(
            owner=self.marker,
            state=state,
            remote=remote_identity(self.owner.remote_store),
            history=history_identity(history),
        )

    @contextmanager
    def preserve_source_release(self, db):
        state = self.state(db)
        yield 0
        changed = db.execute(
            f"UPDATE {TABLE} SET revision=? WHERE owner=? AND epoch=? AND revision=?",
            (state[2], state[0], state[1], state[2] + 1),
        ).rowcount
        if changed != 1:
            raise CoverageCreditRepairRequired("native credit changed during exact source release")

    def load(self, key, history):
        with self.journal.read_transaction() as db:
            self.state(db)
            completed = db.execute(f"SELECT owner FROM {LEDGER} WHERE id=?", (key,)).fetchone()
            selected = db.execute(f"SELECT result FROM {INDEX} WHERE id=?", (key,)).fetchone()
            if completed is None and selected is None:
                return None
            if completed != (self.marker["owner"],) or selected is None:
                raise CoverageCreditRepairRequired("completed native credit selection missing")
        try:
            snapshot = self.snapshot(history)
        except CreditReuseUnavailable as error:
            raise CoverageCreditRepairRequired(
                "completed native credit dependency generation is missing"
            ) from error
        with self.journal.read_transaction() as db:
            if (
                self.state(db) != snapshot["state"]
                or db.execute(f"SELECT result FROM {INDEX} WHERE id=?", (key,)).fetchone()
                != selected
            ):
                raise CoverageCreditRepairRequired("native credit changed while loading")
            fact = self.journal.get(FACT, selected[0], db=db)
            if not isinstance(fact, dict) or digest(fact) != selected[0] or fact.get("key") != key:
                raise CoverageCreditRepairRequired(
                    "completed native credit fact missing or damaged"
                )
            if fact["dependencies"] != snapshot:
                raise CoverageCreditRepairRequired("completed native credit dependencies changed")
            for endpoint, verdict in fact["endpoints"].items():
                if db.execute(
                    "SELECT result FROM coverage_checkpoint_index WHERE id=?", (endpoint,)
                ).fetchone() != (verdict,):
                    raise CoverageCreditRepairRequired("native credit endpoint verdict changed")
            groups = []
            for group, expected in fact["groups"]:
                value = self.journal.get(GROUP, group, db=db)
                if (
                    not isinstance(value, dict)
                    or digest(value) != expected
                    or digest(value["dependencies"]) != group
                ):
                    raise CoverageCreditRepairRequired(
                        "native credit dependency group missing or damaged"
                    )
                groups.append(value)
        return fact, groups, snapshot

    def recheck(self, snapshot, history):
        if self.snapshot(history) != snapshot:
            raise CoverageCreditRepairRequired(
                "native credit dependencies changed during native refresh"
            )

    def remember(self, interval, values, history, *, repair_reason=None):
        if any(value is None for value in values):
            return  # A synthetic/test-only endpoint is never a native reuse authority.
        if any(v.get("model_dependencies", {}).get("mode") == "native_required" for v in values):
            raise CreditReuseUnavailable("original directory model checks remain required")
        with self.journal.read_transaction() as db:
            completed = db.execute(
                f"SELECT owner FROM {LEDGER} WHERE id=?", (interval.key(),)
            ).fetchone()
        try:
            snapshot = self.snapshot(history)
        except CreditReuseUnavailable as error:
            if completed is not None:
                raise CoverageCreditRepairRequired(
                    "completed native credit dependency generation is missing"
                ) from error
            raise
        if completed is not None and repair_reason is None:
            # Repeated capture must not silently recreate lost completion
            # metadata or rebind an already completed interval after damage.
            self.load(interval.key(), history)
        if repair_reason is not None:
            self.groups.clear()
        groups, endpoints, references, points = [], {}, [], {}
        for value in values:
            point = CoveragePoint.model_validate(value["point"])
            dependencies = dependency_group(value)
            group_key = digest(dependencies)
            group = self.groups.get(group_key)
            if group is None:
                group = self.journal.get(GROUP, group_key)
                if group is None:
                    group = dict(
                        dependencies=dependencies, endpoint=point.key(), verdict=digest(value)
                    )
                    groups.append((GROUP, group_key, group))
                elif group["dependencies"] != dependencies:
                    raise CoverageCreditRepairRequired("native credit dependency group changed")
                self.groups[group_key] = group
            references.append([group_key, digest(group)])
            endpoints[point.key()] = digest(value)
            points[point.key()] = value["point"]
        fact = dict(
            schema="umi-native-coverage-credit/1",
            key=interval.key(),
            interval=interval.model_dump(mode="json", by_alias=True),
            through=values[-1]["point"]["block"],
            endpoints=endpoints,
            points=points,
            groups=references,
            dependencies=snapshot,
        )
        key = digest(fact)
        repair_records = []
        if repair_reason is not None:
            if (
                type(repair_reason) is not str
                or not repair_reason.strip()
                or len(repair_reason) > 1024
            ):
                raise ValueError("native credit repair requires an explicit bounded reason")
            with self.journal.read_transaction() as db:
                prior = db.execute(
                    f"SELECT result FROM {INDEX} WHERE id=?", (interval.key(),)
                ).fetchone()
                completion = db.execute(
                    f"SELECT owner FROM {LEDGER} WHERE id=?", (interval.key(),)
                ).fetchone()
            if completion != (self.marker["owner"],):
                raise CoverageCreditRepairRequired(
                    "credit repair requires its original completion owner"
                )
            audit = dict(
                owner=self.marker,
                interval=interval.key(),
                prior=None if prior is None else prior[0],
                restored=key,
                reason=repair_reason,
            )
            repair_records.append(("coverage_credit_repair", digest(audit), audit))

        def commit(db):
            if self.state(db) != snapshot["state"]:
                raise CoverageCreditRepairRequired("native credit changed before commit")
            for endpoint, verdict in endpoints.items():
                if db.execute(
                    "SELECT result FROM coverage_checkpoint_index WHERE id=?", (endpoint,)
                ).fetchone() != (verdict,):
                    raise CoverageCreditRepairRequired(
                        "native credit endpoint changed before commit"
                    )
            prior = db.execute(
                f"SELECT result FROM {INDEX} WHERE id=?", (interval.key(),)
            ).fetchone()
            if prior is not None and prior != (key,) and repair_reason is None:
                raise CoverageCreditRepairRequired(
                    "completed native credit requires explicit dependency repair"
                )
            db.execute(
                f"INSERT OR IGNORE INTO {LEDGER} VALUES (?,?)",
                (interval.key(), self.marker["owner"]),
            )
            if repair_reason is not None and prior is not None and prior != (key,):
                db.execute(f"UPDATE {INDEX} SET result=? WHERE id=?", (key, interval.key()))
                changed = db.execute(
                    f"UPDATE {TABLE} SET revision=? WHERE owner=? AND epoch=? AND revision=?",
                    (
                        snapshot["state"][2],
                        snapshot["state"][0],
                        snapshot["state"][1],
                        snapshot["state"][2] + 1,
                    ),
                ).rowcount
                if changed != 1:
                    raise CoverageCreditRepairRequired(
                        "credit changed during qualified metadata repair"
                    )
            else:
                db.execute(f"INSERT OR IGNORE INTO {INDEX} VALUES (?,?)", (interval.key(), key))

        self.journal.put_many([*groups, (FACT, key, fact), *repair_records], index=commit)

    def apply(self, fact):
        interval = RewardCoverageInterval.model_validate(fact["interval"])
        if interval.key() != fact["key"]:
            raise CoverageCreditRepairRequired("native credit interval changed")
        self.owner._verified[interval.key()] = interval
        self.owner._verified_through[interval.key()] = fact["through"]
        return _issue_native_credit(self.owner, interval, fact["through"])


_CREDIT_ISSUER = object()


@dataclass(frozen=True)
class OwnedNativeCoverageCredit:
    interval: RewardCoverageInterval
    through_block: int
    owner: object = field(repr=False, compare=False)
    issuer: object = field(repr=False, compare=False)
    binding: str = field(repr=False, compare=False)


def _issue_native_credit(owner, interval, through):
    binding = digest([digest(interval), through, owner.checkpoints.owner])
    return OwnedNativeCoverageCredit(interval, through, owner, _CREDIT_ISSUER, binding)


def validate_native_credit(value, owner):
    if (
        type(value) is not OwnedNativeCoverageCredit
        or value.issuer is not _CREDIT_ISSUER
        or value.owner is not owner
        or value.binding
        != digest([digest(value.interval), value.through_block, owner.checkpoints.owner])
    ):
        raise CoverageCreditRepairRequired("credit lacks the original native owner")
    return value.interval, value.through_block


def dependency_metadata_seal(preparation, dependencies):
    """Metadata-only mutation witness around the actual native group refresh."""
    import os
    from pathlib import Path

    from .competition_reward_coverage_models import (
        CoverageModelDependencies,
        model_metadata_seal,
    )
    from .file_identity import file_fingerprint
    from .private_files import private_path

    transport = preparation.transport_qualifications
    paths = [Path(transport.root), Path(transport.marker), Path(transport.journal.path)]
    raw = dependencies.get("model_dependencies")
    model_seal = []
    if raw is not None:
        models = CoverageModelDependencies.model_validate_json(canonical_json_bytes(raw))
        model_seal = model_metadata_seal(models)
    result = []
    for path in paths:
        private_path(str(path))
        try:
            info = path.lstat()
        except FileNotFoundError:
            result.append([str(path), None])
            continue
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise CoverageCreditRepairRequired("native credit dependency metadata owner changed")
        result.append([str(path), list(map(str, file_fingerprint(info)))])
        if path.suffix == ".sqlite3":
            for suffix in ("-wal", "-journal"):
                side = Path(str(path) + suffix)
                result.append(
                    [
                        str(side),
                        list(map(str, file_fingerprint(side.lstat()))) if side.exists() else None,
                    ]
                )
    return result + model_seal
