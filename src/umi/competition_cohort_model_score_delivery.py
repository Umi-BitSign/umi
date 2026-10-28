"""Bounded atomic delivery of native public score snapshots, including adoptions.

Immutable proof/package transport is separate. The native publisher retains the
original and each adopted projection before replacing its public snapshot. This
reader copies that selected snapshot without replaying its private evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import signal
import stat
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_model_scores import PublicModelScores
from .competition_host_activation import _read_root_control_path
from .competition_public_results_directory import atomic_write, owned_directory, read_owned_file
from .competition_public_results_publisher import publisher_lease
from .competition_verification_snapshot import _Checksummed
from .open_competition import digest
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAXIMUM_BYTES = 2 * 1024**2
NAME = re.compile(r"[0-9a-f]{64}\.json")
# Filesystem nanoseconds exceed JSON's exact integer domain. Preserve their
# complete decimal representation, as other native retained file stamps do.
StampInteger = Annotated[str, Field(pattern=r"^(0|[1-9][0-9]{0,39})$")]
FileStamp = tuple[StampInteger, StampInteger, StampInteger, StampInteger, StampInteger]


class ModelScoreDeliveryConfig(StrictProtocolModel):
    schema_: Literal["umi-native-public-model-score-delivery/1"] = Field(alias="schema")
    source_directory: Directory
    destination_directory: Directory
    state_directory: Directory


def load_config(path):
    return ModelScoreDeliveryConfig.model_validate_json(
        _read_root_control_path(path, 16384, modes={0o444, 0o600, 0o644})
    )


class DeliveredScore(StrictProtocolModel):
    source: FileStamp
    target: FileStamp


class ScoreDeliveryCheckpoint(_Checksummed):
    schema_: Literal["umi-public-score-delivery-checkpoint/1"] = Field(alias="schema")
    binding_sha256: Hex32
    items: Annotated[
        dict[Annotated[str, Field(pattern=r"^[0-9a-f]{64}\.json$")], DeliveredScore],
        Field(max_length=1024),
    ]


class ScoreDeliveryBinding(_Checksummed):
    schema_: Literal["umi-public-score-delivery-binding/1"] = Field(alias="schema")
    binding_sha256: Hex32


def _directory(path, uid):
    if not path.is_absolute() or path.resolve() != path or path == Path(path.anchor):
        raise ValueError("score delivery requires canonical separate roots")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise ValueError("score delivery directory ownership differs")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def _stamp(path, uid):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or not 0 < info.st_size <= MAXIMUM_BYTES
    ):
        raise ValueError("score snapshot has unsafe ownership, layout or size")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(path, uid, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != expected:
            raise ValueError("score snapshot changed before read; retry")
        raw = stream.read(MAXIMUM_BYTES + 1)
    if len(raw) != expected[2] or _stamp(path, uid) != expected:
        raise ValueError("score snapshot changed during read; retry")
    result = PublicModelScores.model_validate_json(raw)
    if result.cohort_sha256 != path.stem or canonical_json_bytes(result) != raw:
        raise ValueError("score snapshot identity or canonical bytes differ")
    return raw, result


def _binding(scores):
    return (
        scores.cohort_sha256,
        scores.round_sha256,
        scores.policy_sha256,
        tuple(sorted((r.submission_sha256, r.model_sha256, r.hotkey, r.uid) for r in scores.items)),
    )


def _replacement(old, new):
    if _binding(old) != _binding(new):
        raise ValueError("score replacement changes certified cohort roster or policy")
    if old == new:
        return
    original = old.original_allocation_sha256 or old.allocation_sha256
    source = old.original_source_metadata_sha256 or old.source_metadata_sha256
    if (
        new.schema_ != "umi-public-cohort-model-results/3"
        or new.original_allocation_sha256 != original
        or new.original_source_metadata_sha256 != source
        or new.reward_adoption_sha256 == old.reward_adoption_sha256
    ):
        raise ValueError("score replacement is not a new adoption of the same native result")


class ModelScoreDelivery:
    def __init__(self, source, destination, state, *, source_uid, destination_uid, destination_gid):
        self.source, self.destination, self.state = map(Path, (source, destination, state))
        self.source_uid, self.destination_uid, self.destination_gid = (
            source_uid,
            destination_uid,
            destination_gid,
        )
        roots = (self.source, self.destination, self.state)
        if any(
            a.is_relative_to(b) or b.is_relative_to(a)
            for i, a in enumerate(roots)
            for b in roots[i + 1 :]
        ):
            raise ValueError("score delivery roots overlap")
        self.identities = (
            _directory(self.source, source_uid),
            _directory(self.destination, destination_uid),
        )
        owned_directory(self.state, create=True)
        self.binding = digest(
            {
                "source": str(self.source),
                "destination": str(self.destination),
                "source_identity": self.identities[0],
                "destination_identity": self.identities[1],
                "source_uid": source_uid,
                "destination_uid": destination_uid,
                "destination_gid": destination_gid,
            }
        )
        self.leases = ExitStack()
        try:
            self.leases.enter_context(publisher_lease(self.state))
            # One service-owned bounded scratch root on the destination filesystem.
            # Its lease also excludes a second delivery configured with another state root.
            self.scratch = self.destination / ".umi-model-score-delivery"
            self.leases.enter_context(publisher_lease(self.scratch))
            for path in self.scratch.iterdir():
                if path.name == "publisher.lock":
                    continue
                info = path.lstat()
                if (
                    not path.name.startswith("copy-")
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid not in {os.getuid(), destination_uid}
                    or info.st_mode & 0o077
                    or info.st_size > MAXIMUM_BYTES
                ):
                    raise ValueError("score delivery scratch needs explicit repair")
                path.unlink()
            self.receipt = self.state / "score-snapshots.json"
            marker = self.state / "score-snapshots-binding.json"
            try:
                saved = ScoreDeliveryCheckpoint.model_validate_json(
                    read_owned_file(self.receipt, MAXIMUM_BYTES)
                ).checked()
            except FileNotFoundError:
                if os.path.lexists(marker):
                    raise ValueError(
                        "score delivery checkpoint missing; explicit repair required"
                    ) from None
                saved = ScoreDeliveryCheckpoint(
                    schema="umi-public-score-delivery-checkpoint/1",
                    binding_sha256=self.binding,
                    items={},
                ).sealed()
                atomic_write(self.receipt, canonical_json_bytes(saved))
            if saved.binding_sha256 != self.binding:
                raise ValueError("score delivery checkpoint namespace differs")
            expected = ScoreDeliveryBinding(
                schema="umi-public-score-delivery-binding/1", binding_sha256=self.binding
            ).sealed()
            if os.path.lexists(marker):
                retained = ScoreDeliveryBinding.model_validate_json(
                    read_owned_file(marker, 4096)
                ).checked()
                if retained != expected:
                    raise ValueError("score delivery checkpoint binding is damaged")
            else:
                atomic_write(marker, canonical_json_bytes(expected))
            self.completed = saved.items
            self.receipt_stamp = _stamp(self.receipt, os.getuid())
        except BaseException:
            self.leases.close()
            raise

    def close(self):
        self.leases.close()

    def deliver(self, name):
        if not NAME.fullmatch(name):
            raise ValueError("score delivery requires a cohort snapshot filename")
        if _stamp(self.receipt, os.getuid()) != self.receipt_stamp:
            raise ValueError("score delivery checkpoint changed; explicit repair required")
        if (
            _directory(self.source, self.source_uid),
            _directory(self.destination, self.destination_uid),
        ) != self.identities:
            raise ValueError("score delivery source/destination namespace changed")
        source, target = self.source / name, self.destination / name
        source_stamp = _stamp(source, self.source_uid)
        try:
            target_stamp = _stamp(target, self.destination_uid)
        except FileNotFoundError:
            target_stamp = None
        saved = self.completed.get(name)
        if (
            saved is not None
            and target_stamp is not None
            and (saved.source, saved.target)
            == (tuple(map(str, source_stamp)), tuple(map(str, target_stamp)))
        ):
            return False
        raw, scores = _read(source, self.source_uid, source_stamp)
        prior = None
        if target_stamp is not None:
            prior, old = _read(target, self.destination_uid, target_stamp)
            _replacement(old, scores)
        if prior != raw:
            fd, pending = tempfile.mkstemp(prefix="copy-", dir=self.scratch)
            try:
                with os.fdopen(fd, "wb") as output:
                    os.fchmod(output.fileno(), 0o600)
                    if os.geteuid() == 0:
                        os.fchown(output.fileno(), self.destination_uid, self.destination_gid)
                    elif self.destination_uid != os.geteuid():
                        raise ValueError("score delivery cannot select another account")
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
                if _stamp(source, self.source_uid) != source_stamp:
                    raise ValueError("score source changed before publication; retry")
                try:
                    current = _stamp(target, self.destination_uid)
                except FileNotFoundError:
                    current = None
                if current != target_stamp:
                    raise ValueError("score destination changed during delivery; retry")
                os.replace(pending, target)
                parent = os.open(self.destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            finally:
                Path(pending).unlink(missing_ok=True)
        item = DeliveredScore(
            source=tuple(map(str, source_stamp)),
            target=tuple(map(str, _stamp(target, self.destination_uid))),
        )
        completed = {**self.completed, name: item}
        checkpoint = ScoreDeliveryCheckpoint(
            schema="umi-public-score-delivery-checkpoint/1",
            binding_sha256=self.binding,
            items=completed,
        ).sealed()
        atomic_write(self.receipt, canonical_json_bytes(checkpoint), immutable=False)
        self.completed = completed
        self.receipt_stamp = _stamp(self.receipt, os.getuid())
        return prior != raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--watch", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("cross-account public score delivery requires its root service")
    config = load_config(args.config)
    source_user, target_user = (
        pwd.getpwnam("umi-validator-uid54"),
        pwd.getpwnam("umi-cohort-public"),
    )
    delivery = ModelScoreDelivery(
        config.source_directory,
        config.destination_directory,
        config.state_directory,
        source_uid=source_user.pw_uid,
        destination_uid=target_user.pw_uid,
        destination_gid=target_user.pw_gid,
    )
    stopped = False

    def stop(*unused):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopped:
            started, completed, changed, errors = time.monotonic(), 0, 0, []
            names = sorted(p.name for p in delivery.source.iterdir() if NAME.fullmatch(p.name))
            if len(names) > 1024:
                raise ValueError("public score inventory exceeds its bounded capacity")
            for name in names:
                if stopped:
                    break
                try:
                    changed += delivery.deliver(name)
                    completed += 1
                except (OSError, ValueError) as error:
                    errors.append({"cohort": name[:-5], "error_type": type(error).__name__})
            print(
                json.dumps(
                    {
                        "stage": "public_model_score_delivery",
                        "completed": completed,
                        "total": len(names),
                        "percent": 100 * completed / len(names) if names else 100,
                        "elapsed_seconds": time.monotonic() - started,
                        "eta_seconds": None if errors else 0,
                        "eta_basis": "explicit_retry_required"
                        if errors
                        else "completed_current_metadata",
                        "stalled_or_retrying": bool(errors),
                        "changed": changed,
                        "errors": errors,
                    }
                ),
                flush=True,
            )
            if not args.watch:
                if errors:
                    raise ValueError("public score delivery has unresolved items")
                break
            until = time.monotonic() + 5
            while not stopped and time.monotonic() < until:
                time.sleep(0.2)
    finally:
        delivery.close()


if __name__ == "__main__":
    main()
