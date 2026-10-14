"""Read completed native R2 preservation receipts without constructing a journal."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from .competition_cohort_direct_model_owner import DirectModelPromotion
from .competition_cohort_direct_model_upload import preserved_model_object_key
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class PublicPromotionJournal(StrictProtocolModel):
    path: str
    owner_uid: int
    binding_sha256: Hex32

    def completed(self, certificates):
        path = Path(self.path)
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError("public promotion journal must be a canonical absolute path")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            held = os.fstat(fd)
            if (
                not stat.S_ISREG(held.st_mode)
                or held.st_nlink != 1
                or held.st_uid != self.owner_uid
                or held.st_mode & 0o077
            ):
                raise ValueError("public promotion journal owner or layout differs")
            result = set()
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                binding = db.execute(
                    "SELECT substr(body,1,1048577) FROM binding LIMIT 2"
                ).fetchall()
                if (
                    len(binding) != 1
                    or len(binding[0][0]) > 1024**2
                    or hashlib.sha256(binding[0][0]).hexdigest() != self.binding_sha256
                ):
                    raise ValueError("public promotion journal binding differs")
                for cert in certificates:
                    a = cert.acceptance
                    if a.direct_artifact is None:
                        continue
                    key = digest(a)
                    row = db.execute(
                        "SELECT substr(body,1,65537) FROM records "
                        "WHERE kind='direct-promotion' AND id=?",
                        (key,),
                    ).fetchone()
                    if row is None:
                        continue
                    if len(row[0]) > 65536:
                        raise ValueError("native promotion receipt exceeds its metadata bound")
                    receipt = DirectModelPromotion.model_validate_json(row[0])
                    reservation = a.direct_artifact
                    payload = reservation.reservation.payload
                    preserved = preserved_model_object_key(
                        a.cohort_sha256, a.model_sha256, payload.payload_sha256
                    )
                    if (
                        canonical_json_bytes(receipt) != row[0]
                        or receipt.acceptance_sha256 != key
                        or receipt.reservation_sha256 != digest(reservation.reservation)
                        or receipt.model_sha256 != a.model_sha256
                        or receipt.payload_sha256 != payload.payload_sha256
                        or receipt.total_bytes != payload.total_bytes
                        or receipt.source_object_key_sha256
                        != reservation.reservation.object_key_sha256
                        or receipt.preserved_object_key_sha256
                        != hashlib.sha256(preserved.encode()).hexdigest()
                    ):
                        raise ValueError(
                            "native promotion receipt differs from accepted public model"
                        )
                    result.add(digest(cert))
                db.rollback()
            current = path.lstat()
            if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("public promotion journal changed during metadata read")
            return result
        finally:
            os.close(fd)
