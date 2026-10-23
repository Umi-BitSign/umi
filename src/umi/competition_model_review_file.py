"""Durably remember shape verification of an unchanged private review document.

This is file-read reuse, not a rights verdict or artifact-acceptance certificate.
The native acceptance/reviewer still consumes and authenticates the documents.
"""

import os
import stat
from pathlib import Path

from .competition_cohort_model_acceptance import ModelArtifactReviewInputs
from .competition_cohort_model_acceptance_store import MAX_PUBLICATION_BYTES
from .open_competition import digest
from .private_files import ensure_private_directory, private_path, read_private_model

PROFILE = "umi-model-review-file-shape/1"


def _metadata(path):
    private_path(str(path))
    ensure_private_directory(path.parent)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
        or not 1 <= info.st_size <= MAX_PUBLICATION_BYTES
    ):
        raise ValueError("model review file must remain private, bounded and singly linked")
    return [
        str(value)
        for value in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    ]


def reviewed_file_ready(journal, path: Path, model_sha256: str) -> bool:
    """Reuse exact trusted file identity across polls/restarts without reading bytes.

    Missing/changed completed evidence is reported for repair. A replacement with
    identical verified documents can acquire a new metadata receipt atomically;
    it cannot silently substitute different documents for the same binding.
    """
    binding = {"schema": PROFILE, "path": str(path), "model_sha256": model_sha256}
    key = digest(binding)
    prior = journal.get("review-file-binding", key)
    if prior is not None and (
        not isinstance(prior, dict)
        or set(prior) != {"binding", "documents_sha256", "initial_metadata"}
        or prior["binding"] != binding
    ):
        raise ValueError("completed model review file binding requires repair")
    try:
        before = _metadata(path)
    except FileNotFoundError:
        if prior is not None:
            raise OSError("completed model review file is missing; restore its original") from None
        return False
    receipt_key = digest({"binding": key, "metadata": before})
    saved = journal.get("review-file-metadata", receipt_key)
    if saved is not None:
        if prior is None or saved != {"binding": key, "metadata": before}:
            raise ValueError("completed model review file receipt requires repair")
        return True
    if prior is not None and before == prior["initial_metadata"]:
        raise ValueError("completed model review file receipt is missing; repair required")
    value = read_private_model(path, ModelArtifactReviewInputs, maximum_bytes=MAX_PUBLICATION_BYTES)
    if value.model_sha256 != model_sha256:
        raise ValueError("direct model review changed")
    after = _metadata(path)
    if after != before:
        raise OSError("model review file changed during verification; retry")
    documents_sha256 = digest(value)
    if prior is not None and prior["documents_sha256"] != documents_sha256:
        raise ValueError("completed model review documents changed; restore their original")
    verified = prior or {
        "binding": binding,
        "documents_sha256": documents_sha256,
        "initial_metadata": before,
    }
    journal.put_many(
        (
            ("review-file-binding", key, verified),
            ("review-file-metadata", receipt_key, {"binding": key, "metadata": before}),
        )
    )
    return True
