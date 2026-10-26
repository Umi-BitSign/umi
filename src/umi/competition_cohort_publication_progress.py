"""Durable advisory publication facts; never settlement or reward authority."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_verification_reuse import metadata_completion, remember_metadata_completion
from .competition_verification_snapshot import _Checksummed
from .file_identity import file_fingerprint
from .private_files import (
    ensure_private_directory,
    private_path,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32


class PublicationObservation(_Checksummed):
    schema_: Literal["umi-native-publication-observation/1"] = Field(
        default="umi-native-publication-observation/1", alias="schema"
    )
    series_sha256: Hex32
    cohort_sha256: Hex32
    evaluator: Hex32
    role: Literal["coordinator"]
    certification_prefix_sha256: Hex32
    output_path: str
    output_identity: Annotated[tuple[str, ...], Field(min_length=9, max_length=9)]
    observed_unix_ms: Annotated[int, Field(ge=0)]
    origin: Literal["selected_native_certification_and_owned_output"]


class NativePublicationProgress:
    """Restore original publication metadata without opening the package body.

    The native owner supplies its authenticated certification closure. A receipt
    is diagnostic only: it cannot skip native replay, sign or activate rewards.
    """

    def __init__(self, root, output, *, series, cohort, evaluator, maximum_package_bytes):
        self.root, self.output = Path(root), Path(output)
        if type(maximum_package_bytes) is not int or maximum_package_bytes <= 0:
            raise ValueError("native publication requires its configured package bound")
        self.maximum_package_bytes = maximum_package_bytes
        self.path = self.root / "publication.json"
        self.context = dict(
            series_sha256=series,
            cohort_sha256=cohort,
            evaluator=evaluator,
            role="coordinator",
            output_path=str(self.output),
        )

    def _identity(self):
        private_path(str(self.output))
        info = self.output.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or not 0 < info.st_size <= self.maximum_package_bytes
        ):
            raise ValueError("native publication output identity is unsafe")
        return tuple(str(value) for value in file_fingerprint(info))

    def observe(self, certification_prefix):
        if certification_prefix is None:
            return None
        expected = dict(self.context, certification_prefix_sha256=certification_prefix)
        try:
            saved = read_private_model(
                self.path, PublicationObservation, maximum_bytes=65536
            ).checked()
        except FileNotFoundError:
            if metadata_completion(self.path).exists():
                return self._repair("publication_receipt_missing")
            try:
                identity = self._identity()
            except FileNotFoundError:
                return None  # First native publication may still be running.
            except (OSError, ValueError):
                return self._repair("publication_output_identity_invalid")
            ensure_private_directory(self.root)
            saved = PublicationObservation(
                **expected,
                output_identity=identity,
                observed_unix_ms=time.time_ns() // 1_000_000,
                origin="selected_native_certification_and_owned_output",
            ).sealed()
            publish_private_model(self.path, saved, maximum_bytes=65536)
        except (OSError, ValueError):
            return self._repair("publication_receipt_damaged")
        if any(getattr(saved, key) != value for key, value in expected.items()):
            return self._repair("publication_native_binding_changed")
        try:
            if self._identity() != saved.output_identity:
                return self._repair("publication_output_changed", saved)
        except FileNotFoundError:
            return self._repair("publication_output_missing", saved)
        except (OSError, ValueError):
            return self._repair("publication_output_identity_invalid", saved)
        remember_metadata_completion(self.path)
        return dict(
            state="completed",
            observed_unix_ms=saved.observed_unix_ms,
            certification_prefix_sha256=saved.certification_prefix_sha256,
            basis=saved.origin,
            output_current=True,
        )

    @staticmethod
    def _repair(reason, saved=None):
        result = dict(state="repair_required", reason_code=reason, output_current=False)
        if saved is not None:
            result.update(
                observed_unix_ms=saved.observed_unix_ms,
                certification_prefix_sha256=saved.certification_prefix_sha256,
                basis=saved.origin,
            )
        return result
