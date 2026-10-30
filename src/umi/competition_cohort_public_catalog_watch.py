"""Publish certified cohort catalogs once and restore public metadata on restart.

Certified score outputs schedule an existing native metadata projection. They
confer no release rights: the original admissions, contribution terms, artifact
acceptances and completed R2 preservation receipts still determine each release.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_model_scores import PublicModelScores, _stamp
from .competition_cohort_public_downloads import PublicModelDownload, legacy_download
from .competition_cohort_public_licenses import ModelLicenseMetadataPublisher
from .competition_cohort_public_publisher import (
    CohortPublicPublisherConfig,
    LegacyPublicModelSource,
    NativePublicProjection,
    prepare_native_cohort,
    publish_native_cohort,
)
from .competition_public_results_directory import atomic_write, owned_directory, read_owned_file
from .competition_public_results_publisher import publisher_lease
from .competition_verification_reuse import metadata_completion, remember_metadata_completion
from .competition_verification_snapshot import _Checksummed
from .competition_work_progress import WorkProgress
from .open_competition import ModelBundle, SignedModelLicenseTermsAdoption, digest
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_COMPLETION_BYTES = 128 * 1024**2
SEMANTICS = "native-public-certified-catalog/1"


class NativePublicCatalogWatchConfig(StrictProtocolModel):
    schema_: Literal["umi-native-public-catalog-watch/1"] = Field(alias="schema")
    score_directory: Directory
    state_directory: Directory
    cohorts: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]
    legacy_sources: dict[Hex32, tuple[LegacyPublicModelSource, ...]] = Field(default_factory=dict)
    template: CohortPublicPublisherConfig
    poll_seconds: float = Field(default=15, ge=1, le=3600)
    model_license_adoptions: Annotated[
        tuple[SignedModelLicenseTermsAdoption, ...], Field(max_length=16)
    ] = ()

    @model_serializer(mode="wrap")
    def preserve_original_config(self, handler):
        value = handler(self)
        if not self.model_license_adoptions:
            value.pop("model_license_adoptions", None)
        return value

    @model_validator(mode="after")
    def selected(self):
        source = self.template.native_intake
        if source is None or self.template.inventory is not None:
            raise ValueError("catalog watch requires its selected native intake")
        if len(set(self.cohorts)) != len(self.cohorts):
            raise ValueError("catalog watch repeats a selected cohort")
        if not set(self.cohorts) <= {c.cohort_sha256 for c in source.config.cohorts}:
            raise ValueError("catalog watch selects an unknown native cohort")
        if not self.legacy_sources.keys() <= set(self.cohorts):
            raise ValueError("legacy public transport selects an unknown cohort")
        adoptions = [digest(item) for item in self.model_license_adoptions]
        if adoptions != sorted(set(adoptions)):
            raise ValueError("model license selections must be sorted and unique")
        authorities = {item.authority_sha256 for item in source.config.cohorts}
        if any(
            item.adoption.authority_sha256 not in authorities
            or not set(item.adoption.cohort_sha256s).intersection(self.cohorts)
            for item in self.model_license_adoptions
        ):
            raise ValueError("model license selection has no configured cohort authority")
        paths = tuple(
            map(
                Path,
                (self.score_directory, self.state_directory, self.template.api.results.directory),
            )
        )
        if any(
            a.is_relative_to(b) or b.is_relative_to(a)
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("catalog trigger, completion and public output must be disjoint")
        return self


class CatalogCompletion(_Checksummed):
    schema_: Literal["umi-native-public-catalog-completion/1"] = Field(alias="schema")
    binding_sha256: Hex32
    source_stamp: tuple[str, ...]
    score_metadata_sha256: Hex32
    projection: NativePublicProjection


class TransportCompletion(_Checksummed):
    schema_: Literal["umi-public-legacy-transport-completion/1"] = Field(alias="schema")
    binding_sha256: Hex32
    download: PublicModelDownload


class NativePublicCatalogWatcher:
    def __init__(self, config):
        self.config = config
        self.score = Path(config.score_directory)
        self.state = Path(config.state_directory)
        self.output = Path(config.template.api.results.directory)
        owned_directory(self.score)
        owned_directory(self.state, create=True)
        owned_directory(self.output, create=True)
        self.receipts, self.outputs, self.transports = OrderedDict(), {}, OrderedDict()
        self.verdicts = {}
        self.licenses = ModelLicenseMetadataPublisher(config)

    def _selected(self, cohort):
        source = self.config.template.native_intake.model_copy(update={"cohort_sha256": cohort})
        return self.config.template.model_copy(update={"native_intake": source})

    @staticmethod
    def _binding(config, *, legacy_deadlines=False):
        # Publication location and HTTP capacities may change without redoing
        # successful native release checks. Their shape is checked on publish.
        value = config.model_dump(mode="json", by_alias=True)
        value.pop("api")
        value["legacy_models"] = []
        source = value["native_intake"]
        source["config"]["cohorts"] = [
            row
            for row in source["config"]["cohorts"]
            if row["cohort_sha256"] == source["cohort_sha256"]
        ]
        if not legacy_deadlines:
            deadlines = [
                row
                for row in source["config"].get("admission_deadlines", ())
                if row["cohort_sha256"] == source["cohort_sha256"]
            ]
            if deadlines:
                source["config"]["admission_deadlines"] = deadlines
            else:
                # Preserve the exact identity of completions predating deadlines.
                source["config"].pop("admission_deadlines", None)
        return digest_binding(dict(semantics=SEMANTICS, native_selection=value))

    def _output_stamps(self, report, cohort):
        descriptor = report["descriptor"]
        keys = [descriptor["catalog_sha256"], *descriptor["downloads"].values()]
        if descriptor["paid_results_sha256"] is not None:
            keys.append(descriptor["paid_results_sha256"])
        paths = [self.output / "cohorts" / (cohort + suffix) for suffix in (".json", ".published")]
        paths.extend(self.output / "artifacts" / (key + ".json") for key in keys)
        # Include the original descriptor artifact used by the publication clock.
        checkpoint = read_owned_file(self.output / "cohorts" / (cohort + ".published"), 64)
        paths.append(self.output / "artifacts" / (checkpoint.decode("ascii") + ".json"))
        return {str(p): tuple(_stamp(p)) for p in paths}

    def _legacy_transports(self, cohort, receipt):
        downloads = {d.model_sha256: d for d in receipt.projection.downloads}
        allowed = {
            r.model_sha256
            for r in receipt.projection.catalog.items
            if r.release == "public_release_authorized"
        }
        pending = [
            source
            for source in self.config.legacy_sources.get(cohort, ())
            if source.model_sha256 in allowed and source.model_sha256 not in downloads
        ]
        with WorkProgress("public_legacy_transport_metadata", len(pending), unit="models") as meter:
            for source in pending:
                binding = digest_binding(
                    dict(
                        semantics="umi-public-legacy-transport/1",
                        cohort=cohort,
                        model=source.model_sha256,
                        association=source.association.sha256,
                        package=source.package.sha256,
                        archive=source.archive,
                    )
                )
                path = self.state / "transports" / cohort / (source.model_sha256 + ".json")
                try:
                    stamp = tuple(_stamp(path))
                    previous = self.transports.get(str(path))
                    retained = (
                        previous[1]
                        if previous is not None and previous[0] == stamp
                        else TransportCompletion.model_validate_json(
                            read_owned_file(path, MAX_COMPLETION_BYTES)
                        ).checked()
                    )
                except FileNotFoundError:
                    if metadata_completion(path).exists():
                        raise ValueError(
                            "legacy transport receipt missing; explicit repair required"
                        ) from None
                    package = source.package.read()
                    bundle = ModelBundle.model_validate_json(
                        canonical_json_bytes(json.loads(package)["native_bundle"])
                    )
                    if digest(bundle) != source.model_sha256:
                        raise ValueError(
                            "legacy transport changes its certified public model"
                        ) from None
                    download = legacy_download(
                        cohort, bundle, json.loads(source.association.read()), package
                    )
                    if source.archive is not None:
                        download = PublicModelDownload.model_validate_json(
                            canonical_json_bytes(
                                download.model_copy(update={"archive": source.archive})
                            )
                        )
                    retained = TransportCompletion(
                        schema="umi-public-legacy-transport-completion/1",
                        binding_sha256=binding,
                        download=download,
                    ).sealed()
                    owned_directory(path.parent, create=True)
                    atomic_write(path, canonical_json_bytes(retained))
                    stamp = tuple(_stamp(path))
                if (
                    retained.binding_sha256 != binding
                    or retained.download.cohort_sha256 != cohort
                    or retained.download.model_sha256 != source.model_sha256
                ):
                    raise ValueError(
                        "legacy transport completion binding changed; explicit repair required"
                    )
                remember_metadata_completion(path)
                self.transports[str(path)] = (stamp, retained)
                self.transports.move_to_end(str(path))
                while len(self.transports) > 8:
                    self.transports.popitem(last=False)
                downloads[source.model_sha256] = retained.download
                meter.advance()
        if len(downloads) == len(receipt.projection.downloads):
            return receipt
        projection = receipt.projection.model_copy(update={"downloads": tuple(downloads.values())})
        return receipt.model_copy(update={"projection": projection}).sealed()

    @staticmethod
    def _outputs_current(previous):
        if previous is None:
            return False
        try:
            return all(tuple(_stamp(Path(p))) == s for p, s in previous.items())
        except FileNotFoundError:
            return False

    def poll_once(self):
        with publisher_lease(self.state):
            return self._poll_once()

    def _poll_once(self):
        entered = time.monotonic()
        license_report = self.licenses.poll_once() if self.config.model_license_adoptions else None
        candidates = [
            c
            for c in self.config.cohorts
            if (self.score / (c + ".json")).exists() or (self.state / (c + ".json")).exists()
        ]
        report = dict(
            stage="native_public_catalog_publication",
            completed=0,
            total=len(candidates),
            published=[],
            retained=[],
            held=[],
            chain_submission_authorized=False,
            eta_scope="public_catalog_and_download_metadata_only_excludes_rewards",
        )
        with WorkProgress(
            "native_public_catalog_publication", len(candidates), unit="cohorts"
        ) as meter:
            for cohort in candidates:
                stage = "catalog_completion"
                receipt = projection = enriched = receipt_raw = None
                try:
                    config = self._selected(cohort)
                    receipt_path, score_path = (
                        self.state / (cohort + ".json"),
                        self.score / (cohort + ".json"),
                    )
                    try:
                        stamp = tuple(_stamp(receipt_path))
                        verdict = self.verdicts.get(cohort)
                        if (
                            verdict is not None
                            and verdict[0] == stamp
                            and verdict[1] == self._binding(config)
                            and (
                                not score_path.exists()
                                or tuple(map(str, _stamp(score_path))) == verdict[2]
                            )
                            and self._outputs_current(self.outputs.get(cohort))
                        ):
                            report["retained"].append(cohort)
                            report["completed"] += 1
                            meter.advance()
                            continue
                        cached = self.receipts.get(cohort)
                        if cached is None:
                            self.receipts.clear()
                        if cached is not None and cached[0] == stamp:
                            receipt = cached[1]
                        else:
                            receipt_raw = read_owned_file(receipt_path, MAX_COMPLETION_BYTES)
                            receipt = CatalogCompletion.model_validate_json(receipt_raw).checked()
                    except FileNotFoundError:
                        if (self.output / "cohorts" / (cohort + ".json")).exists():
                            raise ValueError(
                                "catalog completion missing; restore original metadata"
                            ) from None
                        stage = "certified_catalog_trigger"
                        source_stamp = tuple(map(str, _stamp(score_path)))
                        scores = PublicModelScores.model_validate_json(
                            read_owned_file(score_path, 2 * 1024**2)
                        )
                        if scores.cohort_sha256 != cohort:
                            raise ValueError("catalog trigger belongs to another cohort") from None
                        stage = "native_catalog_projection"
                        projection = prepare_native_cohort(
                            config,
                            submission_sha256s=tuple(r.submission_sha256 for r in scores.items),
                        )
                        if projection.catalog.cohort_sha256 != cohort:
                            raise ValueError("native catalog belongs to another cohort") from None
                        known = {r.submission_sha256: r for r in projection.catalog.items}
                        if projection.catalog.policy_sha256 != scores.policy_sha256 or any(
                            s.submission_sha256 not in known
                            or (
                                known[s.submission_sha256].model_sha256,
                                known[s.submission_sha256].uid,
                                known[s.submission_sha256].hotkey,
                            )
                            != (s.model_sha256, s.uid, s.hotkey)
                            for s in scores.items
                        ):
                            raise ValueError(
                                "native catalog differs from certified submissions"
                            ) from None
                        if tuple(map(str, _stamp(score_path))) != source_stamp:
                            raise ValueError(
                                "catalog trigger changed during native projection"
                            ) from None
                        receipt = CatalogCompletion(
                            schema="umi-native-public-catalog-completion/1",
                            binding_sha256=self._binding(config),
                            source_stamp=source_stamp,
                            score_metadata_sha256=(
                                scores.original_source_metadata_sha256
                                or scores.source_metadata_sha256
                            ),
                            projection=projection,
                        ).sealed()
                        raw = canonical_json_bytes(receipt)
                        if len(raw) > MAX_COMPLETION_BYTES:
                            raise ValueError(
                                "public catalog completion exceeds metadata bound"
                            ) from None
                        # Checkpoint original checked public data before exposing any
                        # output; a partial publication resumes without native reads.
                        atomic_write(receipt_path, raw)
                        stamp = tuple(_stamp(receipt_path))
                    binding = self._binding(config)
                    if (
                        receipt.binding_sha256 != binding
                        and receipt.binding_sha256 != self._binding(config, legacy_deadlines=True)
                    ) or receipt.projection.catalog.cohort_sha256 != cohort:
                        raise ValueError(
                            "catalog completion binding changed; explicit repair required"
                        )
                    if receipt.binding_sha256 != binding:
                        stage = "catalog_binding_compatibility"
                        with WorkProgress(
                            stage,
                            1,
                            unit="completions",
                            estimate=False,
                            planning_range_seconds=(0, 30),
                            planning_basis="bounded_local_metadata_copy_and_atomic_wrapper_replacement",
                        ) as compatibility:
                            # Only an exact historical selection may migrate. Keep
                            # its original bytes for rollback before replacing the
                            # unsigned wrapper; authenticated projection is unchanged.
                            history = self.state / "binding-history" / cohort
                            owned_directory(history, create=True)
                            if receipt_raw is None:
                                receipt_raw = read_owned_file(receipt_path, MAX_COMPLETION_BYTES)
                            atomic_write(history / (receipt.checksum + ".json"), receipt_raw)
                            receipt = receipt.model_copy(
                                update={"binding_sha256": binding}
                            ).sealed()
                            atomic_write(
                                receipt_path, canonical_json_bytes(receipt), immutable=False
                            )
                            stamp = tuple(_stamp(receipt_path))
                            compatibility.advance()
                    self.receipts[cohort] = (stamp, receipt)
                    while len(self.receipts) > 1:
                        self.receipts.popitem(last=False)
                    if (
                        score_path.exists()
                        and tuple(map(str, _stamp(score_path))) != receipt.source_stamp
                    ):
                        stage = "adopted_score_catalog_rebind"
                        source_stamp = tuple(map(str, _stamp(score_path)))
                        scores = PublicModelScores.model_validate_json(
                            read_owned_file(score_path, 2 * 1024**2)
                        )
                        catalog = receipt.projection.catalog
                        known = {
                            row.submission_sha256: (row.model_sha256, row.uid, row.hotkey)
                            for row in catalog.items
                        }
                        selected = {
                            row.submission_sha256: (row.model_sha256, row.uid, row.hotkey)
                            for row in scores.items
                        }
                        if (
                            scores.schema_ != "umi-public-cohort-model-results/3"
                            or scores.cohort_sha256 != cohort
                            or scores.policy_sha256 != catalog.policy_sha256
                            or scores.original_source_metadata_sha256
                            != receipt.score_metadata_sha256
                            or selected != known
                            or tuple(map(str, _stamp(score_path))) != source_stamp
                        ):
                            raise ValueError(
                                "completed catalog trigger changed; explicit repair required"
                            )
                        # Only the trigger's delivered metadata changed. Keep the
                        # original authenticated release source and projection;
                        # later signed revisions use this same immutable basis.
                        receipt = receipt.model_copy(update={"source_stamp": source_stamp}).sealed()
                        atomic_write(receipt_path, canonical_json_bytes(receipt), immutable=False)
                        self.receipts[cohort] = (tuple(_stamp(receipt_path)), receipt)
                    stage = "legacy_public_transport_metadata"
                    enriched = self._legacy_transports(cohort, receipt)
                    if enriched is not receipt:
                        atomic_write(receipt_path, canonical_json_bytes(enriched), immutable=False)
                        receipt = enriched
                        self.receipts[cohort] = (tuple(_stamp(receipt_path)), receipt)
                        self.outputs.pop(cohort, None)
                    previous = self.outputs.get(cohort)
                    if self._outputs_current(previous):
                        report["retained"].append(cohort)
                    else:
                        stage = "public_catalog_output"
                        published = publish_native_cohort(config, projection=receipt.projection)
                        self.outputs[cohort] = self._output_stamps(published, cohort)
                        report["published"].append(cohort)
                    self.verdicts[cohort] = (
                        tuple(_stamp(receipt_path)),
                        receipt.binding_sha256,
                        receipt.source_stamp,
                    )
                    report["completed"] += 1
                    meter.advance()
                except (OSError, ValueError, KeyError) as error:
                    report["held"].append(
                        dict(
                            cohort_sha256=cohort,
                            stage=stage,
                            error_type=type(error).__name__,
                            reason=str(error),
                        )
                    )
        report.update(
            elapsed_seconds=round(time.monotonic() - entered, 3),
            percent=100 * report["completed"] / len(candidates) if candidates else 100,
            eta_seconds=0 if not report["held"] else None,
            eta_basis="selected_public_metadata_current"
            if not report["held"]
            else "waiting_for_original_metadata_or_explicit_repair",
            stalled_or_retrying=bool(report["held"]),
        )
        if self.config.model_license_adoptions:
            report["model_license_adoptions"] = license_report
            if license_report["held"]:
                report["stalled_or_retrying"] = True
                report["eta_seconds"] = None
                report["eta_basis"] = "waiting_for_model_license_metadata_repair"
        return report


def digest_binding(value):
    """Domain-separated metadata selection; payloads never enter this function."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
