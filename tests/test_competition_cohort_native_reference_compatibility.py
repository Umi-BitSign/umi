"""New historical commitments through native reveal, certification and reward replay.

Only the fixture's original producer uses the historical encoding. Production
readers, signed catalogs, services, phase votes and reward consumers are unchanged.
"""

import hashlib
import json

import pytest

from umi.competition_cohort_object_codec import endpoint_object_bytes
from umi.competition_cohort_service_quality import ServiceReference
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_lifecycle as lifecycle_fixture
from . import test_competition_cohort_native_pipeline as pipeline
from .test_competition_cohort_native_pipeline import base_policy as base_policy
from .test_competition_cohort_native_pipeline import chain_config as chain_config
from .test_competition_cohort_native_pipeline import host as host
from .test_competition_cohort_native_pipeline import intake as intake
from .test_competition_cohort_native_pipeline import legacy_scenario as legacy_scenario
from .test_competition_cohort_native_pipeline import lifecycle as lifecycle
from .test_competition_cohort_native_pipeline import (
    lifecycle_before_intake as lifecycle_before_intake,
)
from .test_competition_cohort_native_pipeline import policy as policy
from .test_competition_cohort_native_pipeline import recovery as recovery
from .test_competition_cohort_native_pipeline import runtime as runtime
from .test_competition_cohort_native_pipeline import scenario as scenario


def historical_bytes(value):
    return json.dumps(
        value.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


@pytest.fixture(autouse=True)
def historical_producer(monkeypatch, request):
    """Commit before intake; never rewrite a catalog, signature or stored fixture."""

    def reference(**fields):
        return ServiceReference(**(fields | {"reference": "hello café 世界"}))

    def producer_digest(value):
        if isinstance(value, ServiceReference):
            return hashlib.sha256(historical_bytes(value)).hexdigest()
        return digest(value)

    def producer_bytes(value):
        if isinstance(value, ServiceReference):
            return historical_bytes(value)
        return canonical_json_bytes(value)

    monkeypatch.setattr(pipeline, "ServiceReference", reference)
    monkeypatch.setattr(pipeline, "digest", producer_digest)
    monkeypatch.setattr(pipeline, "canonical_json_bytes", producer_bytes)
    if getattr(request, "param", "historical") == "mixed":
        typed_video = b"inert native pipeline typed service video"
        typed_video_sha256 = hashlib.sha256(typed_video).hexdigest()
        typed = ServiceReference(
            schema="umi-cohort-service-reference/1",
            case_id="92" * 32,
            video_sha256=typed_video_sha256,
            stratum="fingerspelling",
            salt="42" * 32,
            reference="hello typed café 世界",
        )
        original_precommit = pipeline.precommit_service_inventory
        catalog_type = lifecycle_fixture.PrecommittedServiceWorkCatalog

        def precommit_both(h, **kwargs):
            def catalog(**fields):
                return catalog_type(
                    **(
                        fields
                        | {
                            "work": (
                                *fields["work"],
                                {
                                    "case_id": typed.case_id,
                                    "video_sha256": typed.video_sha256,
                                    "reference_sha256": digest(typed),
                                    "stratum": typed.stratum,
                                },
                            )
                        }
                    )
                )

            # Select both original identities before the synthetic catalog is
            # signed and before intake. No retained catalog is rewritten.
            with monkeypatch.context() as producer:
                producer.setattr(lifecycle_fixture, "PrecommittedServiceWorkCatalog", catalog)
                original_precommit(h, **kwargs)
            h.typed_reference = typed
            h.service_media = {typed_video_sha256: typed_video}
            h.reference_objects = {
                producer_digest(h.reference): historical_bytes(h.reference),
                digest(typed): canonical_json_bytes(typed),
            }

        monkeypatch.setattr(pipeline, "precommit_service_inventory", precommit_both)


@pytest.mark.parametrize(
    "lifecycle_before_intake", [pipeline.precommit_model_inventory], indirect=True
)
@pytest.mark.parametrize("interrupt", [False, True], ids=["normal", "interrupted-replay"])
async def test_historical_unicode_reference_reaches_native_certified_rewards(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config, interrupt
):
    reference = host.h.reference
    raw = historical_bytes(reference)
    key = hashlib.sha256(raw).hexdigest()
    assert key != digest(reference)
    assert raw != canonical_json_bytes(reference)
    assert host.h.precommitted[0].catalog.work[0].reference_sha256 == key
    originals = host.h.precommitted_bytes
    settled = await pipeline.run_pipeline(
        host,
        scenario,
        runtime,
        tmp_path,
        monkeypatch,
        chain_config,
        interrupt=interrupt,
        mixed=True,
        activate_after_interruption=interrupt,
    )
    package = settled.package
    assert host.h.precommitted_bytes == originals
    assert tuple(canonical_json_bytes(v) for v in host.h.precommitted) == originals
    assert package.inputs.reveal.catalogs[0].references == (key,)
    item = next(item for item in package.objects if item.sha256 == key)
    assert endpoint_object_bytes(item.value, item.sha256) == raw
    assert ServiceReference.model_validate(item.value) == reference
    assert digest(reference) not in {item.sha256 for item in package.objects}
    # The fixture runs actual recurring settlement and reward activation/replay;
    # only finality, media and inference are synthetic ports.
    assert package.service.statement.allocation.recipients
    assert package.allocation.recipients
    assert package.benchmark


@pytest.mark.parametrize(
    "lifecycle_before_intake", [pipeline.precommit_model_inventory], indirect=True
)
@pytest.mark.parametrize("historical_producer", ["mixed"], indirect=True)
async def test_mixed_reference_encodings_survive_interrupted_native_certified_rewards(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config
):
    historical, typed = host.h.reference, host.h.typed_reference
    originals = host.h.precommitted_bytes
    original_objects = dict(host.h.reference_objects)
    historical_key = hashlib.sha256(historical_bytes(historical)).hexdigest()
    typed_key = digest(typed)
    assert len(original_objects) == 2
    assert historical_key != digest(historical)
    assert typed_key != hashlib.sha256(historical_bytes(typed)).hexdigest()
    assert tuple(work.reference_sha256 for work in host.h.precommitted[0].catalog.work) == (
        historical_key,
        typed_key,
    )
    settled = await pipeline.run_pipeline(
        host,
        scenario,
        runtime,
        tmp_path,
        monkeypatch,
        chain_config,
        interrupt=True,
        mixed=True,
        activate_after_interruption=True,
        service_claim_count=2,
    )
    package = settled.package
    assert host.h.precommitted_bytes == originals
    assert tuple(canonical_json_bytes(value) for value in host.h.precommitted) == originals
    assert host.h.reference_objects == original_objects
    assert package.inputs.reveal.catalogs[0].references == (historical_key, typed_key)
    published = {item.sha256: item for item in package.objects}
    for key, raw in original_objects.items():
        assert endpoint_object_bytes(published[key].value, key) == raw
    assert digest(historical) not in published
    assert hashlib.sha256(historical_bytes(typed)).hexdigest() not in published
    assert len(package.inputs.seals[0].accepted) == 2
    assert len(package.inputs.closure.catalogs[0].terminals) == 2
    assert package.service.statement.allocation.recipients
    assert package.allocation.recipients and package.benchmark
