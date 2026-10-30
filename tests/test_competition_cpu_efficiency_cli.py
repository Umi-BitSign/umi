"""CPU actor envelope uses the same isolated CLI with its own bounded type."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from umi import competition_cpu_efficiency_operator as operator
from umi.protocol import canonical_json_bytes

from .test_competition_cpu_efficiency_adoption import (
    base_policy as base_policy,
)
from .test_competition_cpu_efficiency_adoption import (
    cpu_operator as cpu_operator,
)
from .test_competition_cpu_efficiency_adoption import (
    cpu_review as cpu_review,
)
from .test_competition_cpu_efficiency_adoption import (
    original_runtime as original_runtime,
)
from .test_competition_cpu_efficiency_adoption import (
    policy as policy,
)
from .test_competition_cpu_efficiency_adoption import (
    recovery as recovery,
)
from .test_competition_cpu_efficiency_adoption import (
    runtime as runtime,
)
from .test_competition_cpu_efficiency_adoption import (
    runtime_adoption as runtime_adoption,
)
from .test_competition_cpu_efficiency_adoption import (
    scenario as scenario,
)


def actor_cli(raw):
    module = "umi.competition_cohort_model_batch_adoption_cli"
    source = str(Path(operator.__file__).resolve().parents[1])
    code = (
        "import runpy,sys;sys.path.insert(0," + repr(source) + ")\n"
        "from umi import competition_cpu_efficiency_operator as actor\n"
        "def publish(target,request,signed=None,*,check_only=False):\n"
        " return dict(target=target.model_dump(mode='json'),"
        "request=request.model_dump(mode='json',by_alias=True),"
        "signed=signed,check_only=check_only)\n"
        "actor.publish_cpu_for_actor=publish\n"
        + f"sys.argv=[{module!r},'publish-cpu'];runpy.run_module({module!r},run_name='__main__')"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code], input=raw, capture_output=True, timeout=30
    )
    return result.returncode, json.loads(result.stdout)


@pytest.mark.parametrize("check_only", [False, True])
def test_cpu_actor_cli_roundtrips_exact_selected_request(cpu_operator, check_only):
    o = cpu_operator
    raw = canonical_json_bytes(
        operator.CpuEfficiencyActorPublication(
            target=o.config.owner,
            request=o.c.request,
            check_only=check_only,
        )
    )
    status, result = actor_cli(raw)
    assert status == 0
    assert canonical_json_bytes(result) == raw


@pytest.mark.parametrize("bad", ["noncanonical", "oversized", "wrong-type"])
def test_cpu_actor_cli_rejects_noncanonical_or_unbounded_request(cpu_operator, bad):
    o = cpu_operator
    raw = canonical_json_bytes(
        operator.CpuEfficiencyActorPublication(
            target=o.config.owner,
            request=o.c.request,
        )
    )
    if bad == "noncanonical":
        raw += b"\n"
    elif bad == "oversized":
        raw = b" " * (512 * 1024 + 1)
    else:
        value = json.loads(raw)
        value["request"]["schema"] = "umi-model-batch-adoption-review-request/1"
        raw = canonical_json_bytes(value)
    status, result = actor_cli(raw)
    assert status == 1
    assert result["retained_work_reused_on_exact_retry"] is True
