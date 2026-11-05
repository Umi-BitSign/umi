"""Publication must retain service-only groups without changing account access."""

import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_cohort_model_batch_adoption_operator as operator
from umi.competition_actor_credentials import selected_process_credentials


def test_actual_kernel_credentials():
    assert selected_process_credentials(os.getpid(), os.getuid()) == {
        "user": os.getuid(),
        "group": os.getgid(),
        "extra_groups": sorted(set(os.getgroups())),
    }


@pytest.mark.parametrize(
    "body",
    [
        b"Uid:\t12 12 12 12\nGid:\t13 13 13 13\nGroups:\t13 99\n",
        b"Uid:\t11 11 11 11\nGid:\t13 0 13 13\nGroups:\t13 99\n",
        b"Uid:\t11 11 11 11\nGid:\t13 13 13 13\nGroups:\t4294967295\n",
    ],
)
def test_refuses_foreign_or_mixed_credentials(monkeypatch, body):
    monkeypatch.setattr(Path, "open", lambda *a, **k: io.BytesIO(body))
    with pytest.raises(ValueError):
        selected_process_credentials(55, 11)


def test_root_delegates_exact_service_groups(monkeypatch):
    target = SimpleNamespace(service_account="reviewer", model_dump=lambda **k: {})
    request = SimpleNamespace(model_dump=lambda **k: {})
    monkeypatch.setattr(operator.os, "geteuid", lambda: 0)
    monkeypatch.setattr(operator.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=11))
    monkeypatch.setattr(operator, "check_target_process", lambda t: {"pid": 55})

    def credentials(pid, uid):
        assert (pid, uid) == (55, 11)
        return dict(user=11, group=13, extra_groups=[13, 99])

    monkeypatch.setattr(operator, "selected_process_credentials", credentials)

    def run(command, **kwargs):
        assert "sudo" not in command
        assert kwargs["user"] == 11 and kwargs["group"] == 13
        assert kwargs["extra_groups"] == [13, 99]
        assert command[1:3] == ["-I", "-B"]
        return SimpleNamespace(stdout=b"{}", returncode=0)

    monkeypatch.setattr(operator.subprocess, "run", run)
    assert operator.actor_publication(target, request, check_only=True) == {}


def test_changed_actor_refused_before_spawn(monkeypatch):
    target = SimpleNamespace(service_account="reviewer", model_dump=lambda **k: {})
    request = SimpleNamespace(model_dump=lambda **k: {})
    monkeypatch.setattr(operator.os, "geteuid", lambda: 0)
    monkeypatch.setattr(operator.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=11))
    states = iter([{"pid": 55}, {"pid": 56}])
    monkeypatch.setattr(operator, "check_target_process", lambda t: next(states))
    monkeypatch.setattr(operator, "selected_process_credentials", lambda *a: {})
    monkeypatch.setattr(operator.subprocess, "run", lambda *a, **k: pytest.fail("actor changed"))
    with pytest.raises(operator.ModelBatchAdoptionRefused, match="changed"):
        operator.actor_publication(target, request, check_only=True)
