"""Run real spawned children through the supported isolated host wrapper."""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from umi.competition_host_entrypoints import render_host_entrypoint, repair_host_entrypoint


@pytest.mark.parametrize("guarded", [False, True])
def test_spawned_child_never_reenters_the_supervisor_lease(tmp_path, guarded):
    package = tmp_path / "umi"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "competition_supervisor_cli.py").write_text(
        textwrap.dedent("""
        import fcntl
        import multiprocessing
        from pathlib import Path
        import sys

        def child(output):
            Path(output).write_text("native worker dispatched")

        def main():
            with open(sys.argv[1] + ".lock", "w") as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                process = multiprocessing.get_context("spawn").Process(
                    target=child, args=(sys.argv[1],))
                process.start()
                process.join(15)
                if process.is_alive():
                    process.kill()
                    process.join()
                    raise RuntimeError("spawned worker did not finish")
                if process.exitcode != 0:
                    raise RuntimeError("spawned worker reentered supervisor")
    """)
    )
    interpreter = Path(sys.executable)
    module = "umi.competition_supervisor_cli"
    launcher = tmp_path / "umi-competition-supervisor"
    legacy = f"#!{interpreter} -I\nfrom {module} import main\nmain()\n".encode()
    launcher.write_bytes(repair_host_entrypoint(legacy, interpreter, module) if guarded else legacy)
    output = tmp_path / "worker-result"
    # -I models the installed isolated interpreter; its qualified import root is
    # explicit here, and spawn receives that same root through preparation data.
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
            "p=sys.argv.pop(1); sys.argv[0]=p; runpy.run_path(p,run_name='__main__')",
            str(tmp_path),
            str(launcher),
            str(output),
        ],
        text=True,
        capture_output=True,
        timeout=30,
    )
    if guarded:
        assert result.returncode == 0, result.stderr
        assert output.read_text() == "native worker dispatched"
    else:
        assert result.returncode != 0
        assert "BlockingIOError" in result.stderr
        assert not output.exists()


@pytest.mark.parametrize(
    "module", ["umi.competition_supervisor_cli", "umi.competition_supervisor_cleanup"]
)
def test_supported_repeat_and_unknown_launcher_refusal(module):
    interpreter = Path("/opt/host/.venv/bin/python")
    guarded = render_host_entrypoint(interpreter, module)
    assert repair_host_entrypoint(guarded, interpreter, module) == guarded
    with pytest.raises(ValueError, match="separate migration"):
        repair_host_entrypoint(guarded + b"main()\n", interpreter, module)


@pytest.mark.parametrize(
    "interpreter", [Path("relative/python"), Path("/opt/../python"), Path("/opt/has space/python")]
)
def test_invalid_interpreter_rejected(interpreter):
    with pytest.raises(ValueError, match="unsupported"):
        render_host_entrypoint(interpreter, "umi.competition_supervisor_cli")
