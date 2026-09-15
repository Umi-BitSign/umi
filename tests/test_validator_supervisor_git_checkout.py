from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[1] / "deploy/linux-validator-supervisor/install.sh"


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _source_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, release_ref: str
) -> tuple[Path, str]:
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "0")
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    _git(upstream, "init", "--initial-branch=main")
    _git(upstream, "config", "user.name", "Installer regression")
    _git(upstream, "config", "user.email", "installer@example.invalid")
    (upstream / "release.txt").write_text("main\n")
    _git(upstream, "add", "release.txt")
    _git(upstream, "commit", "-m", "main")
    _git(upstream, "checkout", "-b", "runtime-release")
    (upstream / "release.txt").write_text("exact signed runtime\n")
    _git(upstream, "commit", "-am", "runtime release")
    release = _git(upstream, "rev-parse", "HEAD").stdout.strip()
    if release_ref == "main":
        _git(upstream, "branch", "-f", "main", release)
    elif release_ref == "tag":
        _git(upstream, "tag", "runtime", release)
    _git(upstream, "checkout", "main")
    if release_ref != "remote-only":
        _git(upstream, "branch", "-D", "runtime-release")
    source = tmp_path / "operator checkout"
    _git(tmp_path, "clone", "--no-local", str(upstream), str(source))
    return source, release


def _run_installer_checkout(
    source: Path, destination: Path, release: str
) -> subprocess.CompletedProcess[str]:
    installer = INSTALLER.read_text()
    start = installer.index("supervisor_created=true\n")
    end = installer.index('install -o root -g root -m 0755 "$uv_source"', start)
    # Execute the installer itself through its exact-checkout checks. This block
    # must remain before dependencies, wallets and systemd service retirement.
    assert end < installer.index('systemctl disable --now "$legacy_unit"')
    return subprocess.run(
        ["sh", "-eu", "-c", 'fail() { printf "%s\\n" "$*" >&2; exit 2; }\n' + installer[start:end]],
        env={
            **os.environ,
            "source_root": str(source),
            "supervisor_root": str(destination),
            "release_revision": release,
        },
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize("release_ref", ["remote-only", "main", "tag"])
def test_installer_copies_exact_release_without_source_ref_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, release_ref: str
) -> None:
    source, release = _source_clone(tmp_path, monkeypatch, release_ref)
    source_refs = _git(source, "show-ref").stdout
    source_head = _git(source, "rev-parse", "HEAD").stdout
    if release_ref == "remote-only":
        assert _git(source, "branch", "--contains", release).stdout == ""
        remote_branches = _git(source, "branch", "-r", "--contains", release).stdout
        assert "origin/runtime-release" in remote_branches
        before = tmp_path / "old installer clone"
        _git(
            tmp_path,
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            str(source),
            str(before),
        )
        assert _git(before, "checkout", "--detach", release, check=False).returncode != 0
    destination = tmp_path / "installed supervisor"
    result = _run_installer_checkout(source, destination, release)
    assert result.returncode == 0, result.stderr
    assert _git(destination, "rev-parse", "HEAD").stdout.strip() == release
    assert _git(destination, "symbolic-ref", "-q", "HEAD", check=False).returncode == 1
    assert (destination / "release.txt").read_text() == "exact signed runtime\n"
    assert _git(destination, "status", "--porcelain", "--untracked-files=all").stdout == ""
    assert _git(source, "show-ref").stdout == source_refs
    assert _git(source, "rev-parse", "HEAD").stdout == source_head
    assert _git(source, "status", "--porcelain", "--untracked-files=all").stdout == ""


def test_installer_checkout_rejects_missing_release_without_falling_back_to_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _source_clone(tmp_path, monkeypatch, "remote-only")
    destination = tmp_path / "missing release"
    result = _run_installer_checkout(source, destination, "f" * 40)
    assert result.returncode != 0
    assert "could not fetch the current release revision" in result.stderr
    assert not (destination / "release.txt").exists()
