"""Supported isolated host launchers, safe when multiprocessing imports main.

Apply to an unsigned candidate before sealing and signing its manifest. Existing
signed installations retain their exact bytes until the normal host upgrade.
"""

from __future__ import annotations

from pathlib import Path

HOST_ENTRYPOINTS = {
    "umi-competition-supervisor": "umi.competition_supervisor_cli",
    "umi-competition-supervisor-cleanup": "umi.competition_supervisor_cleanup",
}


def render_host_entrypoint(interpreter: Path, module: str) -> bytes:
    if (
        not interpreter.is_absolute()
        or str(interpreter) != str(Path(str(interpreter)))
        or any(character.isspace() or ord(character) < 32 for character in str(interpreter))
        or ".." in interpreter.parts
        or module not in HOST_ENTRYPOINTS.values()
    ):
        raise ValueError("unsupported isolated host entrypoint")
    return (
        f'#!{interpreter} -I\nfrom {module} import main\n\nif __name__ == "__main__":\n    main()\n'
    ).encode()


def repair_host_entrypoint(raw: bytes, interpreter: Path, module: str) -> bytes:
    """Recognize the original isolated wrapper and its guarded successor."""
    guarded = render_host_entrypoint(interpreter, module)
    legacy = f"#!{interpreter} -I\nfrom {module} import main\nmain()\n".encode()
    if raw not in (legacy, guarded):
        raise ValueError("unsupported host launcher requires a separate migration")
    return guarded
