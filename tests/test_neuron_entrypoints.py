from __future__ import annotations

import ast
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _main_import(path: Path) -> tuple[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = [
        (node.module, alias.name)
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.asname is None and alias.name == "main"
    ]
    assert len(imports) == 1
    module, name = imports[0]
    assert module is not None
    return module, name


def test_conventional_neuron_entrypoints_use_production_services() -> None:
    assert _main_import(REPOSITORY_ROOT / "neurons" / "miner.py") == ("umi.miner", "main")
    assert _main_import(REPOSITORY_ROOT / "neurons" / "validator.py") == (
        "umi.validator_live",
        "main",
    )
