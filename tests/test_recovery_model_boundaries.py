"""Archive schemas stay independent of filesystem and live chain adapters."""

import ast
from pathlib import Path

import pytest

from umi import competition_recovery as recovery
from umi import competition_recovery_models as models


@pytest.mark.parametrize(
    "name",
    [
        "CompetitionRecoveryError",
        "RecoveryLimits",
        "LegacyFileReference",
        "LegacyEffect",
        "LegacySnapshotManifest",
        "RecoveryContextReference",
        "RecoveryCheckpointBody",
        "PreparedRecoveryCheckpoint",
    ],
)
def test_existing_recovery_imports_export_the_same_models(name):
    assert getattr(recovery, name) is getattr(models, name)


def test_model_module_has_no_runtime_host_or_filesystem_dependency():
    tree = ast.parse(Path(models.__file__).read_text())
    imports = {
        name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names
    } | {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imports == {
        "__future__",
        "hashlib",
        "re",
        "typing",
        "pydantic",
        "typing_extensions",
        "encoding",
        "protocol",
    }
    assert not any(isinstance(node, (ast.AsyncFunctionDef, ast.Await)) for node in ast.walk(tree))
