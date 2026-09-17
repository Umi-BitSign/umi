"""Compatibility and dependency checks for the separated command/release layers."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import json
from pathlib import Path

import pytest

from umi.competition_cli import _parser, execute
from umi.competition_commands import COMMAND_HANDLERS

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = Path(__file__).parent / "fixtures" / "module-contracts.json"


def json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def argument_contract(parser: argparse.ArgumentParser) -> dict:
    actions = []
    for action in parser._actions:
        fields = {
            key: getattr(action, key)
            for key in (
                "option_strings",
                "dest",
                "nargs",
                "const",
                "default",
                "required",
                "help",
                "metavar",
            )
        }
        fields["type"] = (
            f"{action.type.__module__}.{action.type.__qualname__}"
            if action.type is not None
            else None
        )
        fields["choices"] = (
            {name: argument_contract(child) for name, child in action.choices.items()}
            if isinstance(action, argparse._SubParsersAction)
            else action.choices
        )
        actions.append(fields)
    return {"description": parser.description, "actions": actions}


def test_public_command_arguments_match_pre_refactor_contract() -> None:
    contracts = json.loads(CONTRACTS.read_text())
    assert json_sha256(argument_contract(_parser())) == contracts["competition_cli_sha256"]


def test_every_command_has_exactly_one_named_handler() -> None:
    parser = _parser()
    commands = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert set(commands.choices) == set(COMMAND_HANDLERS)
    assert all(callable(handler) for handler in COMMAND_HANDLERS.values())
    assert all(handler.__name__ != "<lambda>" for handler in COMMAND_HANDLERS.values())


def test_unknown_command_does_not_open_policy_or_state(tmp_path: Path) -> None:
    state = tmp_path / "must-not-exist"
    with pytest.raises(ValueError, match="unsupported competition command"):
        execute(argparse.Namespace(command="unknown", policy="/missing-policy", state=str(state)))
    assert not state.exists()


def test_published_schemas_match_pre_refactor_contracts() -> None:
    contracts = json.loads(CONTRACTS.read_text())
    for reference, expected in contracts["schema_sha256"].items():
        module_name, class_name = reference.rsplit(".", 1)
        model = getattr(importlib.import_module("umi." + module_name), class_name)
        assert json_sha256(model.model_json_schema()) == expected, reference


@pytest.mark.parametrize(
    ("module_name", "forbidden"),
    [
        (
            "releases.layout",
            {"shadow_release", "releases.models", "releases.sources", "releases.wheel"},
        ),
        ("releases.models", {"shadow_release", "releases.sources", "releases.wheel"}),
        ("releases.sources", {"shadow_release", "releases.models", "releases.wheel"}),
        ("releases.wheel", {"shadow_release", "releases.models", "releases.sources"}),
        ("bridge.policy", {"registration_bridge", "bridge.selection"}),
        ("bridge.selection", {"registration_bridge", "bootstrap_weight_operator"}),
        ("competition_commands.common", {"competition_cli"}),
        ("competition_commands.arguments", {"competition_cli"}),
    ],
)
def test_lower_layers_do_not_import_their_callers(module_name: str, forbidden: set[str]) -> None:
    path = ROOT / "src" / "umi" / (module_name.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text())
    package = "umi." + module_name.rsplit(".", 1)[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            name = (
                importlib.util.resolve_name("." * node.level + (node.module or ""), package)
                if node.level
                else node.module
            )
            assert name not in {"umi." + value for value in forbidden}, (module_name, name)
        elif isinstance(node, ast.Import):
            assert not ({alias.name for alias in node.names} & {"umi." + v for v in forbidden})


@pytest.mark.parametrize(
    ("old", "new", "name"),
    [
        ("shadow_release", "releases.models", "LiveShadowReleaseManifest"),
        ("shadow_release", "releases.layout", "ShadowReleaseError"),
        ("shadow_release", "releases.sources", "_canonical_source_bundle"),
        ("shadow_release", "releases.wheel", "_verify_wheel_matches_source"),
        ("registration_bridge", "bridge.policy", "SignedRegistrationBridgePolicy"),
        ("registration_bridge", "bridge.selection", "validate_registration_bridge_observation"),
        ("competition_cli", "competition_commands.common", "SettlementInput"),
    ],
)
def test_compatibility_exports_are_the_same_objects(old: str, new: str, name: str) -> None:
    assert getattr(importlib.import_module("umi." + old), name) is getattr(
        importlib.import_module("umi." + new), name
    )
