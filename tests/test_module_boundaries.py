"""Compatibility and dependency checks for the separated command/release layers."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import json
from collections.abc import Iterator
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
    current = argument_contract(_parser())
    commands = next(
        action["choices"] for action in current["actions"] if action["dest"] == "command"
    )
    # This additive command has its own parser/handler tests. Preserve the
    # original digest so changes to any pre-existing command still fail here.
    commands.pop("verify-miner-feed-profile")
    # Capacity is an optional operational addition, not a signed protocol field.
    # Check its defaults explicitly, then preserve the historical argument hash.
    for command in ("serve-assignment-feed", "assemble-endpoint-execution"):
        actions = commands[command]["actions"]
        added = next(action for action in actions if action["dest"] == "scheduling_capacity")
        assert added["option_strings"] == ["--scheduling-capacity"]
        assert added["default"] is None
        assert added["required"] is False
        actions.remove(added)
    # Deal-preserving predecessor policies are an optional operator input, not a
    # signed protocol field. Check the flag's shape, then preserve the historical hash.
    predecessor = next(
        action for action in current["actions"] if action["dest"] == "predecessor_policy"
    )
    assert predecessor["option_strings"] == ["--predecessor-policy"]
    assert predecessor["default"] == []
    assert predecessor["required"] is False
    current["actions"].remove(predecessor)
    assert json_sha256(current) == contracts["competition_cli_sha256"]


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
        schema = model.model_json_schema()
        pins = schema.get("$defs", {}).get("PolicyImplementationPins")
        if pins is not None:
            # The optional platform pins extend the schema; all historical
            # fields retain their exact pre-refactor contract and signed bytes.
            extension = pins["properties"].pop("scoring_by_target")
            assert extension["default"] is None
            assert "scoring_by_target" not in pins["required"]
        assert json_sha256(schema) == expected, reference


def runtime_nodes(node: ast.AST) -> Iterator[ast.AST]:
    """Annotation-only imports do not create a runtime dependency cycle."""
    yield node
    if (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Name)
        and node.test.id == "TYPE_CHECKING"
    ):
        children = node.orelse
    else:
        children = ast.iter_child_nodes(node)
    for child in children:
        yield from runtime_nodes(child)


def test_dependency_walk_skips_annotations_but_keeps_runtime_branches() -> None:
    tree = ast.parse(
        "if TYPE_CHECKING:\n"
        "    from .annotations import Type\n"
        "else:\n"
        "    from .fallback import Runtime\n"
        "if enabled:\n"
        "    from .conditional import Runtime\n"
        "from .ordinary import Runtime\n"
    )
    assert [node.module for node in runtime_nodes(tree) if isinstance(node, ast.ImportFrom)] == [
        "fallback",
        "conditional",
        "ordinary",
    ]


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
        (
            "bridge.journal",
            {"registration_bridge", "registration_bridge_recover", "bridge.signing"},
        ),
        ("bridge.signing", {"registration_bridge", "competition_weights", "competition_chain"}),
        (
            "bridge.submission",
            {"registration_bridge", "registration_bridge_recover", "competition_weights"},
        ),
        (
            "bridge.transactions",
            {"registration_bridge", "registration_bridge_recover", "competition_weights"},
        ),
        (
            "bridge.journal_history",
            {"registration_bridge", "registration_bridge_recover", "competition_recovery"},
        ),
        (
            "competition_bridge_recovery",
            {"registration_bridge", "registration_bridge_recover", "competition_recovery"},
        ),
        ("runtime_metadata", {"registration_bridge", "competition_weights", "competition_chain"}),
        ("signed_extrinsic", {"competition_weights", "registration_bridge", "competition_chain"}),
        ("competition_commands.common", {"competition_cli"}),
        ("competition_commands.arguments", {"competition_cli"}),
        (
            "competition_evaluator_capacity",
            {"competition_evaluator", "competition_work_signing", "competition_work_queue"},
        ),
        (
            "competition_evaluator_budget",
            {"competition_work_signing", "competition_work_admission"},
        ),
        ("competition_work_admission", {"competition_work_signing", "competition_work_transport"}),
        (
            "competition_round_journal",
            {
                "competition_rounds",
                "competition_work_signing",
                "competition_work_admission",
                "competition_work_queue",
                "competition_settlement_delivery",
                "competition_successor_feed",
            },
        ),
        (
            "competition_round_plan",
            {"competition_rounds", "competition_round_journal", "competition_work_signing"},
        ),
        (
            "competition_scheduling_receipts",
            {"competition_scheduling", "competition_work_admission"},
        ),
        (
            "grandpa_finality_accounting",
            {"grandpa_finality_supervisor", "competition_chain", "bootstrap_chain_capture"},
        ),
        (
            "private_files",
            {
                "competition_evaluator",
                "competition_exchange",
                "competition_rounds",
                "competition_work_queue",
                "competition_settlement_delivery",
                "competition_successor_feed",
                "competition_successor_follow",
            },
        ),
        (
            "concurrency",
            {
                "competition_chain",
                "competition_chain_state",
                "competition_successor_feed",
                "competition_successor_follow",
                "competition_successor_publisher",
                "grandpa_finality_supervisor",
            },
        ),
    ],
)
def test_lower_layers_do_not_import_their_callers(module_name: str, forbidden: set[str]) -> None:
    path = ROOT / "src" / "umi" / (module_name.replace(".", "/") + ".py")
    tree = ast.parse(path.read_text())
    package = ("umi." + module_name).rpartition(".")[0]
    for node in runtime_nodes(tree):
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
        ("registration_bridge", "bridge.journal", "RegistrationBridgeAttempt"),
        ("registration_bridge", "bridge.journal", "RegistrationBridgeChurnAttempt"),
        ("registration_bridge", "bridge.journal", "RegistrationBridgeJournal"),
        ("registration_bridge", "bridge.journal", "reconcile_registration_bridge_journal"),
        ("registration_bridge", "bridge.journal", "_new_attempt"),
        ("registration_bridge", "bridge.submission", "build_registration_bridge_call"),
        ("registration_bridge", "bridge.journal_history", "MAX_HISTORY_FILES"),
        ("competition_cli", "competition_commands.common", "SettlementInput"),
        ("competition_rounds", "competition_round_plan", "RoundPlan"),
        ("competition_rounds", "competition_round_plan", "RoundProposal"),
        ("competition_rounds", "competition_round_journal", "RoundJournal"),
        ("competition_rounds", "competition_round_journal", "RecordReservation"),
        ("competition_rounds", "competition_round_journal", "MAX_BYTES"),
    ],
)
def test_compatibility_exports_are_the_same_objects(old: str, new: str, name: str) -> None:
    assert getattr(importlib.import_module("umi." + old), name) is getattr(
        importlib.import_module("umi." + new), name
    )


@pytest.mark.parametrize(
    ("legacy", "owner"),
    [
        ("Directory", "Directory"),
        ("_path", "private_path"),
        ("_private", "ensure_private_directory"),
        ("_read", "read_private_model"),
        ("_lock_file", "lock_private_file"),
        ("_publish", "publish_private_model"),
        ("_publish_locked", "_publish_locked"),
    ],
)
def test_evaluator_file_helpers_remain_compatible_exports(legacy: str, owner: str) -> None:
    evaluator = importlib.import_module("umi.competition_evaluator")
    private_files = importlib.import_module("umi.private_files")
    assert getattr(evaluator, legacy) is getattr(private_files, owner)


def test_competition_consumers_import_file_helpers_from_owner() -> None:
    helpers = {"Directory", "_path", "_private", "_read", "_lock_file", "_publish", "MAX_BYTES"}
    for path in (ROOT / "src" / "umi").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom) and node.module in {
                "competition_evaluator",
                "umi.competition_evaluator",
            }:
                assert not (helpers & {alias.name for alias in node.names}), path
