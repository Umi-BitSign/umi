"""One-shot, explicitly quiesced competition-ledger writer migration."""

from __future__ import annotations

import argparse
from pathlib import Path

from .competition_commands.common import load_json
from .competition_service import CompetitionServiceConfig
from .competition_store import CompetitionStore
from .open_competition import CompetitionPolicy, digest
from .protocol import canonical_json_bytes


def migrate(
    state: Path,
    policy: CompetitionPolicy,
    *,
    confirmed: bool,
    service_config=None,
) -> dict:
    if not confirmed:
        raise ValueError("writer migration requires a quiesced store and verified backup")
    state = state.absolute()
    if not (state / "competition.sqlite3").is_file():
        raise ValueError("writer migration requires the existing durable ledger")
    config = None
    if service_config is not None:
        config = CompetitionServiceConfig.model_validate_json(canonical_json_bytes(service_config))
        if Path(config.state_directory).resolve() != state.resolve():
            raise ValueError("service config and migration name different state directories")
        if config.policy_sha256 != digest(policy):
            raise ValueError("service config and migration bind different policies")
        common_options = {
            "admission_capacity": config.admission_capacity,
            "public_launch": config.public_deployment.launch_identity(),
            "migrate_writer_generation": True,
        }
        store = CompetitionStore(
            state,
            policy,
            **common_options,
            submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
            initial_checkpoint_submission_sha256s=(
                config.retained_state.required_submission_sha256s
            ),
            initial_checkpoint_baseline_promotion_sha256=(
                config.retained_state.baseline_promotion_sha256
            ),
            initialize_submission_checkpoint=True,
        )
    else:
        store = CompetitionStore(state, policy, migrate_writer_generation=True)
    return {
        "status": (
            "writer_generation_and_submission_checkpoint_migrated"
            if config is not None
            else "writer_generation_migrated"
        ),
        "policy_sha256": digest(policy),
        "retained_submission_head": store.retained_submission_head(),
        "restart_services_without_migration": True,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Migrate one stopped, backed-up competition ledger to writer generation 2."
    )
    parser.add_argument("--policy", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument(
        "--service-config",
        help="launch-bound service config used to initialize the independent checkpoint",
    )
    parser.add_argument("--confirm-quiesced-backup", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = migrate(
            Path(args.state),
            load_json(args.policy, CompetitionPolicy),
            confirmed=args.confirm_quiesced_backup,
            service_config=(
                load_json(args.service_config, CompetitionServiceConfig)
                if args.service_config
                else None
            ),
        )
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"competition store migration rejected ({type(error).__name__})\n")
    print(canonical_json_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
