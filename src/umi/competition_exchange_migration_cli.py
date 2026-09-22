"""Quiesced, launch-only exchange migration; no intake writes or new signatures."""

from __future__ import annotations

import argparse
import sqlite3

from .competition_commands.common import load_json
from .competition_exchange import ExchangeConfig
from .competition_exchange_migration import migrate_exchange_launch
from .competition_policy_lineage import register_lineage
from .open_competition import CompetitionPolicy
from .protocol import canonical_json_bytes


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--predecessor-policy", action="append", default=[])
    parser.add_argument("--previous-config", required=True)
    parser.add_argument("--replacement-config", required=True)
    parser.add_argument("--confirm-quiesced-backup", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = load_json(args.policy, CompetitionPolicy)
        register_lineage(
            policy, [load_json(path, CompetitionPolicy) for path in args.predecessor_policy]
        )
        result = migrate_exchange_launch(
            load_json(args.previous_config, ExchangeConfig),
            load_json(args.replacement_config, ExchangeConfig),
            policy,
            confirmed=args.confirm_quiesced_backup,
        )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        parser.exit(2, f"exchange launch migration rejected ({type(error).__name__})\n")
    # The durable receipt retains signatures; terminal output contains only identifiers.
    result.pop("signed_amendment")
    print(canonical_json_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
