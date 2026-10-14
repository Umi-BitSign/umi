"""Increase a stopped preparation allowance without opening native history."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .competition_coordinator_namespace import ensure_coordinator_host_view
from .competition_host_anchor import load_materialized_successor_anchor_for_repair
from .competition_reward_history_preparation_capacity import migrate_preparation_capacity


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--preparation-unit", required=True)
    for name in (
        "config",
        "old-boot",
        "new-boot",
        "old-approval",
        "new-approval",
        "old-preparation-launch",
        "new-preparation-launch",
        "old-writer-launch",
        "new-writer-launch",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--held-approval", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or (os.getuid(), os.geteuid()) != (0, 0):
        raise ValueError("capacity migration requires a fresh root Linux broker")
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO)
    ensure_coordinator_host_view(unit_name=args.unit, config_path=args.config)
    anchor = load_materialized_successor_anchor_for_repair(args.config)
    result = migrate_preparation_capacity(
        anchor,
        old_boot=args.old_boot,
        new_boot=args.new_boot,
        old_approval=args.old_approval,
        new_approval=args.new_approval,
        preparation_launch=(args.old_preparation_launch, args.new_preparation_launch),
        writer_launch=(args.old_writer_launch, args.new_writer_launch),
        preparation_unit=args.preparation_unit,
        installed_unit=args.unit,
        config_path=args.config,
        held_approval=args.held_approval,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
