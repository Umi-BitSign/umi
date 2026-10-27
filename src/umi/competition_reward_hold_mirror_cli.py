"""Publish cohort hold mirrors or render their explicit service lifecycle hooks."""

import argparse
import json
import logging
from pathlib import Path

from .competition_reward_hold_mirror import (
    load_mirror_config,
    mirror_drop_in,
    update_hold_mirror,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("publish", "invalidate", "drop-in"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--python")
    parser.add_argument("--source-directory")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        if args.action == "drop-in":
            if args.python is None:
                parser.error("drop-in requires the installed --python path")
            print(
                mirror_drop_in(
                    args.config,
                    python=args.python,
                    source_directory=args.source_directory,
                ),
                end="",
            )
        else:
            if args.python is not None or args.source_directory is not None:
                parser.error("interpreter and source options are only for drop-in")
            print(
                json.dumps(
                    update_hold_mirror(
                        load_mirror_config(args.config),
                        publish=args.action == "publish",
                    )
                )
            )
    except Exception as error:
        report = {"status": "failed", "error_type": type(error).__name__}
        if type(error) is ValueError:
            report["reason"] = str(error)[:256]
        print(json.dumps(report))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
