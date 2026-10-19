"""Local successor rehearsal commands. No command can submit chain weights."""

from __future__ import annotations

import argparse
import re

from .competition_client import CompetitionSubmissionError
from .competition_commands import COMMAND_HANDLERS
from .competition_commands.arguments import build_parser as _parser
from .competition_commands.common import (
    MAX_JSON_BYTES as MAX_JSON_BYTES,
)
from .competition_commands.common import (
    ExecutionInputs as ExecutionInputs,
)
from .competition_commands.common import (
    ExecutionRevealPulses as ExecutionRevealPulses,
)
from .competition_commands.common import (
    IndependentReplayEntry as IndependentReplayEntry,
)
from .competition_commands.common import (
    ProjectionInput as ProjectionInput,
)
from .competition_commands.common import (
    PublicationEvidenceInputs as PublicationEvidenceInputs,
)
from .competition_commands.common import (
    PublicationRoster as PublicationRoster,
)
from .competition_commands.common import (
    ReplayEntry as ReplayEntry,
)
from .competition_commands.common import (
    SettlementInput as SettlementInput,
)
from .competition_commands.common import (
    load_json as _load,
)
from .competition_policy_lineage import register_lineage
from .open_competition import CompetitionPolicy
from .protocol import canonical_json_bytes


def execute(args: argparse.Namespace) -> dict:
    try:
        handler = COMMAND_HANDLERS[args.command]
    except KeyError:
        raise ValueError("unsupported competition command") from None
    policy = _load(args.policy, CompetitionPolicy)
    predecessors = tuple(
        _load(path, CompetitionPolicy) for path in getattr(args, "predecessor_policy", ())
    )
    # Validates the chain and makes it visible to every policy-bound check downstream.
    register_lineage(policy, predecessors)
    return handler(args, policy)


def main(argv: list[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = execute(args)
    except CompetitionSubmissionError as error:
        # Stable diagnostics only: never print response bodies, signed inputs,
        # wallet paths, exception chains or presigned bearer URLs.
        reason = error.reason_code
        if not isinstance(reason, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason) is None:
            reason = "submission_failed"
        status = error.status_code
        detail = f"; HTTP {status}" if type(status) is int and 100 <= status <= 599 else ""
        parser.exit(2, f"competition command rejected ({reason}{detail}); check inputs\n")
    except (OSError, ValueError, RuntimeError) as error:
        # Pydantic exceptions can contain complete input payloads. Do not print
        # them into public terminal logs or mistake malformed data for success.
        parser.exit(2, f"competition command rejected ({type(error).__name__}); check inputs\n")
    print(canonical_json_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
