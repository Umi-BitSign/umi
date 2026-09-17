"""Public argument contract for the umi-competition command."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local successor rehearsal commands. No command can submit chain weights."
    )
    parser.add_argument("--policy", required=True, help="reviewed successor policy JSON")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inspect-policy")
    intake = commands.add_parser("serve-intake")
    intake.add_argument("--config", required=True)
    rounds = commands.add_parser("serve-round-coordinator")
    rounds.add_argument("--config", required=True)
    rounds.add_argument("--legacy-policy")
    submit = commands.add_parser("submit")
    submit.add_argument("--submission", required=True)
    submit.add_argument("--origin", required=True)
    origin = commands.add_parser("check-endpoint-origin")
    origin.add_argument("--submission", required=True)
    origin.add_argument("--chain-config", required=True)
    dispatch = commands.add_parser("run-endpoint-dispatch")
    dispatch.add_argument("--config", required=True)
    dispatch.add_argument("--legacy-policy", required=True)
    dispatch.add_argument("--once", action="store_true")
    evaluator = commands.add_parser("run-evaluator")
    evaluator.add_argument("--config", required=True)
    evaluator.add_argument("--legacy-policy")
    evaluator.add_argument("--once", action="store_true")
    exchange = commands.add_parser("serve-evaluator-exchange")
    exchange.add_argument("--config", required=True)
    exchange.add_argument("--legacy-policy")
    feed = commands.add_parser("serve-assignment-feed")
    for name in ("legacy-policy", "state", "nonce-path"):
        feed.add_argument("--" + name, required=True)
    feed.add_argument("--port", type=int, default=8099)
    feed_sign = commands.add_parser("sign-assignment-query")
    for name in ("query", "wallet-name", "hotkey-name", "wallet-path"):
        feed_sign.add_argument("--" + name, required=True)
    discover = commands.add_parser("discover-assignments")
    for name in ("origin", "legacy-policy", "wallet-name", "hotkey-name", "wallet-path"):
        discover.add_argument("--" + name, required=True)
    discover.add_argument("--publication")
    discover.add_argument("--after")
    discover.add_argument("--limit", type=int, default=20)
    inspection = commands.add_parser("inspect-host-upgrade")
    for name in ("config", "accepted-directive", "expected-hotkey"):
        inspection.add_argument("--" + name, required=True)
    inspection.add_argument(
        "--expected-platform", choices=("linux/amd64", "linux/arm64"), required=True
    )
    inspection.add_argument("--service-uid", type=int, required=True)
    inspection.add_argument("--staged-directory")
    initial_history = commands.add_parser("fetch-initial-successor-history")
    for name in ("config", "accepted-directive", "consent", "output"):
        initial_history.add_argument("--" + name, required=True)
    initial_history.add_argument("--current-block", type=int, required=True)
    initial_history.add_argument("--timeout-seconds", type=int, default=300)
    for name in ("verify-cutoff-publication", "verify-settlement-publication"):
        certificate = commands.add_parser(name)
        for param in ("certificate", "roster", "replay-limits"):
            certificate.add_argument("--" + param, required=True)
        if name == "verify-settlement-publication":
            for param in ("cutoff-certificate", "evidence", "retained-settlement"):
                certificate.add_argument("--" + param, required=True)
    prepare_package = commands.add_parser("prepare-settlement-package")
    for name in (
        "cutoff-certificate",
        "certificate",
        "retained-settlement",
        "roster",
        "evidence",
        "replay-limits",
        "release-identity",
        "package-limits",
        "destination",
    ):
        prepare_package.add_argument("--" + name, required=True)
    replay_package = commands.add_parser("replay-settlement-package")
    for name in (
        "package",
        "expected-package-sha256",
        "release-identity",
        "package-limits",
        "worker-capacity",
        "state",
    ):
        replay_package.add_argument("--" + name, required=True)
    offline = commands.add_parser("run-offline-case")
    for name in ("runtime", "manifest", "archive", "video", "case-id", "video-sha256"):
        offline.add_argument("--" + name, required=True)
    for command in ("run-model-evaluation", "run-endpoint-incumbent"):
        model_run = commands.add_parser(command)
        for name in ("job", "chain-config", "archive", "videos", "state"):
            model_run.add_argument("--" + name, required=True)
        model_run.add_argument("--maximum-jobs", type=int, default=1024)
        model_run.add_argument("--maximum-evidence-bytes", type=int, default=1024**3)
    endpoint_job = commands.add_parser("prepare-endpoint-incumbent")
    for name in (
        "publication",
        "submission-sha256",
        "incumbent",
        "runtime",
        "evaluator-hotkey",
        "legacy-policy",
    ):
        endpoint_job.add_argument("--" + name, required=True)
    endpoint_pair = commands.add_parser("assemble-endpoint-execution")
    for name in (
        "incumbent-execution",
        "dispatch-state",
        "publication-sha256",
        "legacy-policy",
        "suite",
        "reveal-pulses",
    ):
        endpoint_pair.add_argument("--" + name, required=True)
    endpoint_pair.add_argument("--current-block", type=int, required=True)
    execution_status = commands.add_parser("execution-status")
    execution_status.add_argument("--state", required=True)
    execution_status.add_argument("--execution-key", required=True)
    for name in ("propose-execution-result", "prepare-execution-record"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--suite", required=True)
        cmd.add_argument("--current-block", type=int, required=True)
        if name == "propose-execution-result":
            cmd.add_argument("--inputs", required=True)
        else:
            cmd.add_argument("--execution", required=True)
            cmd.add_argument("--result", required=True)
    for name in ("verify-bundle", "preserve-bundle"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--manifest", required=True)
        cmd.add_argument("--source", required=True)
        if name == "preserve-bundle":
            cmd.add_argument("--archive", required=True)
    retrieval = commands.add_parser("retrieve-bundle")
    for name in ("submission", "source-base-url", "archive"):
        retrieval.add_argument("--" + name, required=True)
    for name in ("maximum-files", "maximum-file-bytes", "maximum-total-bytes"):
        retrieval.add_argument("--" + name, required=True, type=int)
    for name in ("request-timeout-seconds", "total-download-timeout-seconds"):
        retrieval.add_argument("--" + name, required=True, type=float)
    sign = commands.add_parser("sign-submission")
    sign.add_argument("--submission", required=True)
    sign.add_argument("--wallet-name", required=True)
    sign.add_argument("--hotkey-name", required=True)
    sign.add_argument("--wallet-path", required=True)
    for name in (
        "status",
        "admit",
        "initialize-baseline",
        "close-round",
        "promote",
        "project-weights",
        "record-evaluation",
        "record-independent-evaluation",
        "fix-evidence-cutoff",
        "settle-round",
        "settlement-status",
        "round-status",
        "serve-rehearsal",
    ):
        cmd = commands.add_parser(name)
        cmd.add_argument("--state", required=True)
        cmd.add_argument(
            "--public-launch",
            help="canonical public launch identity JSON for a launch-bound intake store",
        )
        cmd.add_argument(
            "--submission-head-checkpoint-directory",
            help="external submission checkpoint directory required by a migrated intake store",
        )
        if name in {
            "status",
            "initialize-baseline",
            "promote",
            "record-evaluation",
            "record-independent-evaluation",
            "round-status",
        }:
            cmd.add_argument(
                "--evaluator-review-limits",
                help="use an evaluator-only receipt store with these replay limits",
            )
        if name in {"admit", "promote", "project-weights", "serve-rehearsal", "settle-round"}:
            cmd.add_argument("--snapshot", required=True)
        if name in {"admit", "promote", "record-evaluation", "record-independent-evaluation"}:
            cmd.add_argument("--submission", required=True)
        if name in {
            "promote",
            "close-round",
            "record-evaluation",
            "record-independent-evaluation",
            "fix-evidence-cutoff",
        }:
            cmd.add_argument("--round", required=True)
        if name in {"close-round", "promote", "project-weights", "admit", "settle-round"}:
            cmd.add_argument("--current-block", required=True, type=int)
        if name in {"initialize-baseline", "promote"}:
            cmd.add_argument("--archive", required=True)
        if name == "initialize-baseline":
            cmd.add_argument("--manifest", required=True)
        if name in {"promote", "record-evaluation", "record-independent-evaluation"}:
            cmd.add_argument("--evaluation", required=True)
            cmd.add_argument("--suite", required=True)
        if name in {"record-evaluation", "record-independent-evaluation", "fix-evidence-cutoff"}:
            cmd.add_argument("--observed-block", required=True, type=int)
        if name in {"round-status", "settlement-status"}:
            cmd.add_argument("--round-sha256", required=True)
        if name == "promote":
            cmd.add_argument("--review", required=True)
        if name in {"project-weights", "settle-round"}:
            cmd.add_argument("--inputs", required=True)
        if name == "fix-evidence-cutoff":
            cmd.add_argument("--schedule", required=True)
        if name == "serve-rehearsal":
            cmd.add_argument("--port", type=int, default=8098)
    for name in ("replay-evaluation", "replay-independent-evaluation"):
        replay = commands.add_parser(name)
        for argument in ("submission", "evaluation", "round", "suite"):
            replay.add_argument("--" + argument, required=True)
        replay.add_argument("--current-block", type=int, required=True)
    return parser
