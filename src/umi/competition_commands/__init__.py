"""Explicit command dispatch; handlers own their domain-specific dependencies."""

from argparse import Namespace
from collections.abc import Callable

from ..open_competition import CompetitionPolicy
from . import evidence, host, models, services, store, submissions

CommandHandler = Callable[[Namespace, CompetitionPolicy], dict]

COMMAND_HANDLERS: dict[str, CommandHandler] = {
    "admit": store.admit,
    "assemble-endpoint-execution": evidence.assemble_endpoint_execution,
    "check-endpoint-origin": submissions.check_endpoint_origin,
    "close-round": store.close_round,
    "discover-assignments": submissions.discover_assignments,
    "execution-status": evidence.execution_status,
    "fetch-initial-successor-history": host.fetch_initial_successor_history,
    "fix-evidence-cutoff": store.fix_evidence_cutoff,
    "initialize-baseline": store.initialize_baseline,
    "inspect-host-upgrade": host.inspect_host_upgrade,
    "inspect-policy": evidence.inspect_policy,
    "prepare-endpoint-incumbent": models.prepare_endpoint_incumbent,
    "prepare-execution-record": evidence.propose_execution_result,
    "prepare-settlement-package": evidence.prepare_settlement_package,
    "preserve-bundle": models.verify_bundle,
    "project-weights": store.project_weights,
    "promote": store.promote,
    "propose-execution-result": evidence.propose_execution_result,
    "record-evaluation": store.record_evaluation,
    "record-independent-evaluation": store.record_independent_evaluation,
    "replay-evaluation": evidence.replay_evaluations,
    "replay-independent-evaluation": evidence.replay_evaluations,
    "replay-settlement-package": evidence.replay_settlement_package,
    "retrieve-bundle": models.retrieve_bundle,
    "round-status": store.round_status,
    "run-endpoint-dispatch": services.run_endpoint_dispatch,
    "run-endpoint-incumbent": models.run_model_evaluation,
    "run-evaluator": services.run_evaluator,
    "run-model-evaluation": models.run_model_evaluation,
    "run-offline-case": models.run_offline_case,
    "serve-assignment-feed": services.serve_assignment_feed,
    "serve-evaluator-exchange": services.serve_evaluator_exchange,
    "serve-intake": services.serve_intake,
    "serve-rehearsal": store.serve_rehearsal,
    "serve-round-coordinator": services.serve_round_coordinator,
    "settle-round": store.settle_round,
    "settlement-status": store.settlement_status,
    "sign-assignment-query": submissions.sign_assignment_query,
    "sign-submission": submissions.sign_submission,
    "status": store.status,
    "submit": submissions.submit,
    "verify-bundle": models.verify_bundle,
    "verify-cutoff-publication": evidence.verify_cutoff_publication,
    "verify-settlement-publication": evidence.verify_cutoff_publication,
}
