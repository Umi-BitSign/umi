"""Generate the candidate source guard; qualify compatibility before release.

Keep the ABI only for tested compatible changes. Advance it when accepted native
semantics change. Updating this manifest does not itself establish compatibility.
"""

import argparse
import ast
import hashlib
import importlib.metadata as metadata
import json
import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1] / "src" / "umi"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--candidate-external-versions",
    action="store_true",
    help="Include this environment's external versions as candidates for explicit qualification",
)
arguments = parser.parse_args()
seeds = [
    "competition_verification_reuse",
    "competition_cohort_request_closure",
    "competition_cohort_service_closure",
    "competition_cohort_request_terminal",
    "competition_cohort_service_terminal",
    "competition_cohort_endpoint_archive",
    "competition_cohort_service_quality",
    "competition_cohort_endpoint_quality",
    "competition_verification_snapshot",
    "competition_cohort_settlement",
    "competition_cohort_settlement_service",
    "competition_reward_preparation",
    # Signed reward-adoption handoff candidates select every native consumer,
    # including package delivery, before any held reward row can be released.
    "competition_reward_adoption_handoff",
    "competition_reward_adoption_delivery",
    "competition_reward_exchange_delivery",
    "competition_reward_hold_mirror_cli",
    "competition_reward_transition_signing",
    "competition_reward_coordinator",
    "competition_reward_admission_runner",
    "competition_reward_history_origin_cli",
    # Supported recovery and isolated selection entrypoints consume persisted
    # native results without necessarily being imported by the standing owner.
    "competition_reward_cutover_cli",
    "competition_reward_timing_review",
    "competition_reward_history_preparation_cli",
    "competition_reward_history_preparation_capacity_cli",
    "competition_reward_writer_broker_cli",
    "competition_reward_writer_broker_worker",
    "competition_reward_writer_review_cli",
    # Independent acceptance observers select authenticated effective profiles
    # without changing the original signed standing manifest.
    "competition_reward_runtime_review",
    "competition_reward_history_transfer_cli",
    "competition_package_reuse_cli",
    "historical_header_hint_import_cli",
    "competition_model_source_verification",
    "competition_cohort_model_client",
    "competition_cohort_direct_model_client",
    # Retained legacy retries consume native acceptance and durable byte facts
    # through the direct owner, including after local payload reclamation.
    "competition_cohort_model_upload_delivery",
    "competition_cohort_direct_model_owner",
    # Lifecycle publication owns durable native replay outside the intake fence.
    "competition_cohort_request_publication",
    # These independent consumers select the private byte-verification owner
    # and authenticated imports without being imported by the native replay.
    "competition_cohort_lifecycle_host",
    "competition_cohort_model_delivery_candidate",
    "competition_cohort_review_config",
    "competition_cohort_service_host",
    "competition_model_byte_store_cli",
    "competition_miner_transition_cli",
]
modules = set()
external_imports = set()
pending = list(seeds)
while pending:
    name = pending.pop()
    path = ROOT / (name + ".py")
    if name in modules or not path.is_file():
        continue
    modules.add(name)
    for node in ast.walk(ast.parse(path.read_bytes())):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
            pending.append(node.module.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            external_imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            external_imports.update(alias.name.split(".")[0] for alias in node.names)
distributions = metadata.packages_distributions()
pending_external = []
for name in sorted(external_imports - sys.stdlib_module_names - {"umi"}):
    if name not in distributions:
        raise SystemExit("No installed distribution for native external import: " + name)
    pending_external.extend(distributions[name])
current_external = {}
while pending_external:
    name = canonicalize_name(pending_external.pop())
    if name in current_external:
        continue
    current_external[name] = metadata.version(name)
    for declaration in metadata.requires(name) or ():
        requirement = Requirement(declaration)
        if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
            pending_external.append(requirement.name)
manifest_path = ROOT / "competition_verification_rules.json"
prior = json.loads(manifest_path.read_bytes()) if manifest_path.exists() else {}
external_versions = prior.get("external_distributions", {})
for name, version in sorted(current_external.items()):
    qualified = external_versions.get(name, [])
    if version not in qualified:
        if not arguments.candidate_external_versions:
            raise SystemExit(
                f"Unqualified native dependency {name}=={version}; use "
                "--candidate-external-versions and qualify compatibility before release"
            )
        external_versions[name] = sorted({*qualified, version})
body = {
    "schema": "umi-native-verification-dependencies/1",
    "abi": "umi-native-request-verification/1",
    "extensions": {
        "archived_execution_shared_incumbent_v2": "umi-native-shared-incumbent/2",
        "shared_incumbent_source_terminal_v2": "umi-native-shared-incumbent/2",
        "shared_incumbent_source_participant_v2": "umi-native-shared-incumbent/2",
    },
    "compatibility_basis": (
        "Native signed closure, endpoint ancestry/content, execution, paid-work, restart, "
        "interruption and reward lifecycle fixture parity; source manifest alone does not "
        "establish certification. Update only after qualification; advance ABI when "
        "accepted semantics change."
    ),
    "sources": {
        n + ".py": hashlib.sha256((ROOT / (n + ".py")).read_bytes()).hexdigest()
        for n in sorted(modules)
    },
    "external_distributions": dict(sorted(external_versions.items())),
}
manifest_path.write_text(json.dumps(body, indent=2) + "\n")
print("guarded local sources", len(modules), "external distributions", len(external_versions))
