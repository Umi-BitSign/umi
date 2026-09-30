"""Allowlisted normalization of the separately published provisional C3 asset."""

from __future__ import annotations


def normalize_public_results(value: dict) -> dict:
    if value.get("schema") != "umi-cohort3-provisional-results/1":
        return value
    top = {
        "schema",
        "cohort",
        "round_sha256",
        "policy_sha256",
        "settlement_sha256",
        "generated_at",
        "historical_score_replay_block",
        "round_valid_through_block",
        "status",
        "certification_status",
        "provisional",
        "settlement_certified",
        "rewards_status",
        "chain_submission_authorized",
        "publication_scope",
        "score_semantics",
        "scoring_environment",
        "scoring_runtime_verified",
        "counts",
        "results",
    }
    if set(value) != top or (
        value["cohort"] != 3
        or value["status"] != "closed_uncertified"
        or value["certification_status"] != "deadline_missed"
        or value["provisional"] is not True
        or value["settlement_certified"] is not False
        or value["rewards_status"] != "not_activated"
        or value["chain_submission_authorized"] is not False
        or value["scoring_runtime_verified"] is not True
    ):
        raise ValueError("unsupported provisional artifact metadata")
    environment = value["scoring_environment"]
    if (
        not isinstance(environment, dict)
        or set(environment)
        != {
            "schema",
            "bittensor_distribution_version",
            "python_implementation",
            "python_version",
            "regex_distribution_version",
            "scoring_source_sha256",
            "unicode_data_version",
        }
        or environment["schema"] != "umi-component-scoring-environment/1"
    ):
        raise ValueError("unsupported provisional scoring environment")
    common = {
        "submission_sha256",
        "hotkey",
        "uid_at_settlement",
        "track",
        "outcome",
        "score_rank",
        "first_observed_block",
        "candidate_score",
        "candidate_stratum_scores",
        "incumbent_score",
        "incumbent_stratum_scores",
    }
    items = []
    for row in value["results"]:
        scored = row["outcome"] == "scored"
        expected = common | (
            {
                "result_sha256",
                "independent_evidence_sha256",
                "total_cases",
                "candidate_case_status_counts",
            }
            if scored
            else {"void_decision_sha256", "void_evidence_sha256", "reason"}
        )
        if set(row) != expected or row["outcome"] not in {"scored", "void"}:
            raise ValueError("unsupported provisional result fields")
        if not scored and (
            row["reason"] != "infrastructure_failure"
            or any(
                row[name] is not None
                for name in (
                    "candidate_score",
                    "candidate_stratum_scores",
                    "incumbent_score",
                    "incumbent_stratum_scores",
                    "score_rank",
                )
            )
        ):
            raise ValueError("provisional void must not have scores")
        items.append(
            {
                "submission_sha256": row["submission_sha256"],
                "hotkey": row["hotkey"],
                "uid": row["uid_at_settlement"],
                "track": row["track"],
                "status": row["outcome"],
                "result_sha256": row.get("result_sha256"),
                "independent_evidence_sha256": row.get("independent_evidence_sha256"),
                "void_decision_sha256": row.get("void_decision_sha256"),
                "void_evidence_sha256": row.get("void_evidence_sha256"),
                "first_observed_block": row["first_observed_block"],
                "score_rank": row["score_rank"],
                "candidate": (
                    {
                        "aggregate": row["candidate_score"],
                        "by_stratum": row["candidate_stratum_scores"],
                    }
                    if scored
                    else None
                ),
                "incumbent": (
                    {
                        "aggregate": row["incumbent_score"],
                        "by_stratum": row["incumbent_stratum_scores"],
                    }
                    if scored
                    else None
                ),
            }
        )
    scored_count = sum(item["status"] == "scored" for item in items)
    if value["counts"] != {
        "miners": len(items),
        "scored": scored_count,
        "void": len(items) - scored_count,
    }:
        raise ValueError("provisional artifact counts differ")
    return {
        "schema": "umi-competition-public-results/1",
        "round_sha256": value["round_sha256"],
        "policy_sha256": value["policy_sha256"],
        "settlement_sha256": value["settlement_sha256"],
        "observed_block": value["historical_score_replay_block"],
        "scoring_method": "native_replay_evaluation_at_settlement_observed_block",
        "provisional": True,
        "certified": False,
        "rewards_active": False,
        "chain_submission_authorized": False,
        "items": sorted(items, key=lambda item: item["submission_sha256"]),
    }
