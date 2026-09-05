#!/usr/bin/env python3
"""Read-only api.umi.vision verification for the SN78 activity cutoff."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import sys
from typing import Any

OBSERVER_HOST = "api.umi.vision"
OBSERVER_PATH = "/api/v1/network"
OBSERVER_URL = f"https://{OBSERVER_HOST}{OBSERVER_PATH}"
MAX_RESPONSE_BYTES = 1_048_576
EXPECTED_NETUID = 78
EXPECTED_MECHANISM_ID = 0
EXPECTED_TEMPO_BLOCKS = "360"
EXPECTED_ACTIVITY_CUTOFF_BLOCKS = "360"
RESULT_SCHEMA = "umi-owner-cutoff-verification/1"
_BLOCK_HASH = re.compile(r"0x[0-9a-f]{64}\Z")
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z"
)


class VerificationError(ValueError):
    """A bounded public reason for rejecting an observer response."""

    def __init__(
        self,
        reason_code: str,
        *,
        expected: str | int | bool | None = None,
        actual: str | int | bool | None = None,
    ) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.expected = expected
        self.actual = actual


def _reject_constant(value: str) -> None:
    raise VerificationError("observer_json_nonfinite_number", actual=value)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("observer_json_duplicate_key", actual=key)
        result[key] = value
    return result


def _parse_integer(value: str) -> int:
    if len(value) > 20:
        raise VerificationError("observer_json_integer_out_of_range")
    return int(value, 10)


def decode_document(encoded: bytes) -> dict[str, Any]:
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise VerificationError(
            "observer_response_too_large",
            expected=MAX_RESPONSE_BYTES,
            actual=len(encoded),
        )
    try:
        text = encoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise VerificationError("observer_response_invalid_utf8") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_integer,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VerificationError("observer_response_invalid_json") from exc
    if not isinstance(document, dict):
        raise VerificationError("observer_response_not_object")
    return document


def _expect_equal(
    actual: Any,
    expected: str | int | bool,
    reason_code: str,
) -> None:
    if actual != expected:
        bounded_actual = (
            actual
            if isinstance(actual, (int, bool))
            or (isinstance(actual, str) and len(actual) <= 128)
            else None
        )
        raise VerificationError(reason_code, expected=expected, actual=bounded_actual)


def verify_document(document: dict[str, Any]) -> dict[str, Any]:
    _expect_equal(document.get("schema"), "umi-observer-network/1", "observer_schema_mismatch")
    _expect_equal(document.get("freshness"), "fresh", "observer_snapshot_not_fresh")

    protocol_state = document.get("protocol_state")
    if not isinstance(protocol_state, dict):
        raise VerificationError("observer_protocol_state_missing")
    _expect_equal(protocol_state.get("netuid"), EXPECTED_NETUID, "observer_netuid_mismatch")
    _expect_equal(
        protocol_state.get("mechanism_id"),
        EXPECTED_MECHANISM_ID,
        "observer_mechanism_mismatch",
    )
    _expect_equal(
        protocol_state.get("chain_identity_matches_expected"),
        True,
        "observer_chain_identity_mismatch",
    )

    sources = document.get("sources")
    if not isinstance(sources, list):
        raise VerificationError("observer_sources_missing")
    finalized_sources = [
        source
        for source in sources
        if isinstance(source, dict) and source.get("source_kind") == "chain_finalized"
    ]
    if len(finalized_sources) != 1:
        raise VerificationError(
            "observer_finalized_source_count_mismatch",
            expected=1,
            actual=len(finalized_sources),
        )
    finalized_source = finalized_sources[0]
    _expect_equal(
        finalized_source.get("verification_status"),
        "finalized_read",
        "observer_source_verification_mismatch",
    )
    block = finalized_source.get("block")
    if not isinstance(block, dict):
        raise VerificationError("observer_finalized_block_missing")
    _expect_equal(block.get("finalized"), True, "observer_block_not_finalized")
    block_number = block.get("number")
    block_hash = block.get("hash")
    block_timestamp = block.get("timestamp")
    if (
        not isinstance(block_number, str)
        or len(block_number) > 20
        or not block_number.isdecimal()
    ):
        raise VerificationError("observer_block_number_invalid")
    if not isinstance(block_hash, str) or _BLOCK_HASH.fullmatch(block_hash) is None:
        raise VerificationError("observer_block_hash_invalid")
    if not isinstance(block_timestamp, str) or _UTC_TIMESTAMP.fullmatch(block_timestamp) is None:
        raise VerificationError("observer_block_timestamp_invalid")

    network = document.get("network")
    if not isinstance(network, dict):
        raise VerificationError("observer_network_missing")
    _expect_equal(network.get("netuid"), EXPECTED_NETUID, "network_netuid_mismatch")
    _expect_equal(
        network.get("mechanism_id"),
        EXPECTED_MECHANISM_ID,
        "network_mechanism_mismatch",
    )
    epoch = network.get("epoch")
    hyperparameters = network.get("hyperparameters")
    if not isinstance(epoch, dict):
        raise VerificationError("observer_epoch_missing")
    if not isinstance(hyperparameters, dict):
        raise VerificationError("observer_hyperparameters_missing")
    _expect_equal(
        epoch.get("tempo_blocks"),
        EXPECTED_TEMPO_BLOCKS,
        "tempo_blocks_mismatch",
    )
    _expect_equal(
        hyperparameters.get("activity_cutoff_blocks"),
        EXPECTED_ACTIVITY_CUTOFF_BLOCKS,
        "activity_cutoff_blocks_mismatch",
    )

    generated_at = document.get("generated_at")
    if not isinstance(generated_at, str) or _UTC_TIMESTAMP.fullmatch(generated_at) is None:
        raise VerificationError("observer_generated_at_invalid")
    storage_proofs_verified = block.get("storage_proofs_verified")
    if not isinstance(storage_proofs_verified, bool):
        raise VerificationError("observer_storage_proof_status_invalid")

    return {
        "activity_cutoff_blocks": EXPECTED_ACTIVITY_CUTOFF_BLOCKS,
        "finalized_block": {
            "hash": block_hash,
            "number": block_number,
            "storage_proofs_verified": storage_proofs_verified,
            "timestamp": block_timestamp,
        },
        "generated_at": generated_at,
        "netuid": EXPECTED_NETUID,
        "observer_url": OBSERVER_URL,
        "schema": RESULT_SCHEMA,
        "state_mutated": False,
        "status": "passed",
        "tempo_blocks": EXPECTED_TEMPO_BLOCKS,
    }


def fetch_live_document() -> dict[str, Any]:
    connection = http.client.HTTPSConnection(
        OBSERVER_HOST,
        timeout=15,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "GET",
            OBSERVER_PATH,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "umi-owner-cutoff-verifier/1",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise VerificationError("observer_http_status", expected=200, actual=response.status)
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        _expect_equal(content_type, "application/json", "observer_content_type_mismatch")
        content_encoding = response.getheader("Content-Encoding")
        if content_encoding not in {None, "", "identity"}:
            raise VerificationError(
                "observer_content_encoding_unsupported",
                actual=content_encoding,
            )
        declared_length = response.getheader("Content-Length")
        if declared_length is not None:
            try:
                length = int(declared_length, 10)
            except ValueError as exc:
                raise VerificationError("observer_content_length_invalid") from exc
            if length < 0 or length > MAX_RESPONSE_BYTES:
                raise VerificationError(
                    "observer_response_too_large",
                    expected=MAX_RESPONSE_BYTES,
                    actual=length,
                )
        encoded = response.read(MAX_RESPONSE_BYTES + 1)
    finally:
        connection.close()
    return decode_document(encoded)


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Verify the finalized SN78 activity cutoff through api.umi.vision."
    )


def _write_result(stream: Any, document: dict[str, Any]) -> None:
    stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")


def main(argv: list[str] | None = None) -> int:
    _parser().parse_args(argv)
    try:
        document = fetch_live_document()
        result = verify_document(document)
    except (OSError, ssl.SSLError, http.client.HTTPException):
        failure = {
            "reason_code": "observer_read_failed",
            "schema": RESULT_SCHEMA,
            "state_mutated": False,
            "status": "failed",
        }
        _write_result(sys.stderr, failure)
        return 1
    except VerificationError as exc:
        failure = {
            "reason_code": exc.reason_code,
            "schema": RESULT_SCHEMA,
            "state_mutated": False,
            "status": "failed",
        }
        if exc.expected is not None:
            failure["expected"] = exc.expected
        if exc.actual is not None:
            failure["actual"] = exc.actual
        _write_result(sys.stderr, failure)
        return 1
    _write_result(sys.stdout, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
