from __future__ import annotations

import importlib.util
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


def _load_verifier() -> ModuleType:
    path = (
        Path(__file__).parents[1] / "deploy" / "first-public-result" / "owner-cutoff" / "verify.py"
    )
    spec = importlib.util.spec_from_file_location("owner_cutoff_verify", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load owner cutoff verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = _load_verifier()


def _document(*, cutoff: str = "360", tempo: str = "360") -> dict[str, object]:
    block = {
        "finalized": True,
        "hash": "0x" + "12" * 32,
        "number": "8999000",
        "state_root": "0x" + "34" * 32,
        "storage_proofs_verified": False,
        "timestamp": "2026-09-05T03:00:00Z",
    }
    return {
        "freshness": "fresh",
        "generated_at": "2026-09-05T03:00:20Z",
        "network": {
            "epoch": {"tempo_blocks": tempo},
            "hyperparameters": {"activity_cutoff_blocks": cutoff},
            "mechanism_id": 0,
            "netuid": 78,
        },
        "protocol_state": {
            "chain_identity_matches_expected": True,
            "mechanism_id": 0,
            "netuid": 78,
        },
        "schema": "umi-observer-network/1",
        "sources": [
            {
                "block": block,
                "source_kind": "chain_finalized",
                "verification_status": "finalized_read",
            }
        ],
    }


class OwnerCutoffVerifierTests(unittest.TestCase):
    def test_accepts_exact_finalized_cutoff(self) -> None:
        result = VERIFY.verify_document(_document())
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["activity_cutoff_blocks"], "360")
        self.assertFalse(result["state_mutated"])
        self.assertEqual(result["finalized_block"]["number"], "8999000")

    def test_rejects_old_cutoff(self) -> None:
        with self.assertRaises(VERIFY.VerificationError) as raised:
            VERIFY.verify_document(_document(cutoff="5000"))
        self.assertEqual(raised.exception.reason_code, "activity_cutoff_blocks_mismatch")
        self.assertEqual(raised.exception.expected, "360")
        self.assertEqual(raised.exception.actual, "5000")

    def test_rejects_wrong_tempo(self) -> None:
        with self.assertRaises(VERIFY.VerificationError) as raised:
            VERIFY.verify_document(_document(tempo="361"))
        self.assertEqual(raised.exception.reason_code, "tempo_blocks_mismatch")

    def test_rejects_nonfinalized_source(self) -> None:
        document = _document()
        document["sources"][0]["block"]["finalized"] = False
        with self.assertRaises(VERIFY.VerificationError) as raised:
            VERIFY.verify_document(document)
        self.assertEqual(raised.exception.reason_code, "observer_block_not_finalized")

    def test_decoder_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(VERIFY.VerificationError) as raised:
            VERIFY.decode_document(b'{"schema":"one","schema":"two"}')
        self.assertEqual(raised.exception.reason_code, "observer_json_duplicate_key")

    def test_decoder_rejects_oversized_response(self) -> None:
        oversized = b"{" + b" " * VERIFY.MAX_RESPONSE_BYTES + b"}"
        with self.assertRaises(VERIFY.VerificationError) as raised:
            VERIFY.decode_document(oversized)
        self.assertEqual(raised.exception.reason_code, "observer_response_too_large")

    def test_main_emits_bounded_failure(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(VERIFY, "fetch_live_document", return_value=_document(cutoff="5000")),
            redirect_stderr(stderr),
        ):
            self.assertEqual(VERIFY.main([]), 1)
        self.assertEqual(
            stderr.getvalue(),
            '{"actual":"5000","expected":"360",'
            '"reason_code":"activity_cutoff_blocks_mismatch",'
            '"schema":"umi-owner-cutoff-verification/1",'
            '"state_mutated":false,"status":"failed"}\n',
        )
