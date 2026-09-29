"""Service-query failures must never fabricate failed-service observations."""

import asyncio
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from heartbeat import heartbeat, read_journal, standing_progress


class HeartbeatTests(unittest.TestCase):
    @patch("heartbeat.subprocess.run")
    def test_systemd_permission_failure_is_not_a_service_failure(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, "", "bus unavailable")
        with self.assertRaisesRegex(RuntimeError, "service_status_unavailable"):
            heartbeat(["vali.service"])

    @patch("heartbeat.subprocess.run")
    def test_running_and_failed_services_are_distinguished(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, "ActiveState=active\nSubState=running\n", ""),
            subprocess.CompletedProcess([], 0, "ActiveState=failed\nSubState=failed\n", ""),
        ]
        self.assertEqual(
            heartbeat(["first.service", "second.service"])["services"],
            {"first.service": "running", "second.service": "failed"},
        )

    @patch("heartbeat.subprocess.run", side_effect=subprocess.TimeoutExpired("systemctl", 5))
    def test_query_timeout_does_not_refresh_the_heartbeat(self, run):
        with self.assertRaisesRegex(RuntimeError, "service_status_unavailable"):
            heartbeat(["vali.service"])

    @patch("heartbeat.read_journal")
    def test_native_observation_exports_only_chain_counters(self, read):
        read.return_value = json.dumps(
            {
                "MESSAGE": json.dumps(
                    {
                        "schema": "umi-standing-chain-observation/1",
                        "block_number": 900,
                        "weight_update_block": 850,
                        "extraneous": "private must not leave host",
                    }
                )
            }
        )
        self.assertEqual(
            standing_progress("vali.service"),
            {
                "vali.service/finalized_block": 900,
                "vali.service/weight_update_block": 850,
            },
        )

    @patch("heartbeat.read_journal")
    def test_missing_or_invalid_native_observation_is_explicitly_missing(self, read):
        for output in [
            "",
            "not json",
            "[]",
            json.dumps({"MESSAGE": "[]"}),
            json.dumps(
                {
                    "MESSAGE": json.dumps(
                        {
                            "schema": "umi-standing-chain-observation/1",
                            "block_number": 20,
                            "weight_update_block": 21,
                        }
                    )
                }
            ),
        ]:
            read.return_value = output
            self.assertEqual(set(standing_progress("vali.service").values()), {None})
        read.side_effect = PermissionError("private text")
        self.assertEqual(set(standing_progress("vali.service").values()), {None})

    @patch("heartbeat.subprocess.run")
    @patch("heartbeat.read_journal")
    def test_running_service_without_progress_does_not_claim_native_health(self, read, run):
        read.return_value = ""
        run.return_value = subprocess.CompletedProcess(
            [], 0, "ActiveState=active\nSubState=running\n", ""
        )
        result = heartbeat(["vali.service"], ["vali.service"])
        self.assertEqual(result["schema"], "umi-service-heartbeat/2")
        self.assertEqual(result["services"]["vali.service"], "running")
        self.assertEqual(set(result["progress"].values()), {None})


class JournalProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_oversized_journal_is_killed_and_reaped(self):
        create = asyncio.create_subprocess_exec
        children = []

        async def large_output(*args, **kwargs):
            child = await create(
                sys.executable, "-c", "import sys; sys.stdout.write('x' * 500000)", **kwargs
            )
            children.append(child)
            return child

        with (
            patch("heartbeat.asyncio.create_subprocess_exec", side_effect=large_output),
            self.assertRaisesRegex(ValueError, "too_large"),
        ):
            await asyncio.wait_for(read_journal("vali.service"), timeout=10)
        self.assertIsNotNone(children[0].returncode)


if __name__ == "__main__":
    unittest.main()
