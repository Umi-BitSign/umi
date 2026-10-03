"""Service-query failures must never fabricate failed-service observations."""

import asyncio
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from heartbeat import heartbeat, read_journal, standing_progress, successor_healthy


class HeartbeatTests(unittest.TestCase):
    systemd_running = (
        "ActiveState=active\nSubState=running\n"
        "InvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
    )

    @patch("heartbeat.subprocess.run")
    def test_systemd_permission_failure_is_not_a_service_failure(self, run):
        run.return_value = subprocess.CompletedProcess([], 1, "", "bus unavailable")
        with self.assertRaisesRegex(RuntimeError, "service_status_unavailable"):
            heartbeat(["vali.service"])

    @patch("heartbeat.subprocess.run")
    def test_running_and_failed_services_are_distinguished(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, self.systemd_running, ""),
            subprocess.CompletedProcess(
                [], 0,
                "ActiveState=failed\nSubState=failed\n"
                "InvocationID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                "",
            ),
        ]
        self.assertEqual(
            heartbeat(["first.service", "second.service"])["services"],
            {"first.service": "running", "second.service": "failed"},
        )

    @patch("heartbeat.shutil.disk_usage")
    @patch("heartbeat.subprocess.run")
    def test_storage_heartbeat_exports_only_named_available_bytes(self, run, disk_usage):
        run.return_value = subprocess.CompletedProcess([], 0, self.systemd_running, "")
        disk_usage.return_value = SimpleNamespace(free=12 * 1024**3)
        result = heartbeat(
            ["vali.service"],
            storage_paths={"coordinator-root/available_bytes": "/"},
        )
        self.assertEqual(result["schema"], "umi-service-heartbeat/3")
        self.assertEqual(
            result["resources"],
            {"coordinator-root/available_bytes": 12 * 1024**3},
        )
        disk_usage.assert_called_once_with(Path("/"))

    @patch("heartbeat.subprocess.run")
    def test_invalid_or_unavailable_storage_does_not_refresh_heartbeat(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, self.systemd_running, "")
        for paths in (
            [],
            {"bad": "/"},
            {"root/available_bytes": "relative"},
            {f"disk-{n}/available_bytes": "/" for n in range(11)},
        ):
            with self.assertRaises((ValueError, RuntimeError)):
                heartbeat(["vali.service"], storage_paths=paths)
        with self.assertRaisesRegex(RuntimeError, "storage_status_unavailable"):
            heartbeat(
                ["vali.service"],
                storage_paths={"missing/available_bytes": "/definitely/missing"},
            )

    @patch("heartbeat.subprocess.run")
    def test_storage_path_rejects_symlinked_parent(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, self.systemd_running, "")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "storage_status_unavailable"):
                heartbeat(
                    ["vali.service"],
                    storage_paths={"scratch/available_bytes": str(alias)},
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
            [], 0, self.systemd_running, ""
        )
        result = heartbeat(["vali.service"], ["vali.service"])
        self.assertEqual(result["schema"], "umi-service-heartbeat/2")
        self.assertEqual(result["services"]["vali.service"], "running")
        self.assertEqual(set(result["progress"].values()), {None})

    @patch("heartbeat.read_successor_journal")
    def test_successor_health_uses_only_latest_bounded_status(self, read):
        read.return_value = "\n".join(
            [
                json.dumps(
                    {
                        "MESSAGE": json.dumps(
                            {
                                "schema": "umi-successor-host-status/1",
                                "status": "holding",
                                "reason": "successor_reconcile_failed",
                            }
                        ),
                        "_SYSTEMD_INVOCATION_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    }
                ),
                json.dumps(
                    {
                        "MESSAGE": json.dumps(
                            {
                                "schema": "umi-successor-host-status/1",
                                "status": "worker_healthy",
                                "extraneous": "private must not leave host",
                            }
                        ),
                        "_SYSTEMD_INVOCATION_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    }
                ),
            ]
        )
        self.assertFalse(
            successor_healthy("vali.service", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        )
        read.return_value = json.dumps(
            {
                "MESSAGE": json.dumps(
                    {
                        "schema": "umi-successor-host-status/1",
                        "status": "worker_healthy",
                        "extraneous": "private must not leave host",
                    }
                ),
                "_SYSTEMD_INVOCATION_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }
        )
        self.assertTrue(
            successor_healthy("vali.service", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        )
        for status, reason in (
            ("started", "successor_worker_started"),
            ("healthy", "successor_worker_healthy"),
        ):
            read.return_value = json.dumps(
                {
                    "MESSAGE": json.dumps(
                        {
                            "schema": "umi-successor-host-status/1",
                            "status": status,
                            "reason": reason,
                        }
                    ),
                    "_SYSTEMD_INVOCATION_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                }
            )
            self.assertTrue(
                successor_healthy(
                    "vali.service", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
            )
        read.return_value = json.dumps(
            {
                "MESSAGE": json.dumps(
                    {
                        "schema": "umi-successor-host-status/1",
                        "status": "started",
                        "reason": "successor_reconcile_failed",
                    }
                ),
                "_SYSTEMD_INVOCATION_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }
        )
        self.assertFalse(
            successor_healthy("vali.service", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        )
        self.assertFalse(
            successor_healthy("vali.service", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        )

    @patch("heartbeat.subprocess.run")
    @patch("heartbeat.read_successor_journal")
    def test_running_successor_without_a_recent_healthy_report_is_failed(self, read, run):
        run.return_value = subprocess.CompletedProcess(
            [], 0, self.systemd_running, ""
        )
        read.return_value = json.dumps(
            {
                "MESSAGE": json.dumps(
                    {
                        "schema": "umi-successor-host-status/1",
                        "status": "holding",
                    }
                ),
                "_SYSTEMD_INVOCATION_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }
        )
        result = heartbeat(["vali.service"], successor_services=["vali.service"])
        self.assertEqual(result["services"]["vali.service"], "failed")
        read.return_value = ""
        result = heartbeat(["vali.service"], successor_services=["vali.service"])
        self.assertEqual(result["services"]["vali.service"], "failed")

    def test_successor_services_must_be_unique_service_subsets(self):
        for successor in [["other.service"], ["vali.service", "vali.service"]]:
            with self.assertRaisesRegex(ValueError, "invalid successor services"):
                heartbeat(["vali.service"], successor_services=successor)


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
