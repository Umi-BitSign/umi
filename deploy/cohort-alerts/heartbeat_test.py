"""Service-query failures must never fabricate failed-service observations."""

import subprocess
import unittest
from unittest.mock import patch

from heartbeat import heartbeat


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


if __name__ == "__main__":
    unittest.main()
