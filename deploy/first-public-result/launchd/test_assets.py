from __future__ import annotations

import os
import plistlib
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class LaunchdAssetTests(unittest.TestCase):
    def test_templates_are_unprivileged_restartable_and_token_free(self) -> None:
        observer = plistlib.loads((ROOT / "vision.umi.observer.plist.in").read_bytes())
        cloudflared = plistlib.loads((ROOT / "vision.umi.cloudflared.plist.in").read_bytes())

        for document in (observer, cloudflared):
            self.assertEqual(document["RunAtLoad"], True)
            self.assertEqual(document["KeepAlive"], True)
            self.assertEqual(document["ProcessType"], "Background")
            self.assertEqual(document["Umask"], 0o77)
            self.assertNotEqual(document["UserName"], "root")

        observer_arguments = observer["ProgramArguments"]
        self.assertIn("127.0.0.1", observer_arguments)
        self.assertIn("api.umi.vision", observer_arguments)
        self.assertIn("https://umi.vision", observer_arguments)
        self.assertIn("https://www.umi.vision", observer_arguments)

        tunnel_arguments = cloudflared["ProgramArguments"]
        self.assertIn("--token-file", tunnel_arguments)
        self.assertNotIn("--token", tunnel_arguments)
        self.assertEqual(tunnel_arguments[-1], "REPLACE_WITH_TUNNEL_TOKEN_FILE")
        self.assertNotIn("eyJ", (ROOT / "vision.umi.cloudflared.plist.in").read_text())

    @unittest.skipUnless(os.uname().sysname == "Darwin", "plutil rendering is macOS-only")
    def test_renderer_embeds_only_the_token_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = root / "tunnel.token"
            token_value = "test-token-content-must-not-be-rendered"
            token.write_text(token_value)
            token.chmod(stat.S_IRUSR | stat.S_IWUSR)
            bundle_feed = root / "bundle-feed.json"
            bundle_feed.write_text("{}")
            bundle_feed.chmod(stat.S_IRUSR | stat.S_IWUSR)
            pilot_feed = root / "pilot-feed.json"
            pilot_feed.write_text("{}")
            pilot_feed.chmod(stat.S_IRUSR | stat.S_IWUSR)
            output = root / "rendered"

            completed = subprocess.run(
                [
                    str(ROOT / "manage.sh"),
                    "render",
                    "--output-dir",
                    str(output),
                    "--repo-root",
                    str(ROOT.parents[2]),
                    "--observer-bin",
                    "/usr/bin/true",
                    "--cloudflared-bin",
                    "/usr/bin/true",
                    "--token-file",
                    str(token),
                    "--bundle-feed-config",
                    str(bundle_feed),
                    "--pilot-feed-config",
                    str(pilot_feed),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            observer_path = output / "vision.umi.observer.plist"
            tunnel_path = output / "vision.umi.cloudflared.plist"
            observer = plistlib.loads(observer_path.read_bytes())
            tunnel = plistlib.loads(tunnel_path.read_bytes())
            self.assertEqual(
                observer["ProgramArguments"][:2],
                ["/usr/bin/true", "--listen-host"],
            )
            self.assertEqual(
                observer["ProgramArguments"][-4:],
                [
                    "--bundle-feed-config",
                    str(bundle_feed.resolve()),
                    "--pilot-feed-config",
                    str(pilot_feed.resolve()),
                ],
            )
            self.assertEqual(tunnel["ProgramArguments"][-1], str(token.resolve()))
            self.assertNotIn(token_value, tunnel_path.read_text())
            self.assertNotIn("REPLACE_WITH", observer_path.read_text())
            self.assertNotIn("REPLACE_WITH", tunnel_path.read_text())

    @unittest.skipUnless(os.uname().sysname == "Darwin", "plutil rendering is macOS-only")
    def test_renderer_can_run_observer_with_selected_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = root / "tunnel.token"
            token.write_text("test-token")
            token.chmod(stat.S_IRUSR | stat.S_IWUSR)
            output = root / "rendered"

            completed = subprocess.run(
                [
                    str(ROOT / "manage.sh"),
                    "render",
                    "--output-dir",
                    str(output),
                    "--repo-root",
                    str(ROOT.parents[2]),
                    "--observer-python",
                    "/usr/bin/true",
                    "--cloudflared-bin",
                    "/usr/bin/true",
                    "--token-file",
                    str(token),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            observer = plistlib.loads((output / "vision.umi.observer.plist").read_bytes())
            self.assertEqual(
                observer["ProgramArguments"][:4],
                ["/usr/bin/true", "-m", "umi.observer", "--listen-host"],
            )

    @unittest.skipUnless(os.uname().sysname == "Darwin", "argument checks are macOS-only")
    def test_renderer_rejects_both_observer_selectors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    str(ROOT / "manage.sh"),
                    "render",
                    "--output-dir",
                    str(Path(temporary) / "rendered"),
                    "--repo-root",
                    str(ROOT.parents[2]),
                    "--observer-bin",
                    "/usr/bin/true",
                    "--observer-python",
                    "/usr/bin/true",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("mutually exclusive", completed.stderr)

    @unittest.skipUnless(os.uname().sysname == "Darwin", "argument checks are macOS-only")
    def test_observer_python_must_be_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    str(ROOT / "manage.sh"),
                    "render",
                    "--output-dir",
                    str(Path(temporary) / "rendered"),
                    "--repo-root",
                    str(ROOT.parents[2]),
                    "--observer-python",
                    "deploy/first-public-result/launchd/manage.sh",
                    "--cloudflared-bin",
                    "/usr/bin/true",
                ],
                cwd=ROOT.parents[2],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("executable path is not absolute", completed.stderr)

    @unittest.skipUnless(os.uname().sysname == "Darwin", "file-mode checks are macOS-only")
    def test_renderer_rejects_a_public_token_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            token = root / "public.token"
            token.write_text("not-a-real-token")
            token.chmod(0o644)

            completed = subprocess.run(
                [
                    str(ROOT / "manage.sh"),
                    "render",
                    "--output-dir",
                    str(root / "rendered"),
                    "--repo-root",
                    str(ROOT.parents[2]),
                    "--observer-bin",
                    "/usr/bin/true",
                    "--cloudflared-bin",
                    "/usr/bin/true",
                    "--token-file",
                    str(token),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("mode must be 0400 or 0600", completed.stderr)
            self.assertNotIn("not-a-real-token", completed.stderr)

    def test_management_script_has_valid_shell_syntax(self) -> None:
        completed = subprocess.run(
            ["/bin/sh", "-n", str(ROOT / "manage.sh")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_migration_flow_targets_only_reported_listener_pids(self) -> None:
        script = (ROOT / "manage.sh").read_text()
        readme = (ROOT / "README.md").read_text()

        self.assertIn("manage.sh migration-check", readme)
        self.assertIn("migration_preflight_ready=1", script)
        self.assertIn("listener_pids", script)
        self.assertIn("/bin/ps -p PID -o pid=,ppid=,user=,comm=", script)
        self.assertIn("/bin/kill -TERM PID", script)
        self.assertIn("--tlsv1.1 --tls-max 1.1", script)
        self.assertIn("--tlsv1.2 --tls-max 1.2", script)
        self.assertNotIn("pkill", script + readme)
        self.assertNotIn("killall", script + readme)


if __name__ == "__main__":
    unittest.main()
