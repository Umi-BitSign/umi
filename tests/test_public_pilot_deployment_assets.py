from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_pilot_caddy_proxy_is_bounded_and_exact() -> None:
    config = (ROOT / "deploy" / "public-endpoint-pilot" / "Caddyfile.example").read_text()

    assert "admin off" in config
    assert "auto_https off" in config
    assert "max_header_size 16KiB" in config
    assert "max_size 64KiB" in config
    assert "response_header_timeout 240s" in config
    assert "compression off" in config
    assert "Content-Encoding identity" in config
    assert "127.0.0.1:8091" in config
    assert "method GET HEAD" in config
    assert "path /healthz" in config
    assert "method POST" in config
    assert "path /v1/translate" in config
    assert "respond 404" in config
    assert "encode " not in config
    assert "header_up" not in config
    assert "rewrite" not in config


def test_public_pilot_runbook_links_proxy_and_bounds_remote_probe() -> None:
    runbook = (ROOT / "docs" / "PUBLIC_ENDPOINT_MINER_PILOT.md").read_text()

    assert "deploy/public-endpoint-pilot/Caddyfile.example" in runbook
    assert "--connect-timeout 10" in runbook
    assert "--max-time 30" in runbook
    assert "--max-filesize 65536" in runbook
    assert "Caddy 2.10.0 or later is required" in runbook
    assert "valid for six days" in runbook
