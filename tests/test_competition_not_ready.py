import json

import pytest
from fastapi.testclient import TestClient

from umi.competition_not_ready import create_app, main


@pytest.mark.parametrize(
    ("component", "paths"),
    [
        ("exchange", ("/v1/competition/evaluators/exchange",)),
        (
            "round",
            (
                "/v1/competition/rounds",
                "/v1/competition/settlements",
                "/v1/competition/work",
            ),
        ),
    ],
)
def test_future_routes_return_structured_not_ready(component, paths):
    client = TestClient(create_app(component))
    for path in paths:
        for method in (client.get, client.post):
            response = method(path)
            assert response.status_code == 503
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["retry-after"] == "300"
            assert response.content == json.dumps(
                {
                    "component": component,
                    "reason_code": "service_not_active_during_intake",
                    "retryable": True,
                    "schema": "umi-competition-service-not-ready/1",
                    "status": "not_ready",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()


def test_placeholder_has_bounded_health_and_route_surface():
    client = TestClient(create_app("round"))
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.headers["cache-control"] == "no-store"
    assert health.json() == {
        "component": "round",
        "schema": "umi-competition-service-status/1",
        "status": "not_ready",
    }
    assert client.get("/").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_placeholder_rejects_non_loopback_listener(capsys):
    with pytest.raises(SystemExit, match="2"):
        main(["--component", "round", "--listen-host", "0.0.0.0", "--port", "18201"])
    assert "must listen on loopback" in capsys.readouterr().err


def test_placeholder_rejects_invalid_component():
    with pytest.raises(ValueError, match="unsupported not-ready component"):
        create_app("other")
