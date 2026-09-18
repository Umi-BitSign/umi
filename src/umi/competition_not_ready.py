"""Bounded placeholder for competition routes that are not active yet.

Cloudflare Tunnel must have a live loopback origin for every published ingress
rule.  This process keeps future routes explicit without starting an assignment,
evaluation, or settlement service early.
"""

from __future__ import annotations

import argparse
from typing import Literal

import uvicorn
from fastapi import FastAPI
from starlette.responses import Response

from .protocol import canonical_json_bytes

Component = Literal["exchange", "round"]

_ROUTES: dict[Component, tuple[str, ...]] = {
    "exchange": ("/v1/competition/evaluators/exchange",),
    "round": (
        "/v1/competition/rounds",
        "/v1/competition/settlements",
        "/v1/competition/work",
    ),
}


def _json_response(payload: dict, *, status_code: int) -> Response:
    return Response(
        canonical_json_bytes(payload),
        status_code=status_code,
        media_type="application/json",
        headers={"cache-control": "no-store"},
    )


def create_app(component: Component) -> FastAPI:
    if component not in _ROUTES:
        raise ValueError("unsupported not-ready component")
    app = FastAPI(
        title="UMI competition service placeholder",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz")
    async def healthz() -> Response:
        return _json_response(
            {
                "component": component,
                "schema": "umi-competition-service-status/1",
                "status": "not_ready",
            },
            status_code=200,
        )

    async def not_ready() -> Response:
        return Response(
            canonical_json_bytes(
                {
                    "component": component,
                    "reason_code": "service_not_active_during_intake",
                    "retryable": True,
                    "schema": "umi-competition-service-not-ready/1",
                    "status": "not_ready",
                }
            ),
            status_code=503,
            media_type="application/json",
            headers={"cache-control": "no-store", "retry-after": "300"},
        )

    for path in _ROUTES[component]:
        app.add_api_route(path, not_ready, methods=["GET", "POST"])
    return app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=tuple(_ROUTES), required=True)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)
    if args.listen_host not in {"127.0.0.1", "::1"}:
        parser.error("the not-ready origin must listen on loopback")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    uvicorn.run(
        create_app(args.component),
        host=args.listen_host,
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
