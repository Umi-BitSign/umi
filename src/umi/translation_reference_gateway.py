"""Narrow authenticated R2 gateway; native authority stays in the publisher.

The gateway's R2 binding executes atomic object conditions. This is distinct
from Cloudflare's administrative object API, which does not preserve If-Match.
Only the public common channels and typed approval namespace are admitted.
"""

import re
from urllib.parse import urlsplit

import httpx

from .r2_evidence import R2EvidenceClient
from .validator_supervisor import COMMON_SUPERVISOR_CHANNELS

REFERENCE_GATEWAY_ORIGIN = "https://umi-reference-control.sam-sn78.workers.dev"
REFERENCE_GATEWAY_R2_ENDPOINT = "https://91287420c3cb985d6d726f4ddd730b18.r2.cloudflarestorage.com"


def validate_gateway_origin(origin):
    if origin != REFERENCE_GATEWAY_ORIGIN or urlsplit(origin).scheme != "https":
        raise ValueError("reference control gateway origin differs")


class R2ReferenceGatewayClient(R2EvidenceClient):
    def __init__(self, origin, token, *, timeout_seconds=60, transport=None):
        validate_gateway_origin(origin)
        if re.fullmatch(r"[0-9a-f]{64}", token) is None or not 1 <= timeout_seconds <= 300:
            raise ValueError("reference control gateway credentials/budget differ")
        self.origin, self._token, self.transport = origin, token, transport
        self.timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 15))

    @staticmethod
    def _key(key):
        approval = re.fullmatch(
            r"validator-supervisor/translation-reference-policies/[0-9a-f]{64}\.json", key
        )
        for platform, channel in COMMON_SUPERVISOR_CHANNELS.items():
            if re.fullmatch(
                rf"validator-supervisor/channels/{channel}/{platform.replace('/', '-')}/after/"
                r"(?:0/initial|[1-9][0-9]{0,15}/[0-9a-f]{64})\.json",
                key,
            ):
                return
        if approval is None:
            raise ValueError("reference gateway key is outside the configured namespace")

    def _exchange(self, method, key, *, body=b"", headers=None, maximum=0, statuses=(200,)):
        self._key(key)
        if method not in {"GET", "HEAD", "PUT"}:
            raise ValueError("reference gateway operation is not supported")
        extra = dict(headers or {})
        if any(k.lower() in {"authorization", "host"} for k in extra):
            raise ValueError("reference gateway authorization cannot be overridden")
        request_headers = {
            "Authorization": "Bearer " + self._token,
            "Accept-Encoding": "identity",
            "Content-Length": str(len(body)),
            **extra,
        }
        try:
            with (
                httpx.Client(
                    transport=self.transport,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    method, self.origin + "/" + key, headers=request_headers, content=body
                ) as response,
            ):
                if response.status_code not in statuses:
                    raise OSError(
                        f"reference gateway request failed with HTTP {response.status_code}"
                    )
                if response.headers.get("content-encoding") not in {None, "identity"}:
                    raise ValueError("reference gateway returned encoded control bytes")
                if method == "HEAD":
                    return response.status_code, dict(response.headers), b""
                raw = bytearray()
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    if len(raw) + len(chunk) > maximum:
                        raise ValueError("reference gateway response exceeds its bound")
                    raw.extend(chunk)
                return response.status_code, dict(response.headers), bytes(raw)
        except httpx.HTTPError:
            # HTTPX exceptions may carry the authenticated request object.
            raise OSError("reference control gateway unavailable") from None
