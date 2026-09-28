"""Exact reward inputs that may use an operator-approved worker source tree."""

from pydantic import model_serializer

from .protocol import Hex32, StrictProtocolModel


class WorkerSourceOverlayScope(StrictProtocolModel):
    package_sha256: Hex32
    release_bundle_sha256: Hex32
    recipient_amendment_sha256: Hex32
    successor_recipient_amendment_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def original_bytes(self, handler):
        value = handler(self)
        if self.successor_recipient_amendment_sha256 is None:
            value.pop("successor_recipient_amendment_sha256", None)
        return value
