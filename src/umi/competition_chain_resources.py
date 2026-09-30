"""Local resource locations for replaying an unchanged chain configuration.

Container paths are not portable to a host. These locations select only I/O:
all binary, metadata, chain and cache identity checks still use the original
configuration. They confer no chain or transaction authority.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .private_files import Directory
from .protocol import StrictProtocolModel

if TYPE_CHECKING:
    from .competition_chain import CompetitionChainConfig


class CompetitionChainResources(StrictProtocolModel):
    finality_binary: Directory
    chain_spec: Directory
    proof_binary: Directory
    state_directory: Directory
    storage_codec_metadata_path: Directory | None = None
    runtime_metadata_binary: Directory | None = None

    @classmethod
    def from_config(cls, config: CompetitionChainConfig) -> CompetitionChainResources:
        return cls(**{name: getattr(config, name) for name in cls.model_fields})

    def check(self, config: CompetitionChainConfig) -> None:
        for name in ("storage_codec_metadata_path", "runtime_metadata_binary"):
            if (getattr(self, name) is None) != (getattr(config, name) is None):
                raise ValueError("local resources cannot change the chain verification mode")
