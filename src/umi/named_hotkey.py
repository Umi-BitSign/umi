"""Read the single configured unlocked hotkey without constructing a wallet."""

import os
import stat
from pathlib import Path

from .encoding import account_id32

_MAX_KEYFILE_BYTES = 128 * 1024


def load_named_hotkey(path: Path, expected_hotkey: str):
    # No Wallet constructor, coldkey lookup, password environment or prompt.
    # The caller selects the named hotkey from its approved installation.
    from bittensor.keyfiles import (
        deserialize_keypair_from_keyfile_data,
        keyfile_data_is_encrypted,
    )

    from .competition_upgrade import _fingerprint, _open_without_links

    descriptor = _open_without_links(path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) != 0o400
            or not 0 < before.st_size <= _MAX_KEYFILE_BYTES
        ):
            raise ValueError("successor hotkey mount is unsafe")
        body = bytearray()
        while chunk := os.read(descriptor, min(8192, _MAX_KEYFILE_BYTES + 1 - len(body))):
            body.extend(chunk)
            if len(body) > _MAX_KEYFILE_BYTES:
                raise ValueError("successor hotkey mount exceeds its bound")
        if len(body) != before.st_size or _fingerprint(os.fstat(descriptor)) != _fingerprint(
            before
        ):
            raise ValueError("successor hotkey mount changed while reading")
    finally:
        os.close(descriptor)
    try:
        if keyfile_data_is_encrypted(bytes(body)):
            raise ValueError("successor hotkey must be unlocked by its operator before staging")
        signer = deserialize_keypair_from_keyfile_data(bytes(body))
        if account_id32(signer.ss58_address) != account_id32(expected_hotkey):
            raise ValueError("successor hotkey differs from its installed identity")
        if signer.crypto_type not in {0, 1}:
            raise ValueError("successor hotkey has an unsupported signing scheme")
        return signer
    finally:
        # Best-effort cleanup of this mutable read buffer, not a claim that
        # Python or the SDK can erase all private-key copies from memory.
        body[:] = b"\x00" * len(body)
