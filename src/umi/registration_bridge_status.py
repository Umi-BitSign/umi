"""Wallet-free RPC diagnostics for SN78 rows, not authorization or a payout proof."""

from __future__ import annotations

import argparse
import asyncio
import time

from .protocol import canonical_json_bytes

DEFAULT_VALIDATORS = {
    0: "5Fk765B4CRBekwErwE5VxvveWhHztHSfsnsLt8cbDayDWsuk",
    54: "5FLKx6h7DwWRuqq1dcfQafsBw5i9cbchNEFAEHrqSRthGnDZ",
}


def _uint(value, maximum=2**64 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid chain integer")
    return value


def summarize_rows(*, block, timestamp_ms, now_ms, values, rows, hotkeys, expected):
    """Interpret one RPC-reported finalized snapshot, refusing malformed vectors."""
    _uint(block)
    _uint(timestamp_ms)
    _uint(now_ms)
    if not -30_000 <= now_ms - timestamp_ms <= 120_000:
        raise ValueError("RPC finalized timestamp is stale or in the future")
    tempo = _uint(values["Tempo"])
    factor = _uint(values["ActivityCutoffFactorMilli"])
    rate = _uint(values["WeightsSetRateLimit"])
    if tempo == 0 or factor == 0:
        raise ValueError("unsupported activity cutoff")
    cutoff = max(1, tempo * factor // 1000)
    updates = values["LastUpdate"]
    permits = values["ValidatorPermit"]
    consensus = values["Consensus"]
    incentive = values["Incentive"]
    size = len(updates)
    if not 1 <= size <= 256 or any(len(v) != size for v in (permits, consensus, incentive)):
        raise ValueError("chain vector lengths differ")
    for update in updates:
        _uint(update, block)
    if any(type(p) is not bool for p in permits):
        raise ValueError("invalid validator permit")
    for amount in (*consensus, *incentive):
        _uint(amount, 65535)
    if not expected or set(rows) != set(expected) or set(hotkeys) != set(expected):
        raise ValueError("incomplete validator readback")
    validators = []
    for uid, expected_hotkey in sorted(expected.items()):
        _uint(uid, size - 1)
        row = rows[uid]
        if not isinstance(row, (list, tuple)) or len(row) > size:
            raise ValueError("invalid row")
        destinations = set()
        nonzero = []
        for pair in row:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValueError("invalid row entry")
            target, weight = pair
            _uint(target, size - 1)
            _uint(weight, 65535)
            if target in destinations:
                raise ValueError("duplicate weight destination")
            destinations.add(target)
            if weight:
                nonzero.append(target)
        age = block - updates[uid]
        reason = (
            "hotkey_changed"
            if hotkeys[uid] != expected_hotkey
            else "validator_permit_missing"
            if not permits[uid]
            else "empty_row"
            if not nonzero
            else "row_stale"
            if age > cutoff
            else "row_fresh"
        )
        validators.append(
            {
                "uid": uid,
                "hotkey": hotkeys[uid],
                "reason_code": reason,
                "last_update": updates[uid],
                "age_blocks": age,
                "stale_from_block": updates[uid] + cutoff + 1,
                "rate_ready_block": updates[uid] + rate,
                "row_entries": len(row),
                "nonzero_weights": len(nonzero),
                "weighted_uids_with_positive_incentive": sum(incentive[u] > 0 for u in nonzero),
            }
        )
    return {
        "schema": "umi-registration-bridge-rpc-status/1",
        "evidence_class": "rpc_reported_finalized",
        "independent_finality_verified": False,
        "bridge_policy_verified": False,
        "chain_submission_authorized": False,
        "status": "fresh" if all(v["reason_code"] == "row_fresh" for v in validators) else "alert",
        "netuid": 78,
        "finalized_block": block,
        "block_timestamp_ms": timestamp_ms,
        "checked_at_unix_ms": now_ms,
        "activity_cutoff_blocks": cutoff,
        "weights_set_rate_limit": rate,
        "validators": validators,
        "positive_consensus_count": sum(v > 0 for v in consensus),
        "positive_incentive_count": sum(v > 0 for v in incentive),
    }


async def collect_status(client, *, expected=None, clock_ms=None):
    from bittensor._generated import storage

    expected = DEFAULT_VALIDATORS if expected is None else expected
    clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
    stream = client.blocks(finalized=True)
    try:
        head = await anext(stream)
    finally:
        await stream.aclose()
    pinned = await client.at(head.number)
    names = (
        "Tempo",
        "ActivityCutoffFactorMilli",
        "WeightsSetRateLimit",
        "LastUpdate",
        "ValidatorPermit",
        "Consensus",
        "Incentive",
    )
    subtensor = storage.SubtensorModule

    async def read(item, params):
        result = await pinned.query(item, params)
        return getattr(result, "value", result)

    results = await asyncio.gather(*(read(getattr(subtensor, n), [78]) for n in names))
    uids = sorted(expected)
    row_values = await asyncio.gather(*(read(subtensor.Weights, [78, u]) for u in uids))
    hotkeys = await asyncio.gather(*(read(subtensor.Keys, [78, u]) for u in uids))
    timestamp = await pinned.timestamp()
    if timestamp.tzinfo is None:
        raise ValueError("chain timestamp must be timezone-aware")
    return summarize_rows(
        block=head.number,
        timestamp_ms=int(timestamp.timestamp() * 1000),
        now_ms=clock_ms(),
        values=dict(zip(names, results, strict=True)),
        rows=dict(zip(uids, row_values, strict=True)),
        hotkeys=dict(zip(uids, hotkeys, strict=True)),
        expected=expected,
    )


async def _check():
    import bittensor as bt

    async with bt.Client("finney", retry_forever=False) as client:
        return await collect_status(client)


def run_cli(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        result = asyncio.run(asyncio.wait_for(_check(), timeout=60))
    except Exception:
        # Never print URLs, environment values or exception strings from clients.
        result = {"status": "unknown", "reason_code": "chain_read_failed"}
    print(canonical_json_bytes(result).decode())
    return 0 if result["status"] == "fresh" else 2


def main():
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
