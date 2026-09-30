"""Deterministic shared-IP caps for an explicitly amended endpoint allocation.

Endpoint identities come from the certified roster, never current DNS or a
miner-supplied replacement URL. Ports do not create independent reward groups.
This module computes weights; it does not authorize a change to rewards.
"""

from __future__ import annotations

import ipaddress
from fractions import Fraction
from urllib.parse import urlsplit


def endpoint_ip(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
        raise ValueError("IP grouping requires a public HTTPS endpoint")
    address = ipaddress.ip_address(parsed.hostname or "")
    address = getattr(address, "ipv4_mapped", None) or address
    if not address.is_global or address.is_multicast or getattr(address, "scope_id", None):
        raise ValueError("IP grouping requires a public literal IP")
    return str(address)


def certified_ip_groups(package, removed_uids):
    """Bind every payable endpoint to its original, signed serving IP.

    The scoped amendment supports endpoint-only rounds whose model allocation
    goes to the policy's burn destination. Mixed model/endpoint attribution
    needs its own projection; it must never be inferred from merged weights.
    """
    burn = package.policy.unallocated_model_burn
    if burn is None or package.retained_settlement.promotion_head.contributor_hotkey is not None:
        raise ValueError("IP amendment requires an endpoint-only allocation with model burn")
    origins = {}
    for signed in package.roster.submissions:
        sub = signed.submission
        if sub.track != "endpoint":
            continue
        if sub.hotkey in origins:
            raise ValueError("IP amendment requires one certified endpoint per hotkey")
        origins[sub.hotkey] = sub.endpoint_url
    groups = {}
    for allocation in package.retained_settlement.projection.allocations:
        if (
            allocation.uid == burn.uid
            or allocation.uid in removed_uids
            or not allocation.raw_weight
        ):
            continue
        if allocation.hotkey not in origins:
            raise ValueError("payable recipient lacks its certified endpoint")
        ip = endpoint_ip(origins[allocation.hotkey])
        groups.setdefault(ip, []).append(allocation.uid)
    return tuple((ip, tuple(sorted(uids))) for ip, uids in sorted(groups.items()))


def grouped_endpoint_weights(projection, weights, groups, burn_uid):
    """One best-score budget per IP, divided equally with exact integer totals."""
    selected = {uid for uid, weight in weights.items() if weight and uid != burn_uid}
    members = [uid for _, uids in groups for uid in uids]
    if not groups or len(members) != len(set(members)) or set(members) != selected:
        raise ValueError("IP groups must partition every payable endpoint exactly once")
    shares = {a.uid: Fraction(int(a.numerator), int(a.denominator)) for a in projection.allocations}
    scores = [max(shares[uid] for uid in uids) for _, uids in groups]
    if any(score <= 0 for score in scores):
        raise ValueError("IP group requires positive certified scores")
    budget = sum(weights[uid] for uid in selected)
    total = sum(scores)
    exact = [score * budget / total for score in scores]
    quotas = [int(value) for value in exact]
    # IP is the stable group identity. Adding ports cannot change a group tie.
    order = sorted(range(len(groups)), key=lambda i: (-(exact[i] - quotas[i]), groups[i][0]))
    for i in order[: budget - sum(quotas)]:
        quotas[i] += 1
    result = dict(weights)
    for (_, uids), quota in zip(groups, quotas, strict=True):
        each, remainder = divmod(quota, len(uids))
        for index, uid in enumerate(uids):
            result[uid] = each + (index < remainder)
    return result
