# UMI public observer API

This API is the read-only data source for the public SN78 page on `umi.vision`.
Its initial release observes finalized chain state. It does not publish live UMI
scores, calibration results, or activation evidence because no conforming public
bundle feed exists yet.

The chain remains authoritative. The API is a versioned index with explicit source
and freshness metadata, not a validator input or a second consensus system.

## Current public contract

The base path is `/api/v1`. Every data response includes:

- `schema`, a versioned response schema;
- `generated_at`, the time the complete snapshot was collected;
- `freshness`, either `fresh` or `stale`;
- `snapshot_age_seconds`;
- `finalized_head_age_seconds`, measured from the finalized block timestamp;
- `sources`, including the exact finalized block and verification method;
- `protocol_state.validator_input_eligible: false` where protocol state appears.

The chain source carries `storage_proofs_verified: false`. The collector pins every
read to a finalized block and cross-checks the block header, but this API does not
claim to verify Substrate storage proofs.

`X-UMI-Contract-Revision` and the `dashboard_static` source artifact hash identify
the hardcoded protocol classification. The revision is SHA-256 of compact,
key-sorted JSON for these facts:

```json
{"activation_evidence_available":false,"api_version":"v1","chain_result_classification":"unverified","conformance_evidence_available":false,"economic_era":"unverified","expected_chain_name":"UMI","mechanism_id":0,"netuid":78,"phase":"pre_public_calibration","protocol":"umi-asl/0.1","scoring_policy_hash":null,"specification_version":"0.1","translation_weights_active":false,"validator_input_eligible":false}
```

| Endpoint | Initial contents |
|---|---|
| `GET /api/v1/status` | Service readiness, UMI phase, finalized block, and outstanding gap codes |
| `GET /api/v1/network` | SN78 topology, epoch, runtime, commit-reveal state, emission flags, counts, and selected hyperparameters |
| `GET /api/v1/participants` | Public UID, hotkey, role, serving announcement, chain economics, and explicit UMI-score unavailability |
| `GET /api/v1/leaderboard` | Separate native chain-economics ranking and empty UMI translation leaderboard |
| `GET /api/v1/windows` | Empty public-calibration window feed with `not_started` |
| `GET /api/v1/windows/{window_id}` | A released window once the future bundle feed exists; currently a structured `404` |
| `GET /api/v1/activation-gates` | Gate inventory with every unevidenced gate marked `pending` |
| `GET /api/v1/benchmarks` | Empty public benchmark feed with `not_started` |
| `GET /api/v1/incidents` | Empty published-incident feed with `not_started` |

`HEAD` is supported on every public data endpoint. `POST`, `PUT`, `PATCH`, and
`DELETE` are not. `/openapi.json` contains the machine-readable GET contract.

The service also exposes:

- `GET /healthz`, which reports process liveness only;
- `GET /readyz`, which returns `503` until an acceptably recent complete snapshot
  exists.

## Status example

Values below are illustrative. Clients must use the returned block and timestamps.

```json
{
  "schema": "umi-observer-status/1",
  "generated_at": "2026-09-01T16:00:00Z",
  "freshness": "fresh",
  "snapshot_age_seconds": 3,
  "finalized_head_age_seconds": 18,
  "sources": [
    {
      "source_id": "bittensor-finalized-sn78",
      "source_kind": "chain_finalized",
      "verification_status": "finalized_read",
      "block": {
        "number": "8973539",
        "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "parent_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "state_root": "0x3333333333333333333333333333333333333333333333333333333333333333",
        "timestamp": "2026-09-01T15:59:48Z",
        "finalized": true,
        "storage_proofs_verified": false
      },
      "policy_hash": null,
      "artifact_sha256": null,
      "validator_input_eligible": false
    },
    {
      "source_id": "umi-observer-contract-bfd20ab3df0a7737",
      "source_kind": "dashboard_static",
      "verification_status": "repository_static",
      "block": null,
      "policy_hash": null,
      "artifact_sha256": "bfd20ab3df0a7737361248f6c79fb14794a1fcc4b1cbc5d97854705e0b3df1ab",
      "validator_input_eligible": false
    }
  ],
  "service": "umi-observer-api",
  "api_version": "v1",
  "service_status": "ready",
  "protocol_state": {
    "protocol": "umi-asl/0.1",
    "specification_version": "0.1",
    "phase": "pre_public_calibration",
    "netuid": 78,
    "mechanism_id": 0,
    "translation_weights_active": false,
    "scoring_policy_hash": null,
    "conformance_evidence_available": false,
    "activation_evidence_available": false,
    "economic_era": "unverified",
    "chain_result_classification": "unverified",
    "expected_chain_name": "UMI",
    "chain_identity_matches_expected": false,
    "validator_input_eligible": false
  },
  "finalized_block": {
    "number": "8973539",
    "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "parent_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "state_root": "0x3333333333333333333333333333333333333333333333333333333333333333",
    "timestamp": "2026-09-01T15:59:48Z",
    "finalized": true,
    "storage_proofs_verified": false
  },
  "outstanding_gap_codes": [
    "activation_gates_not_passed",
    "active_scoring_policy_unavailable",
    "public_calibration_not_started",
    "released_audit_bundle_feed_unavailable",
    "umi_weight_cutover_unverified"
  ]
}
```

## Exact quantities

JavaScript cannot exactly represent every chain integer. Block heights, epochs,
token atomic units, and similar `u64` values are base-10 strings. Do not convert
them to `number`; use `BigInt` where arithmetic is needed.

Token quantities are explicit about their asset:

```json
{
  "raw": "9007199254740992",
  "decimals": 9,
  "unit": "rao",
  "asset": "subnet_alpha"
}
```

TAO and subnet alpha are different assets and must not be added together. Render a
human value by placing nine decimal digits, but retain and sort by `raw`.

Current chain fractions use their exact `PerU16` representation:

```json
{
  "raw_numerator": "32767",
  "raw_denominator": "65535",
  "display_decimal": "0.49999237048905165178912031738765545128557259479667",
  "unit": "per_u16"
}
```

Sort by `BigInt(raw_numerator)`, not `display_decimal`. Future UMI scores use exact
string numerators and denominators as well.

The network exchange rate likewise includes exact `tao_reserve_rao` and
`subnet_alpha_reserve_rao` strings. Its `display_decimal` is derived for rendering;
the reserve pair remains authoritative.

Network lifecycle flags have narrow meanings:

- `subnet_exists` is the finalized `NetworksAdded` registration flag;
- `subnet_started` means the owner's one-shot start call has enabled staking,
  alpha trading, and participant emissions;
- `subnet_emission_enabled` is the separate root-controlled switch for TAO-side
  pool injection.

## Participants and pagination

Use `role=all`, `role=miner`, or `role=validator`. `limit` is from 1 through 512.

```text
GET /api/v1/participants?role=miner&limit=100
```

When `page.next_cursor` is non-null, pass it unchanged on the next request. The
cursor binds the role and finalized block, so a page cannot be mixed with a newer
snapshot. A changed snapshot returns `409 cursor_snapshot_changed`; start again
without a cursor.

Participant rows intentionally omit coldkeys, serving IP addresses, personal
identity data, commitments, hypotheses, references, signatures, and video URLs.
`serving_announced` means an endpoint is registered on chain. It does not claim the
endpoint was probed or is reachable.
`chain_active` is the metagraph's chain-state flag. It must not be rendered as
"online," "healthy," or "reachable."

The fields under `chain_metrics` are native chain observations. They are never UMI
translation scores. Until released score evidence exists, every row has:

```json
{
  "umi_translation": {
    "availability": "unavailable",
    "reason_code": "released_umi_score_evidence_unavailable",
    "miner_root": null,
    "accuracy": null,
    "utility": null,
    "rank": null,
    "audit_bundle_sha256": null,
    "audit_release_block": null
  }
}
```

## Leaderboards

`chain_economics` orders miner-role UIDs by the finalized native incentive
numerator, descending, with UID as the display-order tie-breaker. It is marked
`classification: unverified` and `derivation_status: dashboard_derived`. The API
does not call current values legacy, bootstrap, or UMI results until the required
cutover audit establishes their origin. This ranking helps operators inspect
current SN78 economics, but it is not UMI translation performance or a
chain-provided rank.

When at least two incentive values differ, `chain_rank` uses competition ranking:
exact ties receive the same rank and `incentive_tie_size` reports the group size.
When all observed values are equal, `ranking_status` is
`no_economic_separation`, every `chain_rank` is null, and UID order is not a rank.

`umi_translation` is a separate object. It remains `not_started` with no entries
until the future evidence index verifies conforming bundles and their release
blocks. The site must keep these two lists visibly distinct.

```json
{
  "chain_economics": {
    "classification": "unverified",
    "derivation_status": "dashboard_derived",
    "ranking_basis": "native_incentive_per_u16_descending",
    "tie_breaker": "uid_ascending",
    "ranking_status": "no_economic_separation",
    "reason_code": "all_observed_incentives_equal",
    "source_ids": ["bittensor-finalized-sn78"],
    "excluded_missing_incentive": 0,
    "entries": [
      {
        "chain_rank": null,
        "incentive_tie_size": 1,
        "uid": 12,
        "hotkey": "5ExampleHotkey",
        "chain_active": true,
        "serving_announced": true,
        "incentive": {
          "raw_numerator": "32767",
          "raw_denominator": "65535",
          "display_decimal": "0.49999237048905165178912031738765545128557259479667",
          "unit": "per_u16"
        },
        "dividends": null,
        "emission": null
      }
    ]
  },
  "umi_translation": {
    "availability": "not_started",
    "reason_code": "public_calibration_not_started",
    "entries": []
  }
}
```

## Vercel integration

Run `umi-observer` on a separate always-on host. A Vercel function is only the
same-origin proxy; it must not run the background collector. Prefer that server-side
route on `umi.vision` rather than browser requests to the observer origin. This
needs no CORS permission and avoids exposing deployment details.

Use an endpoint allowlist. Do not accept an arbitrary upstream URL or concatenate a
user-supplied path.

```ts
const upstreamPaths = {
  status: "/api/v1/status",
  network: "/api/v1/network",
  participants: "/api/v1/participants",
  leaderboard: "/api/v1/leaderboard",
  windows: "/api/v1/windows",
  gates: "/api/v1/activation-gates",
  benchmarks: "/api/v1/benchmarks",
  incidents: "/api/v1/incidents",
} as const;

export async function fetchObserver(
  key: keyof typeof upstreamPaths,
  query = "",
): Promise<Response> {
  const base = process.env.UMI_OBSERVER_BASE_URL;
  if (!base) throw new Error("UMI_OBSERVER_BASE_URL is not configured");

  return fetch(`${base}${upstreamPaths[key]}${query}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
}
```

Pass only parsed, allowlisted query fields to the participant route. Preserve the
upstream `ETag`, `Cache-Control`, `X-UMI-Contract-Revision`,
`X-UMI-Dataset-Revision`, and `X-UMI-Finalized-Block` headers in the Vercel
response. Render all returned strings as text; do not insert API values as HTML.

If the browser must call the observer directly, configure exact origins:

```text
--cors-origin https://umi.vision \
--cors-origin https://www.umi.vision
```

Preview domains are not wildcarded. Add a particular preview origin only when it
is intentionally trusted. CORS is browser policy, not API authentication.
Direct browser responses expose `ETag`, `X-UMI-Contract-Revision`,
`X-UMI-Dataset-Revision`, and `X-UMI-Finalized-Block` to allowed origins.

## Deployment

Install the repository package and run the observer behind an HTTPS reverse proxy:

```bash
umi-observer \
  --listen-host 127.0.0.1 \
  --port 8092 \
  --network finney \
  --trusted-host api.umi.vision
```

If the reverse proxy preserves an internal Host header, add that exact host with a
second `--trusted-host`. Never use a wildcard. The process needs outbound read
access to a Bittensor RPC endpoint. It needs no wallet files, hotkey, coldkey,
signing service, transaction permissions, or Bittensor token-symbol disk cache.
The observer skips the SDK token-symbol cache and places downloaded runtime
metadata in a process-private temporary directory instead of the operator's normal
Bittensor home cache. Operators may set `BITTENSOR_RUNTIME_CACHE_DIR` to an
observer-owned directory when a persistent cache is preferred.

Useful controls:

```text
--fresh-for-seconds 24
--maximum-stale-seconds 120
--refresh-interval-seconds 12
--refresh-timeout-seconds 45
--finalized-head-timeout-seconds 20
--maximum-finalized-head-age-seconds 120
--maximum-future-block-skew-seconds 30
--log-level info
```

A collection failure leaves the last complete snapshot intact and marks it stale.
A partial collection is never published. Once the maximum stale interval passes,
data endpoints and `/readyz` return a bounded `503 snapshot_unavailable` response.
Public request handlers only read the cache and never trigger an RPC call, miner
probe, or artifact fetch. Safe structured refresh failures and the last successful
block are written to the process log; raw exception text is not.

## Future score and evidence feed

Do not populate `umi_translation` from chain incentive, dividend, or emission
values. Those values belong only in `chain_economics`. Do not ingest
`umi-component-bundle/1` or
`umi-shadow-rehearsal-bundle/2` as calibration evidence. They are engineering
fixtures and expressly deny activation evidence.

The future evidence index must verify every content-addressed object, bind the
bundle to its validator, window, policy, and finalized chain proofs, and quarantine
it until its protocol-defined `audit_release_block`. Public counts, pagination,
errors, ETags, and metrics must not reveal quarantined outcomes. Only then may the
API expose translation scores, terminal window state, activation evidence, or
incidents. The response schema also requires every released score or window to cite
a `released_audit_bundle` source with the same artifact hash, and rejects a release
block above the response's finalized-chain source.

The initial window and incident feeds are deliberately empty and unpaginated. Before
either feed begins retaining public history, introduce a cursor-bound page object under
a new response schema and API contract version. Do not activate an unbounded v1 feed.
