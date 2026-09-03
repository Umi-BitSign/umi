# Reference mirror and delivery service

`umi-mirror-service` is the repository-owned data plane for a certified shadow
window. It serves the exact certified tree to validators and exchanges a complete
selected video-commitment set for short-lived, credential-free miner URLs. It has
no wallet, chain RPC, signing, extrinsic, commitment, or weight capability.

The service is intentionally window-scoped. Start it from a newly written
`certified-release.json`; never point it at a mutable staging tree.

## Private configuration

Start from [the schema-valid example](examples/mirror-service-config.json), but do
not reuse its public example secrets or identifiers. The actual canonical RFC 8785
object must bind:

- the exact inactive scoring-policy bytes and SHA-256;
- the policy-pinned mirror-discovery bytes and SHA-256;
- the exact certified tree and `certified-release.json` SHA-256;
- distinct canonical HTTPS retrieval and delivery origins from that discovery rule;
- an absolute state-database path outside the certified tree; and
- exactly one independently generated 256-bit base64url bearer for every validator
  in the policy registry, ordered by decoded validator account.

The signed discovery rule must contain equally sized retrieval and delivery origin
sets with at least `max(3, floor(2 * V / 3) + 1)` entries for the policy's `V`
validators. Deploy one independently administered service for each readiness pair.
Each service config names one retrieval origin and one delivery origin from those
sets. The availability signer later binds that exact pair to its hotkey.

Create the config directory and state parent as the service OS user with mode
`0700`. Write the config with mode `0600`. Policy and discovery files must be owned
by that user, regular files with one link, and not group- or other-writable. Generate
each bearer independently with a CSPRNG; for example, Python's
`secrets.token_urlsafe(32)` produces the required 43-character encoding. Deliver
each validator only its own bearer and the retrieval origin it belongs to over an
authenticated private channel. Generate a separate token for every
`(validator, retrieval origin)` pair; tokens must not be copied between mirror
services. Never put
bearers in source control, process arguments, URLs, logs, or the certified tree.

The example is a shape reference only. Its zero digests, paths, hotkeys, and public
bearers are deliberately unusable for a real release.

## Offline validation

Run:

```text
umi-mirror-service --config /etc/umi/mirror-service.json --check
```

`--check` reads and verifies the canonical config, inactive policy, discovery rule,
complete certified graph, availability signatures, anchor intents, file ownership,
file modes, hashes, and exact tree membership. It performs no network operation and
no filesystem write; in particular it does not create the state database. A ready
result is not an activation or weight-readiness claim.

After every signer service passes this check and is reachable through its TLS
frontend, use the `attest-mirror` and `verify-mirrors` steps in
[the availability guide](PUBLISHER_AVAILABILITY_OPERATOR.md). No pool anchor should
be submitted without the resulting readiness-set digest.

## TLS and reverse proxy

The installed service deliberately binds plain HTTP to the configured IP and port.
For production, keep `listen_host` on loopback or a private Unix/network namespace
and terminate TLS at a separately maintained reverse proxy. The service does not
claim or infer TLS from proxy headers (`proxy_headers` is disabled).

Configure two distinct public HTTPS virtual hosts:

- the retrieval origin proxies the authenticated window index, certified static
  tree, content-addressed objects, and `POST /v1/umi/video-deliveries`;
- the delivery origin proxies only
  `GET /v1/umi/deliveries/{32-character-token}`.

Preserve the original `Host` header exactly. Do not redirect, rewrite paths, decode
percent escapes, decompress request bodies, add a query string, or expose another
upstream route. Disable access logs at the proxy: miner URL paths contain bearer
tokens. Disable response caching, including at a CDN, so an expired delivery cannot
survive in a cache. The application also disables Uvicorn access logs, rejects
proxy-forwarded authority claims, emits identity-encoded exact-length responses,
and returns only stable reason codes on errors.

## Runtime behavior

All static and issuance requests on the retrieval origin require exactly one
`Authorization: Bearer ...` value. Public delivery GETs accept no credential and
work only before their policy-derived expiry. Query strings, redirects, userinfo,
noncanonical token paths, private source URLs, compression, oversized headers, and
oversized or noncanonical issuance bodies fail closed.

The first valid issuance for a validator credential atomically stores the exact
request, response, token-to-certified-video mappings, and expiry before replying.
An exact replay returns the same bytes. A byte-different replay under that credential
returns conflict and allocates nothing. SQLite uses a private WAL database,
`synchronous=FULL`, record authentication, and immediate write transactions, so
independent worker processes serialize the same durable result.

The service checks the wall clock monotonically and stops on rollback. Config,
policy, discovery, certified-tree, or state mutation also stops service. Rotate to a
new immutable tree, config, secret set, and state database for the next window;
never edit a running window in place.

The issuance schema does not carry a Quicknet selection proof. The service therefore
accepts one complete, policy-sized, distinct-control-group batch set per registered
validator credential from the certified candidate graph. This is bounded and does
not give an authenticated validator new disclosure power: that validator can already
retrieve every certified video. Validators remain responsible for deriving the
common Quicknet selection and will reject a response that differs from their exact
selected commitments.

Credential rotation is coordinated between windows. Keep the old services and
bearer set live through reveal, provision every next-window service and its unique
per-validator tokens, distribute the complete origin-bound token maps, and only
then restart validators onto the new maps before the next announcement. A partial
or in-place rotation intentionally fails closed.

Run after a successful check:

```text
umi-mirror-service --config /etc/umi/mirror-service.json
```

Keep config and state on durable local storage. Backups containing either are
owner-private security material. Monitor only process availability and stable reason
codes; do not collect request paths, authorization values, request bodies, token
mappings, seeds, or private filesystem paths.
