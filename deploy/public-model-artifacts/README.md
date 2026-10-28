# Public model artifacts

This Worker's public routes serve only the comparator model bundle and pinned
offline runtime listed in its static catalog. The private `umi-model-artifacts`
bucket remains private. Public routes provide no upload, mutation or listing
capability. The separately authenticated private transports are documented below.

Each artifact URL includes its model or runtime identity. The discovery index
also publishes the archive SHA-256 and exact byte length. Clients must verify
both the archive digest and the extracted model or runtime identity before use.
The Worker checks the stored object's size and private metadata before streaming
it, supports single byte ranges, and assigns immutable cache headers.

Build the model archive from a previously verified native bundle and reconstruct
the exact OCI runtime archive from its verified chunks:

```sh
python3 build_archives.py \
  --model-source /ABSOLUTE/PRESERVED/NATIVE/BUNDLE \
  --model-sha256 MODEL_SHA256 \
  --runtime-index /ABSOLUTE/RUNTIME/index.json \
  --runtime-chunks /ABSOLUTE/chunks/sha256 \
  --runtime-sha256 RUNTIME_SHA256 \
  --output /ABSOLUTE/NEW/PRIVATE/OUTPUT
```

Upload each completed archive under the exact R2 key in `src/index.ts`. Set
custom metadata `sha256`, `identity` and `kind` to the catalog values. Use a
conditional create or verify an existing object's size and metadata before
deployment. Do not upload private submissions under the public prefix.

Run `npm ci && npm run check`, deploy with `npx wrangler deploy`, then verify the
index, complete `HEAD`, first and last byte ranges, unknown-path rejection and
the published archive digests. The custom domain is
`https://artifacts.umi.vision`. Publishing these artifacts does not open intake,
accept a submission, certify a score or authorize rewards.

## Private metadata transport

Native readers can optionally use `POST /v1/internal/r2/heads` to confirm fresh
object generations in batches of at most 32 keys. This route requires a
purpose-derived HMAC credential and returns sizes and etags only. Requests and
responses are uncached, bounded to 64 KiB, and bound to the original R2 endpoint,
bucket and fresh request nonce. The Worker executes at most six heads at once.
The reader retains its configured metadata concurrency bound. It still validates
every object identity, size and generation and retains existing byte checkpoints.

Configure `METADATA_ENDPOINT` and `METADATA_BUCKET` to match the Worker's actual
R2 account and `ARTIFACTS` binding. The secret `METADATA_KEYS_JSON` maps each native
S3 access ID to the hex encoding of
`HMAC-SHA256(secret_access_key, "umi-r2-metadata-batch-key/1")`. Keep the original
S3 secret out of the Worker and all credentials outside Git. Use an authenticated
operator process to install the purpose keys through Wrangler's secret interface.
Missing configuration leaves the private route disabled.

Select the updated native reader before adding
`METADATA_BATCH_ORIGIN=https://artifacts.umi.vision` to a private credential export.
Use a new credential-file path when older supported services still consume the
original four-field export; their files must remain byte-identical. Preserve the
same native R2 endpoint, bucket and access identity across direct and candidate
readers. No miner flags, signed submissions, byte-receipt format or cohort clocks
change. Historical clients and validators continue direct S3 without the optional
field; updated coordinator, reviewer and settlement readers use it through the
same credential loader. A supported cooperative service selection is required
before claiming native rollout.

A failed batch exchange falls back to direct S3 and disables further proxy attempts
for that metadata scan. An individual unavailable result falls back only for that
item before using direct S3 for later groups. An authenticated missing object or
changed generation retains the native rejection/repair behavior. Existing object
counts, elapsed time and ETA cover both routes; fallback reasons are redacted and
reported as retrying. Qualify exact same-key parity against direct S3 before
selecting the optional transport. Health or successful public artifact reads alone
do not establish the private route's authentication or bucket binding.

## Private proof publication transport

`POST /v1/internal/r2/proof-publications` optionally batches up to eight original
proof objects of at most 4 KiB each. It stores the same bytes at the same R2
content-addressed keys using conditional creation. Objects are not packed or
re-encoded. Existing direct-S3 readers, frames, native verification results and
`umi-r2-proof-reference/1` receipts remain compatible. Larger objects and final
frames keep their existing direct transport; a frame is published only after
every member has its own durable acknowledgement.

The `PROOF_EVIDENCE` binding selects the private `umi-cohort-evidence` bucket.
`PROOF_ENDPOINT` and `PROOF_BUCKET` must match that actual binding. Configure
`PROOF_PUBLICATION_KEYS_JSON` through Wrangler's secret interface, outside Git.
It maps an authorized native S3 access ID to an object containing:

- `key`: hex `HMAC-SHA256(secret_access_key, "umi-r2-proof-publication-key/1")`.
- `prefixes`: exact writable proof-store prefixes, without a trailing slash.

This is separate write authority: metadata-reader keys do not authorize writes.
The Worker permits only `<prefix>/objects/<original-sha256>`, checks the request
nonce, clock, endpoint, bucket and content identity, and conditionally writes at
most six objects concurrently. It returns an ordered result per object. An
existing object is accepted only with its exact original size, ETag and SHA
metadata; conflicting objects are never overwritten. Requests and responses
are bounded to 64 KiB, uncached, and contain no native proof-acceptance claim.
Without the secret, the route remains disabled.

Deploy the compatible Worker and select the updated native producer through
the supported host maintenance/update path. Then select
`PROOF_PUBLISH_BATCH_ORIGIN=https://artifacts.umi.vision` in a new private
credential export for that producer. Preserve the original file for older
supported consumers; older credential loaders reject unknown fields. This
optional transport does not change the native account, bucket, prefix, journal
binding, signed cohort inputs or clocks. Coordinator, reviewer, settlement and
writer producers use the common proof store; miners and validators without the
option continue direct S3 and can read the same resulting objects. Publish the
compatible source selection through the normal miner/validator update paths
before claiming automatic rollout. Rollback selects the original credential
file and preserves all completed individual receipts.

The native store reserves all batch member keys and bytes under its existing
global eight-object admission bound. It retains successful per-object receipts
in one atomic journal transaction, even if other items failed. A lost response,
unavailable route or individual temporary failure invokes visible direct-S3
recovery only for unfinished objects and disables further batch attempts for
that owner process. Original conditional-write recovery handles ambiguous PUTs.
Malformed acknowledgements and conflicts refuse the operation; they do not take
a permissive fallback. Completed receipts survive restart and cache eviction.

`proof_publication_batch` and `proof_publication_fallback` expose counted work,
elapsed time, ETA basis and retry state. Redacted
`umi-r2-proof-publication-exchange/1` events additionally count actual frontend
request attempts/responses, HTTP status, and acknowledged, conflicting,
unavailable, unknown and fallback objects. These counts distinguish network
exchanges from graph/object scopes. Batching reduces frontend request count;
the Worker still makes individual R2 operations. Measure installed throughput
and fallback counts before revising the history forecast.
