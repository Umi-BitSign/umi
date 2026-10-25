# Public model artifacts

This Worker's public routes serve only the comparator model bundle and pinned
offline runtime listed in its static catalog. The private `umi-model-artifacts`
bucket remains private. The Worker has no upload, mutation or listing route.

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
