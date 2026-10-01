# Public model artifacts

This Worker serves only the comparator model bundle and pinned offline runtime
listed in its static catalog. The private `umi-model-artifacts` bucket remains
private. The Worker has no upload, mutation, listing or arbitrary-key route.

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
