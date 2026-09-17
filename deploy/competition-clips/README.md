# Selected competition clips

This Worker serves selected MP4 clips from a private R2 bucket. It has no upload,
listing, labels, signing or model-execution route. Each URL contains a random
256-bit capability and an explicit access window of at most seven days. Changing
the window or any other path segment selects a different, absent R2 object.
The service itself has no rehearsal deadline and can accept new selected clips
without a restart or code deployment.

The bucket must have **r2.dev access disabled and no public custom domain**.
Do not bind the public evidence bucket. Keep request invocation logs, traces,
Logpush and URL-bearing analytics disabled. Only a bounded storage-failure event
is logged by the application. Anyone given a complete URL can download that
clip within its window; this is a bearer capability, not miner authentication.
Do not place capability URLs in chat, public status or error reports.

The Worker verifies the stored SHA-256 checksum and streams at most 16 MiB per
object. Clients must still verify the signed assignment's expected SHA-256.
Responses are not cached. There is no automatic extension of an expired grant.
Completed-round replay uses retained evidence, not these temporary URLs.

## Deploy and verify

Run `npm ci && npm run check`. Create `umi-competition-clips` in the intended
Cloudflare account, verify its public access is disabled, then run
`npx wrangler deploy`. Use the resulting HTTPS Workers hostname. Deploying this
service does not open intake or authorize weights.

Prepare a mode-0600 JSON manifest outside the repository:

```json
{
  "schema": "umi-selected-clip-upload/1",
  "not_before_unix": 1789600000,
  "expires_unix": 1789603600,
  "videos": [{"sha256": "REVIEWED_CLIP_SHA256", "path": "/absolute/private/selected.mp4"}]
}
```

Use the shortest practical timestamps that cover the complete signed dispatch,
response and evaluation window plus a bounded recovery margin; the example is
not an active grant. Files must be private, owned regular files.
Upload only explicitly selected clips. Never upload labels or the unused pool.
The uploader checks MP4 framing, size and the manifest's hash before upload.

```sh
node upload.mjs /absolute/private/selected.json \
  /absolute/private/delivery.json https://YOUR-WORKER.workers.dev/
```

The output directory must be owned and mode 0700. The uploader saves private
capabilities before uploading, uses conditional create, and verifies downloaded
bytes. Retry with the identical input and receipt to recover an interruption.
A saved receipt alone does not prove upload completion: require the successful
bounded status and verify HTTP delivery before signing the round plan. Insert
those exact URLs in the selected suite's private request payloads. Do not modify
an already signed suite or retime an existing round.

Before a new live round, verify successful GET and HEAD with hash readback,
unknown-capability rejection and expiry rejection. Use synthetic or already
exposed clips for these tests. R2 retention is separate from URL expiry; review
old objects for retention under the data policy, not to repair a failed round.
