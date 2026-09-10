# Public pilot R2 upload Worker

This Worker is the only write path from the public-pilot automation host to the
`umi-public-evidence` R2 bucket. It accepts five immutable object classes:

- `PUT /public-pilot-cases/<archive-sha256>/sealed-case.tar.gz`, up to 96 MiB,
  with `Content-Type: application/gzip`;
- `PUT /public-pilot-evidence/<archive-sha256>/evidence.tar.gz`, up to 96 MiB,
  with `Content-Type: application/gzip`;
- `PUT /public-pilot-attempts/<archive-sha256>/attempt-journal.tar.gz`, up to
  96 MiB, with `Content-Type: application/gzip`;
- `PUT /public-pilot-automation/results/<authorization-id>.json`, up to 256 KiB,
  with `Content-Type: application/json`.
- `PUT /validator-bootstrap-results/<submission-id>.json`, up to 4 MiB, with
  `Content-Type: application/json`.

Every hexadecimal identifier must contain exactly 64 lowercase characters. The
case, evidence, and attempt-journal identifiers are their content SHA-256 values.
A result identifier is the automation authorization ID; its content SHA-256 is
supplied separately. Archive responses set the fixed attachment filename for
their respective object class.

The Worker stores result JSON as opaque bytes. The automation result envelope has
its own canonical-payload signature contract, separate from this upload-layer
HMAC. The uploader must construct and validate that envelope before this request.

The Worker has no read, list, overwrite, or delete HTTP route. It checks for an
existing object and then uses R2's atomic conditional `put` with
`etagDoesNotMatch: "*"`. An existing object returns `409`. A write that loses a
race returns `412`. Clients must treat either response as immutable conflict and
must verify the already-published bytes rather than retrying with changed content.

## Authentication contract

Set `UPLOAD_HMAC_SECRET` to one 32-byte random value encoded as 64 lowercase
hexadecimal characters. Set `VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST` to a
canonical JSON object whose keys are authorized 64-character submission IDs and
whose values are stable, per-validator 32-byte HMAC credentials. The object must
contain no whitespace, its keys must be sorted, and it may contain at most 32
entries in 4 KiB. This stays below Cloudflare's 5 KB per-variable limit. Unknown
submission IDs are denied. Malformed, noncanonical,
duplicate-key, or oversized maps fail closed.

The public-pilot secret authorizes only public-pilot paths. A mapped credential
authorizes only its named validator-bootstrap result paths. The value installed on
a validator must remain stable across that validator's later submissions. Add each
new signed submission ID to the server-side map before publishing its directive.
Another validator receives a different value. Keep every value out of Wrangler
configuration, source control, process arguments, and logs. Generate each into an
owner-only file and install secrets through standard input:

```sh
umask 077
secret_file="$(mktemp)"
openssl rand -hex 32 > "$secret_file"
npx wrangler secret put UPLOAD_HMAC_SECRET < "$secret_file"
rm -f "$secret_file"
```

Build the validator map in an owner-only file without printing its values. Install
it as `VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST`, then retain the per-validator
credentials in the approved secret store. Updating the map is a server-side
operation and does not replace the validator's installed credential.

Only currently authorized or imminently published submission IDs need to remain
in the map. Remove an ID after its immutable result has been verified. This keeps
the map bounded during a multi-day bootstrap cadence.

Each request supplies:

```text
Authorization: UMI-HMAC-SHA256 <lowercase HMAC-SHA256 hex>
Content-Length: <canonical positive decimal byte count>
Content-Type: application/gzip | application/json
X-UMI-Content-SHA256: <lowercase SHA-256 hex of the exact request body>
X-UMI-Timestamp: <canonical Unix timestamp in seconds>
```

The timestamp must be within 300 seconds of the Worker clock. Do not use
`Content-Encoding` or a query string. Construct the HMAC message as UTF-8 with no
trailing newline:

```text
umi-r2-upload-v1
PUT
/<exact object key>
<X-UMI-Timestamp>
<Content-Length>
<Content-Type>
<X-UMI-Content-SHA256>
```

R2 verifies the declared SHA-256 while consuming the request stream. The Worker
also requires the returned object size and SHA-256 metadata to match before it
returns `201`.

Use different HMAC values for pilot automation and each validator's bootstrap
results. They must also differ from the result-envelope HMAC, GitHub,
coordinator-wallet, observer, tunnel, and direct R2 credentials. Neither uploader
needs an R2 API token. A validator receives only its own stable bootstrap-result
transport credential; the result object is separately signed by its validator
hotkey and fully replayed before it can enter the observer feed.

## Local verification

The generated Worker types include both the R2 binding and secret placeholder.
The test configuration replaces the placeholder with a test-only value and uses a
local R2 binding. It does not contact the production bucket.

```sh
npm ci
npm run check
```

`npm run check` regenerates the ignored compatibility-date types, runs TypeScript
and the Workers-runtime Vitest suite, builds a Wrangler dry run, and checks startup
limits.

For local manual requests, copy `.dev.vars.example` to the ignored `.dev.vars`
file and replace its value with a fresh local-only secret. Do not reuse the
production secret.

## Deployment

Review `wrangler.jsonc` and confirm that the account already contains the
`umi-public-evidence` bucket. Then run the checks above, install the production
secret interactively, and deploy from this directory:

```sh
npx wrangler secret put UPLOAD_HMAC_SECRET
npx wrangler secret put VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST
npx wrangler deploy
```

The configuration publishes only the `pilot-upload.umi.vision` custom domain and
disables both `workers.dev` and preview URLs. Record that exact origin in the
root-owned automation configuration. Keep public R2 readback on its separate
origin. After every upload, download the object without credentials and verify its
length and SHA-256 before publishing its URL to GitHub.

To revoke a submission, remove its ID from the server-side map. To revoke a
validator credential, stop its supervisor, replace the value on that host, and
replace every retained mapping for that validator before resuming. Normal
submission refreshes only add a server-side ID and do not require validator action.
No production secret value belongs in an environment file.
