# Public pilot R2 upload Worker

This Worker is the only write path from the public-pilot automation host to the
`umi-public-evidence` R2 bucket. It accepts four immutable object classes:

- `PUT /public-pilot-cases/<archive-sha256>/sealed-case.tar.gz`, up to 96 MiB,
  with `Content-Type: application/gzip`;
- `PUT /public-pilot-evidence/<archive-sha256>/evidence.tar.gz`, up to 96 MiB,
  with `Content-Type: application/gzip`;
- `PUT /public-pilot-attempts/<archive-sha256>/attempt-journal.tar.gz`, up to
  96 MiB, with `Content-Type: application/gzip`;
- `PUT /public-pilot-automation/results/<authorization-id>.json`, up to 256 KiB,
  with `Content-Type: application/json`.

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

Set `UPLOAD_HMAC_SECRET` to 32 random bytes encoded as 64 lowercase hexadecimal
characters. Keep it out of Wrangler configuration, source control, process
arguments, and logs. Generate it into an owner-only file, install it through
standard input, and then remove the temporary file:

```sh
umask 077
secret_file="$(mktemp)"
openssl rand -hex 32 > "$secret_file"
npx wrangler secret put UPLOAD_HMAC_SECRET < "$secret_file"
rm -f "$secret_file"
```

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

Use a different upload HMAC secret from the result-envelope HMAC, GitHub,
coordinator-wallet, observer, tunnel, and direct R2 credentials. The automation
host needs only this Worker secret and URL. It must not receive an R2 API token.

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
npx wrangler deploy
```

The configuration publishes only the `pilot-upload.umi.vision` custom domain and
disables both `workers.dev` and preview URLs. Record that exact origin in the
root-owned automation configuration. Keep public R2 readback on its separate
origin. After every upload, download the object without credentials and verify its
length and SHA-256 before publishing its URL to GitHub.

Rotate the HMAC secret by stopping the VPS controller, replacing the Worker secret,
replacing the VPS systemd credential, and then restarting the uploader. No secret
value belongs in an environment file.
