# bitsign MVP execution plan

Status: implementation baseline

Last reviewed: 29 August 2026

This document turns the bitsign product, technical, and pilot documents into an
ordered set of work packages. An implementation agent should start here. The
technical specification remains the source for product requirements, and the pilot
plan remains the source for external-use gates. When those documents disagree about
implementation order or a technical choice, this document controls until the source
documents are reconciled.

## 1. Delivery boundary

The work has three releases. They must remain separate.

1. **Internal vertical slice**: an iOS TestFlight build captures a short ASL clip,
   uploads it, receives a result from a declared internal model, and displays the
   `technical_prototype` label. Only named team testers may use it.
2. **Contribution build**: the same app supports separately consented Task A and
   Task B work, including a bounded offline queue. Contribution data never originates
   from the ordinary Communicate flow.
3. **Closed pilot build**: an approved model has passed the frozen evaluation and the
   app has passed gates R1 through R5. External pilot accounts use role `user`, never
   `internal`. Pilot evidence follows the separate protocol in Section 12.

The internal vertical slice is the first engineering target. A real translation model,
community recruitment, and pilot materials do not block local development because the
repository includes a declared fixture model for development and CI. Fixture output
must never be served in production or represented as translation.

## 2. Fixed decisions

These choices are settled for the MVP. Change one only through a written decision
record that identifies affected work packages and tests.

| Area | Decision |
|---|---|
| Repository | Keep the mobile app, API contract, gateway, Rust API, and test fixtures in this repository. |
| iOS target | iOS 17.0 or later, iPhone only, SwiftUI, Swift 6 language mode. |
| Apple toolchain | Xcode 26.6 with the bundled Swift 6.3 compiler. Pin the Xcode build in CI and `.xcode-version`. |
| Project generation | XcodeGen 2.46.0 from a committed `project.yml`. Commit `Package.resolved`; do not commit generated API sources. |
| API client | OpenAPI 3.1 is canonical. Generate the Swift client at build time with Swift OpenAPI Generator 1.13.0 and use its URLSession transport for JSON endpoints. |
| Rust toolchain | Rust 1.98.0, edition 2024, Axum 0.8.9. Commit `rust-toolchain.toml` and `Cargo.lock`. |
| Media toolchain | FFmpeg and ffprobe 8.1.2. Pin the version in `.ffmpeg-version`, CI, and the API image; record the release image digest. |
| Worker toolchain | Node 26.5.0, npm 11.17.0, Wrangler 4.127.1, TypeScript 7.0.2, and Vitest 4.1.11. Commit `.node-version`, exact package versions, and `package-lock.json`. |
| App architecture | Feature-first Swift packages, protocol-based dependency injection, Swift Observation, and actors for mutable service state. No third-party state-management framework. |
| Camera format | Front camera, MP4/H.264, no audio track, nominal 30 fps, 720p preset, 2 through 6 seconds, and at most 12 MiB. Accept portrait or landscape after applying the transform: long edge 480 through 1280, short edge 360 through 720, measured frame rate 24 through 31, and at most 190 decoded frames. |
| Speech reply | Require on-device recognition. If the active locale or device does not support it, offer typed reply instead. Audio never leaves the device. |
| Client model choice | The user cannot select a model. The authenticated configuration response supplies `inference_mode` and a canonical `config_version`; the app echoes both to `/v1/inferences`. |
| Communicate feedback | Ordinary Communicate offers an optional local text edit, held in memory and discarded with the result. It has no rating control or feedback endpoint. Ratings or corrections may leave the device only inside a separately consented pilot or research flow. |
| Contribution queue | Persist only consented contribution work. Use protected app-container files excluded from backup, with a maximum of 10 clips or 120 MiB and a 24-hour task expiry. |
| Session authority | D1 is authoritative for sessions and revocation. KV stores non-sensitive configuration only. Do not authorize requests from KV because KV reads are eventually consistent. |
| Gateway boundary | The Worker assigns request IDs, applies coarse IP limits, and routes to the API container. The Rust API owns authentication, authorization, and business logic. |
| Cloudflare bindings | The API container reaches D1, R2, KV, and Queues through Worker outbound handlers. Each handler exposes a narrow versioned internal operation, not arbitrary public SQL or bucket access. |
| Inference routing | The Rust API resolves the active model and calls the registered inference runtime. The Worker does not choose models. |
| Real model runtime | The inference HTTP contract is language-neutral. The fixture runtime is Rust. A real runtime may use Python or Rust as required by the selected model, but must pass the same contract and readiness tests. |
| Model output | UTF-8 plain text only, at most 2 KiB and 120 Unicode-whitespace-delimited words after trimming and whitespace collapse. Reject control characters other than input whitespace. The app renders `Text`, never Markdown, HTML, or detected links. |
| Confidence | No confidence field in the public API or UI until a calibration study gives it defined user meaning. Runtime diagnostics remain internal and cannot change the label. |
| Participant eligibility | Contribution and closed-pilot accounts are named, consented adults age 18 or older for the MVP. The app does not infer age from Apple identity data. Minor participation requires a later protocol and product change. |
| Deployment authority | An agent may build, test, and commit locally. It must not push, deploy, upload a TestFlight build, change Cloudflare resources, or recruit participants without explicit owner approval. |

Proposed identifiers and URLs:

- bundle identifier: `ai.bitsign.app`;
- staging API: `https://api.staging.bitsign.ai`;
- production API: `https://api.bitsign.ai`;
- background contribution session: `ai.bitsign.app.contribution-upload`.

The owner must confirm control of the bundle identifier and domains before work package
E8. Earlier packages use local configuration and do not require that confirmation.

## 3. Required repository layout

The scaffold work package creates this layout:

```text
.xcode-version
.node-version
rust-toolchain.toml
.ffmpeg-version
Cargo.lock

apps/ios/
  project.yml
  Config/
    Base.xcconfig
    Debug.xcconfig
    StagingDevice.xcconfig
    StagingTestFlight.xcconfig
    Production.xcconfig
  Bitsign/
    App/
    Resources/
      Assets.xcassets/
      Localizable.xcstrings
      PrivacyInfo.xcprivacy
  Packages/
    BitsignKit/
      Package.swift
      Sources/
        BitsignAPIClient/
        BitsignAppState/
        BitsignAuth/
        BitsignCapture/
        BitsignTransfer/
        BitsignCommunicate/
        BitsignContribute/
        BitsignPilot/
        BitsignSettings/
        BitsignSupport/
      Tests/
  BitsignUITests/
  Package.resolved

contracts/
  openapi/bitsign-v1.yaml
  fixtures/
    api/
    media/
    model/

crates/
  bitsign-domain/

services/
  gateway/
    src/
    test/
    package.json
    wrangler.jsonc
  api/
    src/
    tests/
    Cargo.toml
  inference-fixture/
    src/
    tests/
    Cargo.toml

infra/
  migrations/
  environments/

scripts/
  check-mobile-toolchains.sh
  check-mobile.sh
  ios-test.sh
  local-mobile-stack.sh
  verify-openapi.sh
```

`scripts/check-mobile.sh` is the single local verification entry point. It must run
contract validation, Worker checks, Rust formatting/lint/tests, iOS generation,
build, unit tests, and UI tests that do not require a physical camera or Apple service.
`scripts/check-mobile-toolchains.sh` checks the exact versions in Section 2 and exits
with install guidance without installing anything. `scripts/local-mobile-stack.sh`
starts or stops isolated local Worker, API, fixture-inference, D1, R2, KV, and Queue
emulators without touching a Cloudflare account.

## 4. Configuration and secrets

### 4.1 Build configuration

The app has four build configurations:

| Configuration | API | Auth behavior | Model eligibility |
|---|---|---|---|
| Debug | local stack | injected fake provider only | fixture only |
| StagingDevice | staging | real Sign in with Apple; App Attest `development`; development-signed physical devices only | fixture or internal evaluation |
| StagingTestFlight | staging | real Sign in with Apple; App Attest `production`; archived internal TestFlight build | internal evaluation or an approved candidate |
| Production | production | real Sign in with Apple; App Attest `production`; no bypass | approved role and release-scope combinations only |

The API base URL, build channel, and App Attest environment are compile-time values in
`.xcconfig`. Staging accepts both App Attest environments only when each is bound to
the matching allowlisted build channel; the challenge response never trusts a client
environment choice. There is no settings-screen environment switch. The
StagingTestFlight and Production targets must fail their build when a bypass flag is
present.

The generated Info.plist carries localized `NSCameraUsageDescription`,
`NSMicrophoneUsageDescription`, and `NSSpeechRecognitionUsageDescription`. It does not
request Photo Library access. Every non-Debug entitlement set includes Sign in with
Apple and the channel-correct App Attest environment; Debug uses injected providers.
App Transport Security allows only HTTPS outside a Debug-only localhost exception. The
app uses its default private Keychain access group and declares no keychain sharing.

### 4.2 Server configuration

The authenticated `GET /v1/config` response contains:

```json
{
  "schema": "bitsign-client-config/1",
  "config_version": "hex-encoded-sha256",
  "minimum_app_version": "0.1.0",
  "inference_mode": "continuous",
  "capability_label": "technical_prototype",
  "capability_copy_version": "1",
  "scope_list_version": "internal-fixture-1",
  "model": {
    "id": "fixture/hash-map-v1",
    "version": "1",
    "release_scope": "internal_evaluation"
  },
  "authorization": {
    "pilot_participant_expires_at": null,
    "pilot_reviewer_expires_at": null
  },
  "features": {
    "communicate": true,
    "reply": true,
    "contribute": false,
    "pilot": false,
    "pilot_review": false
  },
  "limits": {
    "minimum_clip_milliseconds": 2000,
    "maximum_clip_milliseconds": 6000,
    "maximum_clip_bytes": 12582912
  }
}
```

The client rejects an unknown schema or capability label and shows an update-required
screen when below `minimum_app_version`. Capability copy is bundled in the app and
selected by label plus `capability_copy_version`; the server cannot inject arbitrary
user-facing text. App versions are exactly three dot-separated unsigned decimal
components with no prerelease syntax; compare their integer tuples. A malformed
minimum version fails closed to the update-required screen.

`config_version` is lowercase hexadecimal SHA-256 of the RFC 8785 bytes of the
role-filtered config object with exactly that field omitted. Any model, label, scope,
copy, feature, limit, minimum-version, or authorization change produces a new digest.
The inference request carries both `mode` and `config_version`; a mismatch returns
`config_stale` before model dispatch.

Update-required and unsupported-feature screens keep only Sign out, account deletion,
deletion-status tracking, and support copy available. The server preserves compatible
auth, config, logout, deletion-create, and deletion-status operations for every
distributed MVP build until its last possible 90-day session and 45-day status-token
window have elapsed; it may reject all media and task operations from an old build.

### 4.3 Secrets and owner-provided values

No secret belongs in source control, an `.xcconfig`, the app bundle, or an OpenAPI
example. Before staging deployment, the owner supplies:

- Apple team ID, App Store Connect app record, and signing access;
- final bundle identifier confirmation;
- Sign in with Apple and App Attest entitlements;
- Cloudflare account and zone access;
- R2 signing credentials, script-encryption key, network-hash key, and internal
  service credentials;
- staging and production API hostnames.

Tests use generated local keys and fake Apple fixtures. Production code must have no
fallback secret or default credential.

Commit `.env.example` with names and safe local placeholders only. Ignore `.env`,
archive export options containing team data, derived Xcode output, local D1/R2 data,
media captured by tests, and every credentials file. The local stack generates its
own disposable signing, HMAC, and encryption keys under an ignored temporary data
directory.

## 5. Canonical API contract

`contracts/openapi/bitsign-v1.yaml` is written before feature code. Every public JSON
endpoint, status code, error envelope, enum, length limit, and example lives there.
The Rust request types and Swift client are generated or checked against this file.
CI fails when either side diverges.

### 5.1 General rules

- JSON uses UTF-8 and `snake_case` keys.
- IDs are 26-character ULIDs. Timestamps are UTC RFC 3339 strings.
- Every Worker response includes `X-Request-ID`.
- Every authenticated mutation accepts a client-generated 26-character ULID in
  `Idempotency-Key`; scope is `(account_id, operation_id, key)` and retention is 24
  hours unless the operation table says longer.
- Unknown JSON fields are rejected on security-sensitive requests and ignored on
  additive responses only where the schema says so.
- Errors use `{ "error": { "code", "message", "request_id", "retry_after_ms"? } }`.
- Clients branch on `code`, never `message`.
- The request target is at most 2 KiB and the decoded header block at most 16 KiB.
  JSON request and response bodies are at most 64 KiB except the admin script import,
  whose request is at most 256 KiB. The Worker and API both enforce the applicable
  decoded limit. Direct media transfers remain subject to the declared 12 MiB object
  bound and are never proxied through the public JSON route.
- JSON requests use `Content-Type: application/json`; responses use
  `application/json; charset=utf-8`. Unsupported media types receive `415`.
- Auth, config, upload, inference, task, review, pilot, and deletion responses send
  `Cache-Control: no-store`; R2 GET reservations also sign a no-store response policy.
- Session and deletion tokens are 32 random bytes encoded as unpadded base64url.
- R2 object keys are `<purpose>/<random ULID>` and contain no account, task, script,
  participant, filename, or model identifier.
- After authentication, the API applies two D1-backed atomic token buckets per
  session. Reads have capacity 240 and refill at 2 tokens per second; mutations have
  capacity 60 and refill at 1 token per 2 seconds. Each request costs one token.
  Arithmetic uses integer millitokens and server time. Exhaustion returns `429`,
  `Retry-After`, and the matching `retry_after_ms`. Rows expire 24 hours after the
  session expires. The Worker separately applies a coarse IP backstop and limits each
  auth route to 10 requests per minute per IP without persisting or logging the IP.

### 5.2 Required public operations

| Operation | Purpose | Idempotency |
|---|---|---|
| `POST /v1/auth/challenges` | Create a single-use Apple/App Attest challenge. | Not retried automatically. |
| `POST /v1/auth/apple` | Exchange Apple identity plus an App Attest attestation or assertion for a session. | Challenge ID is single-use. |
| `POST /v1/auth/logout` | Revoke the current session. | Safe to repeat. |
| `GET /v1/config` | Fetch feature, model-mode, label, version, and capture limits. | Read. |
| `POST /v1/uploads` | Reserve one object and return a presigned PUT URL plus exact required headers. | Key retained for 24 hours. |
| `POST /v1/inferences` | Run or recover one inference from an uploaded object. | Key retained for 24 hours. |
| `GET /v1/consent` | Return current contribution-consent status and document version. | Read. |
| `POST /v1/consent` | Grant exactly the displayed contribution-consent version. | Safe to repeat for the same version. |
| `DELETE /v1/consent` | Withdraw contribution consent and stop task issuance. | Safe to repeat. |
| `GET /v1/tasks/next` | Return one prioritized Task B review, Task A capture, or `no_task`. | Issuance ID prevents duplicates. |
| `POST /v1/tasks/{id}/submit` | Attach an uploaded Task A clip. | Key retained for task lifetime. |
| `POST /v1/reviews/{id}/submit` | Submit one Task B reconstruction. | Key retained for review lifetime. |
| `DELETE /v1/me` | Revoke sessions and enqueue account deletion; requires a client-generated `Deletion-Status-Token`. | One job per account. |
| `GET /v1/deletions/status` | Read deletion progress after local logout using `Authorization: Deletion <token>`. | Read; only the token hash is stored. |
| `GET /healthz` | Shallow process health. | Public read. |

The admin tag contains `GET /v1/admin/queue`, `POST /v1/admin/decisions`,
`POST /v1/admin/holds/release`, `POST /v1/admin/scripts`,
`POST /v1/admin/anchors/{task_id}/promote`, and `GET /v1/admin/metrics`. These
operations require role `admin`, accept no participant identity in a URL or log, and
write an audit row for every mutation.

The pilot tag contains `GET /v1/pilot/consent`, `POST /v1/pilot/consent`,
`GET /v1/pilot/tasks/next`, `POST /v1/pilot/tasks/{id}/submit`,
`POST /v1/pilot/tasks/{id}/ratings`, `GET /v1/pilot/reviews/next`,
`POST /v1/pilot/reviews/{id}/submit`, and `POST /v1/pilot/withdrawals`. Task
submission accepts a `pilot_evaluation` upload ID and the per-task confirmation
version; it runs inference, returns the output, and writes the exact restricted
output record atomically. Participant operations require a pilot-authorized `user`
account and current pilot consent. Review operations require the separate
`pilot_reviewer` permission. E9 also adds an admin-only enrollment and revocation
operation. Its schemas and role tests must exist before pilot mode can be enabled.

### 5.3 Authorization matrix

| Caller | Allowed surface |
|---|---|
| Unauthenticated | Auth challenge/exchange and shallow health only. |
| `user` | Configuration and ordinary Communicate with an `approved_pilot` model; Contribute only with current contribution consent. |
| Pilot-authorized `user` | User surface plus current-consent pilot participant operations; never an `internal_evaluation` model. |
| `internal` | Named technical testing, including `internal_evaluation` models; no admin operation. |
| `admin` | Admin CLI/API operations and declared technical tests; no implicit pilot-review access. |
| `pilot_reviewer` permission | Time-limited pilot review operations for the assigned review set only. |

The API evaluates both account role and the requested model release scope for every
inference. The echoed `inference_mode` is a stale-configuration check, not authority;
the API resolves the permitted mode from current server state and returns
`config_stale` on mismatch. A feature flag cannot grant a role or permission.

### 5.4 Authentication protocol

`POST /v1/auth/challenges` accepts the compile-time build channel, app version, and
build number. It returns a challenge ID, 32 random bytes as unpadded base64url, an
Apple nonce, expiry, and the expected App Attest environment. The API host and an
allowlist map the build channel to bundle ID and environment; an unknown combination
is rejected before a challenge is created.
The server stores only the challenge hash, expected bundle and environment, expiry,
and consumed timestamp in D1. Challenge creation has a coarse per-IP limit and auth
exchange consumes the row atomically before any session is issued.

The Sign in with Apple request includes the returned nonce. The app then computes one
canonical auth-client-data object containing the challenge ID, raw challenge hash,
identity-token hash, key ID, bundle ID, build channel, app version/build number, and
App Attest environment.

- A newly generated App Attest key returns `kind=attestation` and an attestation object.
- A key already registered to the Apple subject returns `kind=assertion` and an
  assertion object. The server verifies and advances its counter.
- Reinstall, migration, restore, or an unknown key produces
  `attestation_registration_required`; the app generates and attests a new key after a
  fresh challenge.
- Unsupported App Attest devices cannot enter Staging or Production. Debug simulator
  tests use an injected provider and a separate local endpoint configuration.
- An expired, replayed, wrong-environment, wrong-bundle, counter-regressed, or
  signature-invalid object is rejected.

The server validates the Apple identity token issuer, audience, expiry, nonce, and
signature against Apple keys. It stores the App Attest public key and counter per
account/device. A successful response returns an opaque 32-byte session token once.
Only `SHA256(session_token)` is stored in D1.

The successful auth response contains the token, its current expiry, and
`account: { id, role }`. It never returns the Apple subject or App Attest public key.
The app stores the account ID beside the token in the same device-only Keychain record
and uses it only for local ownership checks. Role and the config authorization fields
control presentation; the server still authorizes every request. Pilot authorization
expiries are RFC 3339 instants, and the app hides the affected work immediately when
one passes.

The app keeps two `AfterFirstUnlockThisDeviceOnly` Keychain records: a session record
containing token, bitsign account ID, and the Sign in with Apple user identifier; and a
device record containing the App Attest key ID. This permits a user-authorized
background contribution upload after the first unlock and provides the identifier
needed for Apple credential-state checks. Neither record is synchronized or logged. A
401 clears the session record after the credential check but leaves the device key for
a returning assertion. Explicit logout clears the session and queued work; account
deletion clears both records. The app presents Sign in with Apple when another identity
token is needed and does not claim a silent token refresh.

Sessions initially expire after 30 days. When fewer than 15 days remain, an
authenticated primary-D1 read may extend expiry to the earlier of 30 days from that
request or 90 days from session creation. It writes at most once per 24 hours and
never extends a revoked session. Logout, account deletion, or a successful new-device
login sets `revoked_at` before the response returns. At the 90-day absolute limit, the
app presents Sign in with Apple again.

### 5.5 Upload and inference protocol

The iOS client computes SHA-256 and byte length from the completed local file. Upload
creation returns:

```json
{
  "upload_id": "01...",
  "put_url": "https://...",
  "required_headers": {
    "content-type": "video/mp4",
    "content-length": "123456",
    "x-amz-meta-sha256": "..."
  },
  "expires_at": "2026-08-29T12:00:00Z"
}
```

The app sends exactly those headers. Presigned URLs are bearer credentials and must
never be logged. Communicate URLs expire after 10 minutes; contribution and pilot URLs
expire after 60 minutes. Only Contribute uses background transfer, and it starts one
only when at least 15 minutes remain. A failed or expired PUT returns its contribution
queue item to `reserving`; the app requests a new reservation during the current
background callback when possible, or on the next launch. It never reuses the URL for
another file. The server verifies actual bytes and
media structure, then checks duration, transformed dimensions, frame count, declared
digest, and object ownership before inference or task submission.

The API validates and normalizes model output using the fixed rule in Section 2 before
returning it. An out-of-bounds or invalid output is `internal`, never truncated into a
plausible translation. Pilot evidence stores the exact validated string that the app
received.

A successful inference response has the following minimum shape; OpenAPI fixes every
field bound and status variant:

```json
{
  "request_id": "01...",
  "transcript": "checked and normalized plain text",
  "model": {
    "id": "model-id",
    "mode": "continuous",
    "version": "content-bound-version",
    "capability_label": "technical_prototype",
    "release_scope": "internal_evaluation"
  },
  "timings": {
    "queue_ms": 0,
    "inference_ms": 125
  }
}
```

The API returns `config_stale` instead of output unless the active model's ID, mode,
capability label, version, and release scope match the current role-filtered config.
The app displays the label carried by the successful response, verifies that all five
values match its last config, and refetches config once on a mismatch. There is no
public confidence field.

Communicate uses a foreground ephemeral `URLSession`. It retains the protected local
clip until a result is received or the user discards it. A failed inference reuses the
server `upload_id`. A transport retry reuses the idempotency key; a user-requested rerun
after a typed terminal failure uses a new key only while the upload remains `stored`.
If the first inference succeeded but its response was lost, the server object is
already deleted and the server returns `result_unavailable`; the app can create a new
upload from the still-local clip. If the app terminates, launch cleanup removes the
unreferenced local clip and the server sweep deletes any orphan within 24 hours.

Contribute uses a background `URLSessionUploadTask` created from a protected file. It
persists task ID, local file URL, digest, bytes, attempt count, next attempt, and current
upload reservation. When a presigned URL expires, it requests a fresh reservation.

### 5.6 Client error mapping

The OpenAPI enum includes at least:

| Code | Client response |
|---|---|
| `unauthorized` | Clear session and show Sign in with Apple. Keep a consented queued contribution file until the user signs in or cancels it. |
| `attestation_required` | Explain physical-device requirement; no retry loop. |
| `attestation_registration_required` | Generate a new App Attest key after a fresh challenge. |
| `consent_required` | Route to the current contribution consent. |
| `invalid_media` | Keep the local clip and offer reshoot or diagnostic details. |
| `media_too_long` | Return to review and require reshoot. |
| `upload_expired` | Reserve a new upload and retry the same file. |
| `config_stale` | Refetch authenticated configuration once, then require an app update if the mismatch remains. |
| `model_unavailable` | Show the current capability boundary and disable Translate. |
| `model_warming` | Honor `retry_after_ms`, cap at three retries and 60 seconds total. |
| `inference_timeout` | The server attempt is terminal. Offer an explicit rerun with a new key while the upload remains stored. |
| `result_unavailable` | Explain that the prior result was not retained. Offer a new upload of the still-local clip, or recapture if it is gone. Do not rerun under the completed key. |
| `rate_limited` or `overloaded` | Honor bounded retry delay; keep current work. |
| `task_expired` | Delete its queued clip and fetch another task. |
| `conflict` | Poll or retry the same idempotency key; never create parallel inference. |
| `internal` | Show request ID and a retry action; log no user content. |

## 6. iOS implementation design

### 6.1 Module ownership

| Module | Owns | Must not own |
|---|---|---|
| `AppState` | launch routing, authenticated account state, feature flags, scene privacy | camera or network implementation |
| `APIClient` | generated JSON client, auth middleware, error decoding | presigned upload bodies |
| `Auth` | Sign in with Apple, App Attest provider, Keychain session | account-role policy |
| `Capture` | camera authorization, preview, recording, review asset, temp-file cleanup | uploads or model selection |
| `Transfer` | direct presigned PUT/GET sessions, exact signed headers, progress, background-task reconciliation | reservation policy, model selection, or consent |
| `Communicate` | communicate state machine, in-memory results and local edits, TTS | persisted transcript history or feedback submission |
| `Contribute` | consent state, next-task state machine, protected queue | ordinary communication clips |
| `Pilot` | participant tasks, per-task confirmation and ratings, permission-gated reviewer queue | ordinary Communicate or training contributions |
| `Settings` | versions, consent withdrawal, deletion initiation/status | hidden admin controls |
| `Support` | clock, UUID/ULID, hashing, file protection, redacted logging | product state |

Each service has a protocol and production implementation. Tests inject clocks, App
Attest, Apple authorization, API, upload, speech, camera, and filesystem fakes.

The Swift package targets use the `Bitsign`-prefixed names from the repository layout.
Their dependency graph is acyclic: Support has no product dependency; APIClient,
Capture, and Transfer depend on Support; Auth depends on APIClient and Support;
Communicate and Contribute depend on APIClient, Capture, Transfer, and Support;
Settings depends on APIClient, Auth, Contribute, Pilot, and Support; Pilot depends on
APIClient, Capture, Transfer, Auth, and Support; AppState composes all feature targets.
The executable app contains only composition, resources, and scene entry points.

### 6.2 Navigation and feature gates

Launch routing is deterministic:

```text
launch
  -> unsupported build
  -> sign in
  -> authenticated configuration load
      -> update required
      -> main tabs
```

A stored session is loaded before presenting an unsupported or update-required route
so Sign out and account deletion remain reachable. No such route can capture, upload,
infer, or fetch a task.

Main tabs are `Communicate`, optional `Contribute`, and `Settings`. `Contribute` appears
only when the server flag is true. Pilot mode is not a hidden gesture or local toggle;
it requires a server-authorized pilot account and a pilot-capable build. A participant
then receives a `Pilot` tab instead of ordinary `Communicate` for the scheduled session.
A separate `Review` tab appears only with an unexpired `pilot_reviewer` permission.
Both tabs also require their matching server feature flag; a flag alone grants no
authorization.

### 6.3 Communicate state machine

Only these transitions are valid:

```text
ready -> recording -> review -> reserving_upload -> uploading -> inferring -> result
recording -> ready                 (cancel)
review -> ready                    (discard)
uploading -> review                (recoverable upload failure)
inferring -> inferring             (warming or idempotent recovery)
inferring -> review                (recoverable terminal failure)
result -> ready                    (new message or clear)
any foreground state -> signed_out (401)
```

The record control enables after 2 seconds and hard-stops at 6 seconds. The app shows
recording time visually and through VoiceOver announcements that do not fire more than
once per second. Upload and inference have separate labels and progress. Numeric model
confidence is not displayed because it has no calibrated user meaning.

Results exist in memory only. The app shows an opaque privacy cover whenever the scene
is inactive so iOS app-switcher snapshots contain no video or transcript. Logout,
account deletion, a manual Clear action, and process termination remove the transcript
list and pending Communicate state.

An ordinary result keeps the immutable model string and an optional editable copy in
memory. The UI labels the latter `Edit for this conversation`, never replaces the
displayed provenance, and keeps the capability label visible. Speak uses the edited
copy when present. Both strings clear together and neither is submitted. Pilot output
is immutable; its separately consented rating and correction fields never alter the
stored exact model output.

When the scene becomes inactive, stop camera and speech input immediately. A recording
is cancelled and its partial file deleted; a completed review clip stays protected for
the current process. An in-flight foreground upload or inference may finish, but the
result remains behind the privacy cover and is reconciled on return. Camera interruption,
route change, and insufficient-storage errors return to a stable review or ready state.

### 6.4 Capture implementation

- Use `AVCaptureSession` with a video input and `AVCaptureVideoDataOutput`; feed sample
  buffers to `AVAssetWriter`. Do not use `AVCaptureMovieFileOutput`, request microphone
  access for ASL capture, or create an audio input or track.
- Use the front camera and 720p preset at 30 fps. Configure `AVAssetWriter` for H.264
  in MP4, real-time input, an empty metadata array, and no location. Fail capture when
  the requested codec/settings cannot be created; do not fall back to HEVC.
- Mirror the live preview for the signer, but write a canonical unmirrored file. Add
  a media fixture that proves preprocessing preserves handedness and applies the
  orientation transform exactly once.
- Record device orientation and apply the track transform during server preprocessing.
  Apply the exact transformed dimension, frame-rate, and decoded-frame envelope from
  Section 2.
- Write to `Library/Caches/Communicate` for ordinary clips and
  `Library/Application Support/ContributionQueue` for consented queued clips.
- Set `.completeUnlessOpen` on Communicate files. Set
  `.completeUntilFirstUserAuthentication` on contribution queue files so a previously
  authorized background transfer can resume after the first device unlock. Exclude
  every clip from backup.
- Delete abandoned partial files, files left by a crash, and files not referenced by a
  live queue entry during launch cleanup.
- Never save to Photos. Do not embed a thumbnail in notifications or widgets.

The preview overlay is advisory; it does not reject a signer based on pose estimation.
The guide must fit face, torso, and both hands and adapt to portrait or landscape.

### 6.5 Contribution queue

The queue is an actor backed by an atomic Codable index plus protected files. Every
item is bound to the authenticated account ID and is either a Task A capture or a Task
B reconstruction. A user must be online to receive a new task. Once issued, Task A
prompt state or the Task B source clip may be held under the same file-protection,
backup-exclusion, cap, and expiry rules.

Task A uses:

```text
captured -> waiting_for_network -> reserving -> uploading -> submitting -> complete
       \-> cancelled
       \-> expired
       \-> paused
```

Task B uses:

```text
downloading -> awaiting_reconstruction -> submitting -> complete
          \-> cancelled
          \-> expired
          \-> paused
```

Retry delays are 5 seconds, 30 seconds, 2 minutes, and 10 minutes. After four failed
attempts, the item waits for a manual retry. Retry jitter is deterministic in tests.
The queue enforces its byte and item caps before capture. Consent withdrawal, account
deletion, task expiry, or user cancellation removes the file and server reservation.

Background uploads are created from file URLs. On app launch, recreate the background
session using the same identifier and reconcile system tasks against the queue index.
Force-quit cancellation is treated as a paused item, not success or data loss.
Explicit logout cancels system tasks and deletes the queue. A 401 may preserve it while
the same account reauthenticates, but signing in as a different account deletes the old
queue and can never reassign its files.

A contribution-consent version change pauses issuance, queued transfers, and
submissions before the next network action. Accepting the exact new version resumes
still-live tasks; declining invokes withdrawal and deletes their local and server
artifacts. A feature flag cannot bypass this state.

### 6.6 Speech reply

Request microphone and Speech authorization only when the user opens Reply and taps
the microphone. Create the recognizer for `en-US` and set
`requiresOnDeviceRecognition=true` only when it reports on-device support. Otherwise
show the typed reply control and explain that speech input is unavailable. The reply
text remains in memory and is never sent to bitsign servers. TTS uses an installed
English `AVSpeechSynthesizer` voice and is always optional.

### 6.7 Accessibility and copy

All user-facing strings live in a String Catalog. English is the only release language,
but no feature string may be hard-coded in a view. The following are release checks:

- VoiceOver labels, hints, traits, and predictable focus after every state transition;
- Dynamic Type through `accessibility5` without clipping or horizontal scrolling;
- WCAG AA contrast for text and essential controls;
- no information conveyed by color, sound, or animation alone;
- Reduce Motion support for the countdown and progress states;
- a non-timed alternative to every timed instruction;
- permission-denial screens with a Settings link and a non-camera exit path;
- the capability label next to every result, not only in onboarding.

The three label strings are versioned fixtures and snapshot-tested:

- `technical_prototype`: internal connection test; translation quality unproven;
- `bounded_vocabulary`: only the listed signs and phrases are supported;
- `short_clip_preview`: experimental short ASL messages in the approved check-in scope.

### 6.8 Local privacy and diagnostics

Include `PrivacyInfo.xcprivacy` from the first build. Use no advertising, tracking,
third-party analytics, keyboard SDK, or crash SDK in the MVP. Unified logging may include
build version, request ID, state transition, byte count, duration, and stable error code.
It must redact URLs, bearer tokens, presigned URLs, Apple identifiers, task text,
account IDs, transcripts, reconstructions, and file paths containing IDs.

The generated JSON transport and every foreground media transfer use an ephemeral
`URLSessionConfiguration` with URL cache disabled, cookies disabled, and request cache
policy `reloadIgnoringLocalCacheData`. The background configuration exists only in
`BitsignTransfer` for consented Contribute PUTs; its task descriptions contain an opaque
queue-item ULID and no URL, account, task, or script text.

The privacy manifest declares tracking as false and lists every required-reason API
category actually used by the app or a dependency. CI validates the plist, entitlements,
privacy manifest, and merged archive settings. Adding a package that introduces a new
privacy manifest or collected-data declaration requires a review before merge.

## 7. Backend implementation design

### 7.1 Worker gateway

The Worker has four responsibilities:

1. reject bodies and headers over configured limits before proxying;
2. assign one server-generated ULID request ID and ignore any caller-supplied value;
3. apply a coarse IP rate limit without logging the raw IP; and
4. proxy public requests to the named API container.

Container outbound handlers expose versioned internal hosts for D1 operations, R2
object operations and presigning, queue publication, and KV configuration reads. They
verify the calling container identity and accept only known operation schemas. No
internal handler is reachable through the public fetch router.

### 7.2 Rust API

The API is stateless and organized into domain, application, and adapter layers.
Handlers do not contain SQL or Cloudflare-specific code. Storage, object, queue, clock,
Apple-token verification, App Attest verification, and inference are traits.

Operational logs contain request ID, build and model version, sizes, timings, status,
and stable error code. When abuse correlation needs an account dimension, use a
daily-rotated HMAC pseudonym; never log the account ID, Apple subject, raw IP, media,
prompt, reconstruction, transcript, presigned URL, or output-derived hash. Restricted
authorization and admin audit rows remain in D1 under their declared retention.

Use D1 primary reads for session authentication and role checks. The `sessions` table
stores token hash, account ID, device ID, created time, expiry, last refresh, and revoked
time. Apply the 30-day sliding and 90-day absolute limits from Section 5.4. Deletion and
new-device login revoke prior sessions in the same D1 batch as the account/device
transition.

Inference idempotency rows store the request hash, state, terminal code, and expiry,
never response bytes, transcript text, or output-derived hashes. A duplicate key cannot
dispatch a second inference. A retry of a successfully completed request returns
`result_unavailable`; a retry of a terminal failure returns its stored terminal code.
This is the explicit privacy-over-recovery tradeoff for ordinary Communicate. Task
submissions may replay their non-transcript response from the authoritative task row.

Every queue consumer is idempotent because Cloudflare Queues can deliver a message more
than once. The message ID is a database uniqueness key, and a duplicate consumer run
must produce the prior terminal result.

Queue bodies contain only a schema version, opaque job ULID, and operation enum. They
contain no account ID, object key, URL, script, reconstruction, transcript, or model
output. The consumer loads authorized work from D1 by job ID and rechecks current
consent, purpose, and deletion state before touching another store.

After E4 verifies a clip, the API opens it through the narrow R2 adapter and streams the
exact bytes to `POST /internal/inferences`. The internal request body is
`video/mp4`, bounded at 12 MiB while streaming, with `Content-Length`,
`X-Video-SHA256`, `X-Model-ID`, and `X-Request-ID`. It uses a distinct rotatable service
credential over HTTPS. The runtime verifies length and digest before inference. No R2
object key, presigned URL, account/task identifier, prompt, or capability decision
crosses this boundary. The response contains transcript, inference milliseconds, and
optional internal diagnostics under the public output bounds. The API remains the only
component that applies release scope and capability labels.

### 7.3 Fixture inference

The fixture runtime exists only in Debug and Staging. It declares:

```json
{
  "id": "fixture/hash-map-v1",
  "release_scope": "internal_evaluation",
  "capability_label": "technical_prototype",
  "runtime": "fixture",
  "fixture_set_sha256": "..."
}
```

It maps the SHA-256 of a checked-in rights-cleared fixture clip to a checked-in result.
An unknown digest returns `model_unavailable`; it never guesses or returns generic text.
Production configuration rejects `runtime=fixture` at startup.

### 7.4 Real model handoff

A real model is not selected by an implementation agent. Before integration, the owner
provides a signed-off manifest containing model source, exact revision, weight digest,
license and use determination, preprocessing, prompt, decoding settings, expected
hardware, approved release scope, network/auth boundary, temporary-file behavior, and
provider request-log and retention settings. The runtime must then pass:

- exact request/response contract tests;
- startup hash verification and fixture self-test;
- invalid-media and output-bound tests;
- concurrency, overload, timeout, and warming tests;
- the measured CPU benchmark; use GPU when warm end-to-end p95 exceeds 12 seconds or
  inference p95 exceeds 6 seconds on the declared CPU class;
- the model-readiness gate before any external account can receive output.

## 8. Work packages

An agent executes packages in dependency order. Each package ends with a runnable or
verifiable state. A package is incomplete if its tests or named artifacts are missing.

### E0: Contract and scaffold

Depends on: none.

Create the repository layout, toolchain pins, OpenAPI skeleton, XcodeGen project,
Cargo workspace additions, gateway package, and verification scripts.

Required checks:

- OpenAPI validates and has one example for every response status;
- XcodeGen produces the project without a dirty diff on a second run;
- empty iOS app builds and launches in the pinned simulator;
- Rust and Worker health handlers pass local tests;
- `scripts/check-mobile.sh` runs from the repository root.

### E1: Shared domain and contract fixtures

Depends on: E0.

Implement ULIDs, RFC 3339 handling, RFC 8785 config hashing, capability labels, error
codes, upload purposes, task enums, idempotency records, and fixture serialization.
Generate the Swift API client. Add cross-language JSON fixtures that Rust and Swift
both decode and re-encode.

Exit test: every fixture round-trips canonically, unknown required enum values fail,
and the OpenAPI diff check is clean.

### E2: Gateway and Cloudflare adapters

Depends on: E0, E1.

Implement request IDs, body/header bounds, coarse rate limiting, container routing,
and private outbound handlers for D1, R2, Queues, and KV config. Add local Miniflare or
equivalent integration tests with isolated bindings. Document resource names for local,
staging, and production without placing account IDs in the public contract.

Exit test: public requests cannot reach internal handlers, over-limit requests never
reach the container, and binding operations reject unknown schemas.

### E3: Authentication and session lifecycle

Depends on: E1, E2.

Implement challenge issuance, Apple-token verification, new-key attestation,
returning-key assertion and counter checks, session issuance, refresh, logout,
new-device supersession, account-role checks, and the session token buckets in Section
5.1. Build deterministic cryptographic fixtures for valid, replayed, expired, wrong-app,
wrong-environment, and regressed-counter cases.

Exit test: revocation is visible on the next primary D1 read; no KV session read exists;
the production build has no bypass route.

### I0: iOS shell and test doubles

Depends on: E0, E1.

Implement launch routing, tab shell, design tokens, String Catalog, privacy cover,
generated client wiring, and injected fake providers. Add UI launch arguments for each
auth/config state.

Exit test: UI tests reach sign-in, update-required, unsupported, and main-tab states
without network or Apple services.

### I1: iOS authentication

Depends on: E3, I0.

Implement Keychain storage, Sign in with Apple nonce flow, App Attest key registration,
returning assertions, reinstall recovery, logout, and 401 handling. Keep platform calls
behind protocols.

Exit test: unit tests cover every auth state; one physical staging device completes new
key, returning key, logout, and reinstall flows before TestFlight packaging.

### E4: Media reservation and validation

Depends on: E1, E2, E3.

Implement upload reservation, presigned PUT requirements, ownership, digest/size
verification, demux validation, upload state transitions, inline deletion, and hourly
sweep. Add valid H.264 portrait/landscape fixtures plus malformed, oversized, wrong-hash,
audio-track, and truncated fixtures.

Run media tools with fixed arguments, no shell interpolation, a wall timeout, a child
process limit, and container CPU/memory limits. Kill the process group on timeout and
record only the stable reason code. The deployment manifest, not application code,
enforces the child RSS ceiling.

`ffprobe` emits JSON for format, streams, side data, and tags. Accept exactly one H.264
video stream, no other stream, and only a 0, 90, 180, or 270 degree orientation. A full
`ffmpeg` decode counts frames and must reach EOF. Compute measured frame rate as the
exact rational `decoded_frame_count / presentation_duration`; apply the orientation
once before checking long and short edges. Reject location, author, device make/model,
title, comment, or unexpected free-text metadata. The app writes no such metadata, and
rights-cleared fixtures cover every accepted orientation.

Exit test: all invalid fixtures are rejected under a fixed timeout with no residual R2
object; successful and failed Communicate objects meet the deletion rules.

### I2: Capture, review, and file lifecycle

Depends on: I0.

Implement permission states, camera preview, adaptive framing guide, H.264 recording,
countdown, playback, retry, discard, protection attributes, backup exclusion, and launch
cleanup. The simulator uses an injected fixture capture source.

Exit test: unit and UI tests cover permission denial, early stop, hard stop, retry,
discard, orientation metadata, cleanup, and accessibility focus. A physical-device test
confirms the produced file passes E4 validation.

### E5: Inference orchestration and fixture runtime

Depends on: E3, E4.

Implement model registry checks, fixture runtime, readiness, bounded concurrency,
warming, overload, timeout, duplicate-dispatch suppression, the
`result_unavailable` privacy path, object cleanup on success, and telemetry redaction.

Exit test: the ten checked-in fixture clips complete 100 attempts with schema-valid
declared output; unknown clips and unloaded models return typed failures without
placeholder text.

### I3: Communicate networking and result flow

Depends on: I1, I2, E4, E5.

Implement upload reservation, foreground PUT, inference, warming recovery, result list,
manual Clear, capability label, optional TTS, and stable error recovery. Add a custom
URL protocol or transport fake for every response case.

Exit test: the complete simulator fixture path passes 20 consecutive UI runs; local
files and in-memory results follow the stated lifecycle after success, failure, clear,
logout, background snapshot, and process relaunch.

### I4: Reply and accessibility pass

Depends on: I3.

Implement just-in-time microphone and speech permissions, on-device recognition,
typed fallback, Reduce Motion behavior, VoiceOver focus transitions, Dynamic Type, and
contrast checks.

Exit test: automated accessibility audits pass on every screen and at the largest text
size; physical-device tests cover supported and unsupported on-device speech.

### E6: Contribution domain and APIs

Depends on: E3, E4.

Implement consent grant/withdrawal, one prioritized next task, Task A submission, Task B
review, expiry/reassignment, consensus, anchors, holds, deletion propagation, and admin
CLI operations. Use the current top-50 curriculum only after its content file is approved;
fixtures use a five-item internal curriculum.

Exit test: property tests cover deterministic consensus and assignment exclusions;
withdrawal immediately stops issuance and queues deletion.

### I5: Contribution UI and offline queue

Depends on: I1, I2, E6.

Implement consent, the single next-task screen, Task A capture, Task B playback and
reconstruction, queue capacity, protected persistence, background uploads, retries,
expiry, cancellation, and withdrawal cleanup.

Exit test: relaunch and background-session reconciliation lose no accepted queue item;
expired, cancelled, withdrawn, and deleted items leave no file or system upload task.

### E7: Account deletion and operational checks

Depends on: E3 through E5 and I3.

Implement the deletion job, status bearer secret, retries, audit record, storage purge, and
dead-link checks. The iOS app separately purges its session token, App Attest key identifier,
temporary clips, and in-memory results when deletion starts. E6 and I5 extend the
same deletion walk to contribution objects, review rows, queue files, and derived
artifacts before the Contribution build gate runs.

Before calling `DELETE /v1/me`, the app generates a 32-byte random status secret and
stores it in a separate `AfterFirstUnlockThisDeviceOnly` Keychain item. The request
sends it once as the `Deletion-Status-Token` header; the server stores only its SHA-256.
The app keeps the secret until the server reports complete or the user explicitly
clears status tracking. It never places it in a URL, log, notification, pasteboard, or
analytics field. The server accepts it for 45 days from job creation, covering the
30-day deletion deadline, and permits repeated status reads until then. It then removes
the token hash. A lost deletion response does not lose status access because the app
persisted the secret before the request.

The local transition is `confirm -> persist secret -> send deletion -> accepted`.
On `202`, or when an ambiguous transport failure is followed by a successful status
read, the app cancels transfers and clears every local account artifact except the
status secret. If status returns `not_found` and the session is still usable, it retries
the same deletion idempotency key and secret. It never reports deletion as accepted
from a transport error alone.

Exit test: server integration tests prove server-layer deletion; iOS tests prove local
deletion. No test claims the server can erase an iPhone file.

### E8: Staging and internal TestFlight

Depends on: E0 through E5, E7, I0 through I4, and owner-provided Apple/Cloudflare
access.

Deploy isolated staging resources, run migrations, configure entitlements, archive the
StagingTestFlight app, and produce a release record with exact commits, image digests, OpenAPI hash,
model manifest, app version, config snapshot, and test output. The operator performs
the first TestFlight upload after reviewing the archive and privacy report.

Exit test: D1, D2, and D3 pass on a physical iPhone using an eligible declared model.
The fixture model may establish the connection path but cannot satisfy a translation
quality claim.

- **D1:** the archived TestFlight build installs and launches for an authorized tester.
- **D2:** public `/healthz` succeeds and an authenticated `/v1/inferences` call returns
  the declared model's schema-valid output.
- **D3:** a recorded physical-device session captures signing in the TestFlight build
  and displays an output produced by the live backend and declared model.

### E9: Pilot evidence mode

Depends on: E8, R1, R2, and an approved pilot protocol.

Add a separate `pilot_evaluation` upload purpose, pilot consent version, participant
code, task record, output record, reviewer access, retention job, withdrawal path, and
aggregate export. An ordinary Communicate upload can never be copied into this store.
The participant confirms pilot use before each task upload. Implement the server-gated
participant task, output, and rating screens and the permission-gated reviewer queue in
`BitsignPilot`. The reviewer screen plays the assigned source clip, shows only the
approved comparison material, and submits the frozen rubric. It writes no clip or
transcript to logs, notifications, or app-created snapshots and uses the scene privacy
cover. iOS cannot prevent a reviewer from taking a system screenshot; the reviewer
agreement prohibits it and the residual limitation is stated in the protocol.

Pilot uploads are foreground-only and have no offline queue. A protected local clip is
deleted when the upload is accepted, the task is declined or cancelled, consent is
withdrawn, the account changes, or launch cleanup finds no live pilot task. Downloaded
review clips use the same protection and backup exclusion and are deleted on submission,
expiry, permission revocation, or launch cleanup.

Exit test: access-role, purpose-isolation, withdrawal, retention, and aggregate-export
tests pass, and UI tests prove the participant and reviewer tabs cannot appear for any
other authorization. R3 through R5 then run against this exact candidate build. No
pilot recruitment or session begins from code completion alone.

## 9. Verification matrix

| Requirement | Automated evidence | Physical/manual evidence |
|---|---|---|
| API compatibility | OpenAPI validation and Swift/Rust fixture round trips | None |
| Auth replay resistance | Apple/App Attest fixture suite | New, returning, and reinstalled device |
| Media bounds | Demux fixture suite | One clip from the oldest-OS and pilot device classes |
| Communicate lifecycle | filesystem, R2, state-machine tests | Cancel, retry, scene-inactive, and force-quit walkthrough |
| No transcript persistence | schema assertion and log scan | app-switcher privacy inspection |
| Contribution recovery | background queue integration tests | lock, suspend, reconnect, and relaunch walkthrough |
| Accessibility | XCUITest accessibility audits and snapshots | VoiceOver and largest-Dynamic-Type review |
| Reliability | 100-run fixed-clip harness | 20 consecutive scripted app flows |
| Performance | signposted app timings plus server timings | LTE-profile run on the declared iPhone |
| Deletion | server purge test and iOS local purge test | dead presigned URL and status-link check |
| Serving policy | role/release-scope matrix tests | external account cannot access internal model |
| Pilot isolation | purpose and role tests | consent and withdrawal walkthrough |

All release evidence records the device, OS, app build, network profile, API commit,
OpenAPI hash, model manifest, config hash, warm-state definition, and percentile method.

## 10. CI and local commands

The scaffold must make these commands real. Until then, a package that names one is
not complete.

```bash
./scripts/check-mobile-toolchains.sh
./scripts/verify-openapi.sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix services/gateway ci
npm --prefix services/gateway test
npm --prefix services/gateway run check
xcodegen generate --spec apps/ios/project.yml
./scripts/ios-test.sh
./scripts/check-mobile.sh
```

`ios-test.sh` uses the Xcode 26.6 iOS 26.5 simulator runtime pinned by CI. It runs unit
and UI tests with code coverage and stores `.xcresult` as an artifact. Signing-dependent,
camera-device, App Attest, Speech, performance, and TestFlight checks are separate named
manual gates. CI must not hide their absence by marking them skipped and green.

CI has two required jobs. `contracts-backend` runs on Linux with pinned Rust and Node
toolchains; `ios` runs on macOS, selects Xcode build 17F113, asserts the iOS 26.5
runtime, regenerates the project, and runs simulator tests. Upload OpenAPI reports,
JUnit output, coverage, and `.xcresult` on failure and on protected release runs. Pull
request jobs have no Apple, Cloudflare, signing, or deployment credentials. Staging,
TestFlight, and production are manual protected environments, never branch-push side
effects.

## 11. Release gates and stop rules

The pilot gate identifiers are fixed here and detailed in `pilot-plan.tex`. R1 and R2
authorize construction of the candidate pilot mode; R3 through R5 certify the exact
candidate build after E9:

| Gate | Required evidence |
|---|---|
| R1, community readiness | At least three Deaf ASL signers approve the use case, scope list, rubric, pilot tasks, public claims, and stop conditions; every material concern has a recorded resolution. |
| R2, model readiness | Evaluation consent, provenance, and deployment eligibility are recorded; the frozen evaluation passes and assigns one capability label. |
| R3, end-to-end system | D3 passes with the pilot candidate build, live service, and declared model. |
| R4, performance | Twenty consecutive scripted flows are crash-free; at least 95 of 100 warm attempts over ten fixed clips succeed; end-to-end p95 is at most 12 seconds; invalid inputs return stable errors. |
| R5, trust, security, and accessibility | Access, transport, resource and output bounds, deletion, VoiceOver, Dynamic Type, visible limitations, and separation of research consent from communication use all pass their named tests. |

Evidence is version-bound to the app build, API and model manifests, OpenAPI and
configuration hashes, device/OS, and test corpus. A change to a bound input invalidates
the affected gate and requires it to run again.

### Internal vertical slice

Required: E0 through E5, E7, E8, I0 through I4, engineering gates, no production
bypass, and an internal model manifest. Result copy must say `technical_prototype`
unless a stronger label has passed the frozen evaluation.

### Contribution build

Required: E6, I5, the E7 contribution-deletion extension, approved consent text,
approved curriculum file, named data-access roles, retention configuration, and a
deletion drill.

### Closed pilot

Required: E9, R1 through R5, a pilot-eligible capability label, approved study protocol,
named reviewers and incident responders, frozen scope/tasks/rubric, and an owner-approved
TestFlight group. A code-complete app does not authorize recruitment.

Pause execution and request owner input when a task would:

- select or license a real model;
- change a public capability claim or safety boundary;
- collect or retain a new data class;
- change consent, retention, withdrawal, or deletion behavior;
- create, modify, deploy, or delete external infrastructure;
- upload a build or invite a tester;
- publish participant or evaluation results.

An implementation detail within the contracts above does not require another product
decision. Record it in an architecture decision record when it changes a dependency,
schema, trust boundary, or deployment topology.

## 12. Pilot evidence protocol

Pilot review needs source clips and exact returned outputs. It therefore uses a data
class separate from ordinary Communicate and from training contributions.

- Enrollment consent covers three pilot tasks, reviewer access, incident review,
  withdrawal, publication of aggregate results, and the retention schedule.
- Before each upload, the participant confirms that the reviewed clip may enter the
  pilot evidence store. Declining skips that task without converting the clip to an
  ordinary or contribution upload.
- Pilot capture and upload are foreground-only. The app has no pilot offline queue and
  deletes its protected local file at the lifecycle points defined in E9.
- `purpose=pilot_evaluation` selects a dedicated private R2 bucket. Objects cannot move
  to the Communicate or Contribute buckets.
- The restricted record stores participant code, task ID, clip digest, object key,
  exact model output, model/config versions, ratings, reviewer results, and timestamps.
- Raw clips and linked outputs are deleted by the earlier of 30 days after final
  adjudication and 45 days after upload. Linked ratings are deleted on withdrawal and
  otherwise by the earlier of 90 days after the final session and 120 days after
  collection. Aggregate, de-identified counts may remain in the report.
- Pilot evidence is excluded from training and the frozen model evaluation.
- Two named Deaf ASL-fluent reviewers receive time-limited access. Access is audited.
- Reviewer terms prohibit screenshots, and participant consent names the residual risk
  that iOS cannot technically prevent a reviewer from taking one.
- Pilot access audits contain actor ID, object or review ID, time, action, and outcome,
  but no clip or transcript content. Retain them through the later of 90 days after the
  final session and closure of a related incident, subject to an absolute 365-day cap
  from each event; withdrawal does not erase the minimal security audit, as the consent
  must state.
- A retention miss, unauthorized access, or loss of withdrawal control pauses the pilot.

This protocol must be reflected in the pilot consent and reviewed under R1 before E9
begins. The implementation agent must not derive consent copy from this engineering
summary.

## 13. External inputs that remain intentionally open

These are owner or community inputs, not choices for an implementation agent:

| Input | Blocks | Required artifact |
|---|---|---|
| Apple team and App Store access | E8 | confirmed team ID, bundle ID, entitlements, signing method |
| Cloudflare account and domains | E8 | staging/prod resource inventory and operator access |
| Physical iPhone matrix | I1, I2, I4, and R3 through R5 | one iPhone on iOS 17.x and one on the intended pilot OS/device class, or an owner-approved higher deployment target |
| Reference model | D2/D3 and release gate R2 | signed-off model manifest and rights determination |
| Top-50 curriculum | E6 production seed | versioned script/alias file approved through the community process |
| Capability copy and scope list | external build | versioned R1-approved copy and scope artifacts |
| Consent documents | Contribution and E9 | signed-off versioned documents and retention/access schedule |
| Reviewer and tester lists | physical gates and pilot | named restricted records, not source-controlled identities |
| Wordmark assets | final visual polish | approved asset files; text fallback is `bitsign` |

If an input is absent, the agent continues with fixtures until the first blocked package
and reports the exact missing artifact. It must not invent a model license, participant
consent, identity, or external credential.

## 14. Handoff checklist

Before handing a package to the next agent:

- run the package checks and `scripts/check-mobile.sh` when available;
- update OpenAPI, migrations, fixtures, and this plan when behavior changed;
- include no secret, participant identity, presigned URL, media, transcript, or task
  plaintext in logs, snapshots, fixtures, or commits;
- state which physical or external gates remain unrun;
- keep the worktree diff limited to the package or explain overlaps;
- commit locally only after checks pass;
- do not push, deploy, upload, invite, or publish without explicit owner approval.

## 15. Platform references

- [Apple App Attest client flow](https://developer.apple.com/documentation/DeviceCheck/establishing-your-app-s-integrity)
- [Apple App Attest server validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [Sign in with Apple authentication](https://developer.apple.com/documentation/authenticationservices/implementing-user-authentication-with-sign-in-with-apple)
- [Background URLSession](https://developer.apple.com/documentation/foundation/urlsessionconfiguration/background(withidentifier:))
- [On-device speech support](https://developer.apple.com/documentation/speech/sfspeechrecognizer/supportsondevicerecognition)
- [Apple privacy manifests](https://developer.apple.com/documentation/bundleresources/privacy-manifest-files)
- [Swift OpenAPI Generator](https://github.com/apple/swift-openapi-generator)
- [Cloudflare Container binding access](https://developers.cloudflare.com/containers/configuration/workers-connections/)
- [Cloudflare KV consistency](https://developers.cloudflare.com/kv/concepts/how-kv-works/)
- [Cloudflare R2 presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/)
- [Cloudflare Queues delivery guarantees](https://developers.cloudflare.com/queues/reference/delivery-guarantees/)
