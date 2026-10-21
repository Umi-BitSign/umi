[Documentation](../README.md) / Current miner connection guide

# Current miner connection guide

The competition uses a recoverable cohort runtime: phase blocks are operating targets, and
coordinator or validator downtime delays unfinished work instead of expiring the
cohort. Check [live status](https://api.umi.vision/v1/competition/status) and
the target cohort’s `/v1/competition/cohorts/{cohort_sha256}/readiness` route
with a fresh 32-character lowercase hexadecimal `nonce` before signing or
diagnosing a submission. The global `admission_accepting_new` flag does not
establish that a particular cohort is open. A cohort readiness response is an
operational observation, not a reservation or admission certificate.

The [request-window recovery contract](../competition/transport-cadence.md)
explains retained attempts and the new linked-deadline extension. That extension
requires compatible selected coordinator and miner releases. Publishing its
source alone does not enable new request windows. Do not delete grant, request,
response or retirement state to upgrade or recover delayed work. Completed
requests release their active-window resource slot only after a verified signed
retirement receipt is committed. Their counters, response archive and execution
fence remain retained; pending work continues to occupy its slot.

The coordinator recovers saved responses and retires answered peer cases before
dispatching another case from the same assignment. If that retirement cannot be
acknowledged, further work remains pending. A retryable HTTP 429 or 503 without a
valid signed response is an unresolved delivery attempt, not a zero-quality
answer. Preserve the existing request and response state while recovery retries;
do not raise the window limit or reset the miner to bypass a held retirement.

The previous certified allocation remains effective until the active cohort
produces a certified successor row. Acceptance under an earlier policy does not
accept the current policy or terms. Participants must retain the acceptance
receipt for the active policy. Registration, acceptance, selection, scoring and
reward activation are separate events.

## Change an endpoint model revision

A cohort that still allows the endpoint track can retain a replacement while its
intake remains unsealed. The new signed submission needs a higher sequence for
the same hotkey and track, a new `model_revision` for changed inference artifacts,
and the policy’s minimum submission interval since the previous retained
observation. Sign separate participation consent for each target cohort. Retry an
unchanged request using its original signed bytes; do not generate another
revision or sequence to recover a lost acknowledgement.

The intake seal selects the highest retained sequence even if its admission
certificate is still pending. Preparation waits for that selected certificate;
it does not fall back to an older certified entry. The selected replacement can
still receive its certificate after intake seals. Neither global nor cohort
readiness promises enough time for certification before the seal. Check the
exact replacement after submission:

```sh
umi-competition --policy policy.json query-cohort-admission \
  --origin https://api.umi.vision --request replacement-participation.json
```

The read-only participation-status route exposes the latest retained sequence
and its certificate together:

```text
GET /v1/competition/cohorts/{cohort_sha256}/participation-status/{hotkey}?track=endpoint&nonce={fresh_32_hex}&consent={consent_sha256}
```

`consent` is optional. With it, `requested_consent_status` distinguishes `latest`,
`superseded` and `not_retained`; `latest.admission.status` describes the newest
entry even while an older one remains certified. `minimum_next_sequence` and
`submission_not_before_block` are lower bounds, not permission to submit:
registration, track eligibility, readiness, capacity and the seal still apply.
A `null` minimum sequence means the sequence range is exhausted. Check `phase`
as well as `intake_fenced`; a closed phase blocks new participation even without
a fence at its current tip. This advisory response does not verify the seal’s
selected roster (`sealed_selection_verified: false`) or authorize a runtime
migration (`runtime_migration_authorized: false`). Older servers may not yet
provide the route; HTTP 404 is not evidence that no participation exists.

An `admission_certified` response authenticates that participation; it does not
prove it remains the newest entry or authorize changing the running model. The
current updater supports selected runtime upgrades while preserving the installed
revision, authority, service account and state paths. It does not provide a
model-revision rollover or a general migration for custom multi-cohort rosters;
unsupported authority layouts refuse before changes. The grant journal binds
the revision and complete roster, so editing either,
removing a closed cohort, or substituting an empty grant directory is not a
supported in-place upgrade. Preserve the original configuration, grants, requests,
responses and retirement receipts. Qualify an explicit transition for the actual
installed startup layout and any remaining old-revision obligations before
switching the endpoint; cohort closure alone does not release retained state.

Paid-work claims also bind the original `submission_sha256`. A replacement
participation does not move an accepted claim or its assigned work to the new
revision. A retained but unaccepted claim still names the old submission; changing
its fields while reusing its nonce is not a retry. Inventory the authoritative
claim/admission state and all outstanding old-revision work across the configured
cohorts before selecting a transition. Exact cached response recovery and grant
or retirement replay are separate paths; the latter still require the original
grant authority even after the response has been retired. Preserve signed bytes
and journal bindings rather than rewriting them or starting an empty journal.

A transition must inspect the effective startup command, account, state paths,
systemd drop-ins or container mounts, and model-service dependencies. Drain the
miner before changing its sidecar/backend. `KillMode=mixed` with a finite
`TimeoutStopSec` can still force-kill remaining processes unless the effective
settings disable that. The supported runtime updater uses an infinite stop
timeout and `SendSIGKILL=no`; those settings alone do not authorize a revision
migration. A container needs equivalent signal forwarding, restart control,
confirmed process-tree drainage and exclusive ownership of the original mounted
state. Preserve old model assets until their retained obligations are released.

Endpoint participation does not require the unmodified baseline. A fine-tuned
model must declare its own revision and meet the applicable provenance, license,
resource and execution rules. See [model revision](model.md#model-revision) for
which artifacts define a revision. Public-model admission does not replace
endpoint admission or paid-work checks.

### Inspect retained obligations before selecting a transition

The Linux `umi-miner-revision-preflight --request /absolute/preflight.json`
command inspects an already stopped miner under its original service UID. It
acquires the existing grant and assignment locks without creating or migrating
original state. It accepts clean rollback databases or fully checkpointed WAL
main files with no remaining sidecars. An active owner, missing lock, retained
WAL/journal, changed source file or unsupported layout refuses the inspection;
the command does not stop services or repair original databases.

The request schema is `umi-miner-revision-preflight-request/1`. Supply the exact
`original_argv` and `proposed_argv` arrays, `service_uid`, `launch_kind` (`systemd`
or `container`), `enrollments` entries containing `cohort_sha256` and absolute
`directory`, and a private `verification_directory` separate from all original
state. Optional `maximum_inventory_items` (default 65,536) and
`maximum_summary_bytes` (default 64 MiB) bound inventories and serialized summaries;
exceeding either reports an explicit refusal, without changing cohort policy or
execution limits. Both commands must retain the original options except the model revision
and proposed startup file. The proposed startup retains the entire cohort roster,
authority, paths, terms and limits. Console-script, Python console-script and
`python -m umi.miner` launch forms are recognized; recognizing a command does not
verify its interpreter, installed wallet or container mount identity.

The JSON result reports independently verified grant ancestry, acknowledgment
intents, exact request-index coverage, signed retirements, response archives and
signed paid claims. `known_requests_retired` refers only to the enumerated
retained requests. `local_inventory_complete` reports supplied-directory and
assignment coverage; it does not certify enrollment contents. Unknown or omitted
artifacts remain explicit. A claim without a local grant has unknown remote
admission, not proof that it was rejected. Native assignment-ledger startup
audit, wallet/runtime identity, enrollment authority, current cohort selection
and actual process drainage remain separately unverified gates.

Every result has `runtime_migration_authorized: false`. A stopped-state inventory
cannot fence later grants, move a paid claim, rebind a journal, authorize a backend
switch, or make four independent cohort replacements atomic. Those obligations
need an explicitly qualified transition, with retained old-revision execution
capability wherever native authority has not closed or replaced old work.

Progress on stderr includes counts, elapsed time, stage ETA and its basis. Before
measured samples, the displayed planning range assumes 0.01–30 seconds per bounded
local item; it excludes external checks and runtime migration. Completed grant
and retirement checks persist independently of the source state, allowing restart
without repeating unchanged native checks. Their keys bind original file identity,
policy/startup inputs and qualified verifier semantics; a changed grant database
invalidates its grant checks, and a changed assignment database invalidates its
retirement checks. Missing or damaged completed metadata requires an explicit
`--verification-repair-reason`; successful repair replaces only derived metadata.
Never delete original signed records or substitute an empty verification directory
to conceal a repair requirement.

## Upgrade an existing miner

Linux miners managed by systemd use one updater. Choose only whether
you intend to participate in the public-model track:

```sh
curl -fsSLo /tmp/umi-miner-upgrade.py \
  https://raw.githubusercontent.com/Umi-BitSign/umi/main/deploy/miner-upgrade/upgrade.py \
  && sudo python3 /tmp/umi-miner-upgrade.py --public-model-track no
```

Use `yes` instead of `no` for public-model participation. The published upgrade
manifest decides which answers are allowed, and the updater stops before changing
the service if the selected track is unavailable. When endpoint participation is
allowed, the updater signs and retains the endpoint request with the running
miner hotkey, submits it to the active cohort, and checks its admission
certificate. `yes` also records public-model intent; it does not assert model
rights or upload a bundle. A model submission still needs its own signed consent,
rights decision and complete artifact.

Before changing a Linux endpoint service, the updater installs an owner-checked
needrestart override so package upgrades cannot restart UMI owners outside their
controlled lifecycle. Standard `umi-*.service` units are covered together; a
supported custom miner or sidecar name receives an exact-name override. Existing
administrator content or conflicting needrestart rules refuse the upgrade before
any service stop. Security package updates remain enabled. The standalone public
model client does not change endpoint services or this root-level configuration.

The updater discovers the one running `umi.miner` systemd service and retains its
hotkey, model revision, serving origin, wallet, model backend and public port. It
keeps the existing service account, including an existing root-run installation.
It inspects the installed startup schema and authority before choosing a migration.
For a runtime update under the same cohort authority, it retains the exact startup
bytes, grant directory, nonce database, assignment database and finality database
in place, including custom paths and explicit local grant-count, byte and history
read-timeout settings. A grant directory must be absolute and dedicated; relative
CLI paths keep the service's existing
working directory, including a model sidecar's configuration path. The updater
pins that effective directory in the selected unit, including installations whose
old launcher changed directory before starting Python. It
does not copy a directory-bound grant journal or
change accounts as part of an upgrade. A same-authority cohort runtime update also
retains an explicit `--competition-chain-config`, including its owned observer
state and selected proof-provider budgets.
The selected miner runs with isolated Python imports, so an old checkout in the
working directory or an inherited `PYTHONPATH` or `PYTHONHOME` cannot silently
select the previous source. The working directory still resolves existing data
and configuration paths.
It fetches the current canonical manifest, checks its policy and profile against
the public competition status, and selects that matching deployment's exact
runtime revision. A published maintenance release may name a different exact
runtime revision and bind it to the existing deployment revision. This updates
miner code without replacing the cohort's signed launch, policy, authority or
state bindings; a different deployment or profile is refused before cutover.
It selects the exact root-owned CPython patch version and
scoring package versions required by the signed transport policy for this host.
It checks the installed source, Python, package contents and scoring profile as
the miner service user before switching services. It also uses the selected
runtime's native secure reader and startup schemas under that account and working
directory to check the exact policy, transport and cohort startup files and the
separate grant-directory binding. Generated files remain owned by the service
account inside a root-controlled configuration directory that other users cannot
write. A missing compatible Python or failed runtime check stops the upgrade while
the existing miner remains selected.

The runtime installs beside the old runtime, with its directory bound to both
the source revision and scoring profile. The private state namespace remains
bound to the current transport policy. Nonce, assignment,
finality, grant and model-sidecar state from earlier policies remain intact.

Rerunning the command installs a changed runtime even within the same cohort.
An existing successful upgrade receipt skips cutover only when the running miner
already uses the supported cohort configuration, its revision and interpreter
match the selected deployment and scoring profile, and native startup validation
passes under its retained service account. A legacy miner still requires migration
even if its current interpreter and a stale receipt name the target revision. An
older runtime launch without isolated Python imports also requires cutover, even if its receipt
names the selected revision. An older runtime for the same source revision is
preserved and replaced by the verified policy
profile instead of being reused merely because its revision matches. Retained
enrollment, nonce, assignment and grant state stay in the same namespace.

The updater also handles the standard Unix-socket model sidecar. It binds a new
sidecar socket and capacity descriptor to the current transport policy before
starting the miner. It verifies exact policy, transport, model, finality and
sidecar health. If any check fails, it restores the prior systemd commands and
restarts the previous miner and sidecar. Rerunning the updater is idempotent.

In cohort mode, omitting `--inference-timeout` selects the full inference allowance
from the pinned competition policy. An explicit smaller override remains in force;
the startup `cohort_runtime_limits` report and `/healthz` `effective_limits` show
the selected values. The sidecar must advertise that same inference budget.
The same resolver gives omitted cohort startup and queue-wait timeouts three and
two inference budgets respectively, with minimums of 120 and 60 seconds. Body
reads get 30 seconds; clip fetching gets at least 120 seconds. Explicit startup,
queue and body overrides remain selected and appear in the startup report.
These operational waits do not extend either signed response deadline or change
authentication freshness, transmission counts, or the active-window limit.
The updater adjusts supported community-model sidecars using the selected runtime's
resolved inference allowance and preserves prior configuration and commands for rollback.
Startup observation uses twice that runtime's effective
backend lifecycle budget, allowing a complete startup plus observation headroom;
it returns as soon as health is ready. Health confirms the observer is running,
not that a fresh chain proof has already been collected. Existing signed clocks
and proof freshness checks still apply to requests. The updater retains the
resolved budgets in its receipt. Before stopping an installed miner, it verifies
cooperative service shutdown settings and waits for the miner to drain before
stopping its model service. There is no separate five-minute stop-command cutoff
or systemd forced-kill timer. The selected service retains cooperative shutdown
and the resolved startup allowance for subsequent boots. Before its first stop,
the updater durably records the selected manifest, original service accounts and
working directories, exact command and startup input hashes, and original unit
overrides and control files. An interrupted run can therefore resume even while the miner or
sidecar is stopped. Rerun the same upgrade: it validates those bindings before
service changes, retains the cooperative drain protection, and adopts an already
selected healthy runtime without restarting it. Once the successful cutover
receipt is durable, retries only resume enrollment. A changed manifest, account,
working directory, command, startup input or unrelated unit override is refused;
preserve the recovery record and resolve that mismatch without resetting state.
Existing grants, signed requests, responses and state paths remain in place.
Only one endpoint upgrade or recovery can run at a time.

The updater writes structured progress to stderr at each stage change and every
30 seconds while waiting. It reports completed-stage percentage, total and stage
elapsed time, recovery attempt, and ETA. The percentage counts stages rather than
bytes or inference work. A first run gives a low-confidence planning range,
assuming available network/package mirrors, no prolonged active-work drain and no
additional retries. The activation range reflects the selected runtime's startup
and inference budgets. Comparable completed-stage timings supersede the planning
estimate on later runs, including recovery. A stage that exceeds its estimate is
reported as waiting beyond estimate with an unknown ETA; a recovery attempt is
explicitly marked as retrying. These observations do not add an execution deadline.
A disconnected progress stream does not abort the upgrade. The successful receipt retains
the stage timings; the final result remains a JSON object on stdout.
An unsupported sidecar layout stops the upgrade before services change. Check any
external proxy's request timeout as well: a healthy `/healthz` alone does not prove
that the proxy can carry a full-length translation.

The current runtime shares concurrent RPC reads for the same exact block hash
and retains them in a bounded cache. Current-head reads remain fresh; cached
storage still requires proof verification. A retryable authority rejection does
not establish that an RPC quota was exceeded. If it persists, the miner logs
`miner_admission_failure report=` with bounded native cause codes for translate,
grant or background failures. Those reports omit exception messages, request
contents and provider URLs. Include those selected lines when reporting a hold;
keep the existing enrollment and assignment state.

Endpoint enrollment and service-work admission are durable phases, so a temporary
coordinator or finality outage does not roll back a healthy miner upgrade. Before
each first send, the updater stores the exact signed participation request and
service-work claim under the current private policy state. A systemd timer retries
the same bytes every 15 minutes and after reboot until it retains both the quorum
endpoint certificate and the service-work admission. The command may therefore
finish with `endpoint_enrollment_retry_scheduled`,
`endpoint_enrollment_pending_attestation`, or
`service_work_claim_retry_scheduled`; none requires a new signature or manual
renewal. `endpoint_enrollment_and_service_claim_certified` confirms that the
endpoint is admitted and has an assigned service-work slot. It does not promise a
score or reward before the work is completed and the cohort settles.

The coordinator recovers an unchanged accepted claim from its retained admission
and complete proof archive without waiting behind new claims collecting chain
evidence. An older admission missing its proof archive remains pending until the
coordinator repairs that archive. Keep retrying the original claim; do not sign
a replacement to work around a temporary hold.

The updater installs itself at `/usr/local/libexec/umi-miner-upgrade`. Use that
same installed file for later cohorts; the current manifest supplies the active
cohort's inputs and allowed tracks:

```sh
sudo /usr/local/libexec/umi-miner-upgrade --public-model-track yes
```

If the published manifest offers only public-model participation, the updater rejects
`no`, records model-track intent, and leaves the existing endpoint service
unchanged as a recoverable prior deployment. The model submission still requires
the operator's signed rights declaration and selected bundle. Recording intent
does not install or update the model submission command: use the separate
[model client installation](#install-or-update-the-model-submission-client) below.
Published manifests,
rather than cohort numbers baked into the script, enforce the profile published
before intake. No cohort-specific replacement script is needed.

The automatic path stops before service changes when it finds an unsupported
transition or ambiguous deployment, including multiple miner services, an unknown
startup schema or authority transition, a non-systemd sidecar or an unrecognized
entry point. A custom state directory or existing root account alone does not
require a manual upgrade. Do not create fresh protocol state, relocate grants or
reset an existing installation to get past a refused migration. Container and
other unsupported service layouts need a qualified migration using the same
[current upgrade manifest](../../deploy/miner-upgrade/current.json), with the
existing deployment and journals preserved until the replacement passes the
health contract below.

The public TLS edge must proxy `POST /v1/translate`,
`POST /v1/competition/cohorts/assignments`, the response-recovery route, and the
retirement route without changing paths, bodies or authentication headers. A
static edge `/healthz` response does not prove those routes work.

The assignment route carries the complete signed grant and accepts bodies up to
**16 MiB**. Give that route the same allowance at every reverse proxy or tunnel;
a generic 64-KiB JSON limit is too small for grants. Translation, response
recovery and retirement keep their selected transport-policy limits. An HTTP 413
on grant delivery leaves the assignment pending. Check the receiving process and
edge body limits before rebuilding the miner or creating new enrollment state.
For nginx, set `client_max_body_size 16m;` in the existing assignment-route
location, retaining its proxy settings. A smaller location-level value overrides
a server-level allowance. Validate and reload with
`sudo nginx -t && sudo systemctl reload nginx`; the miner and its state can stay
in place.

## Install or update the model submission client

Model contributors can install the submission CLI separately from any endpoint
miner. This path supports Linux and macOS with Python 3.10 through 3.14, Git,
Python's `venv`/pip support and access to GitHub and PyPI. Run it as the existing
account that owns the submission wallet. An existing root-owned wallet can keep
its root account; do not move wallets or switch accounts to install this client:

```sh
(
  umi_client_installer="$(mktemp "${TMPDIR:-/tmp}/umi-model-client.XXXXXX")" || exit
  trap 'rm -f "$umi_client_installer"' EXIT
  curl -fsSLo "$umi_client_installer" \
    https://raw.githubusercontent.com/Umi-BitSign/umi/main/deploy/miner-upgrade/upgrade.py \
    && python3 -I -B "$umi_client_installer" --install-model-client
)
```

The installer verifies the current manifest against public status and requires
the model track to be available. It installs the selected exact source revision
and its locked dependencies in a separate, noneditable virtual environment under
`~/.local/share/umi/model-client`. It verifies the installed source, dependency
lock and submission command before selecting the new command. A maintenance
release can update this client while retaining the live cohort's policy, tracks,
authority and explicit deployment binding.

Use the installed command explicitly, including for consent signing, upload
resume and admission queries:

```sh
"$HOME/.local/share/umi/model-client/umi-model-client" --help
```

The command uses its selected absolute interpreter with isolated Python imports.
An older checkout, activated endpoint environment or inherited `PYTHONPATH`
cannot select a different client. The JSON installation receipt reports the
exact revision, interpreter, command path and source verification. An alternate
location requires `--model-client-directory /absolute/dedicated/path`; the
installer refuses an unrelated existing directory.

Rerun the same installation command for a new published release. Each revision
and Python patch gets its own environment; an unchanged release is checked
without reinstalling its runtime. The old command stays selected if installation
or verification fails. Previously installed releases remain available for
already-running uploads and recovery. Do not remove their directories while a
process uses them. A failed new installation does not erase earlier releases.

This mode does not discover, stop or change an endpoint service. It does not read
wallets, migrate a startup file, change service accounts, move grant or protocol
journals, sign consent or enroll a model. It works alongside an older, manual,
systemd or launchd endpoint installation and on a host without an endpoint. The
Linux endpoint updater remains the supported endpoint migration path; installing
this client does not qualify or perform a macOS endpoint upgrade.

Keep existing signed requests, receipts and model files unchanged when moving to
the new command. Follow [model delivery](model.md#model-files-for-recoverable-cohorts)
with the same request, source, wallet and policy to resume an interrupted upload.
The current client authenticates model-delivery changes from cohort history,
resumes a retained original through its authenticated continuation when required,
and uploads new direct-delivery payloads to R2. It signs additional transport
declarations using the same wallet; do not edit or re-sign the original request.
Admission review follows byte delivery, so an uploaded payload alone does not
mean the model has been admitted.
Direct R2 transfers retry temporary network failures, throttling and expired
capabilities. A connection with no read/write progress for five minutes returns
to that retry loop; this is an inactivity timeout, not a deadline for the whole
model. An interrupted multipart delivery can retransmit parts when rerun with
the same request. A completed, verified payload is reused without uploading it
again. Terminal submission errors show a stable reason code and, when available,
an HTTP status; retain those diagnostics without sharing wallet files or signed
upload URLs.
Always check current intake readiness before creating a new submission.

## Check the running miner

Read `/healthz` directly from the protocol process. Expect:

- `ok: true`, `runtime_mode: competition_no_weight`, and
  `finality_service: running`;
- competition and transport policy digests matching the
  [current upgrade manifest](../../deploy/miner-upgrade/current.json) and live
  status;
- the same model revision and serving origin as the accepted active submission.

No assignments are expected during intake. After roster and request phases open,
the miner retrieves signed cohort history from the public API and durably stores
each grant before inference. An unavailable coordinator or validator causes a
retry; it does not become a miner failure or terminate the cohort. Preserve signed
responses and grant state until certified retirement.
