[Documentation](../README.md) / Current miner connection guide

# Current miner connection guide

The competition uses a recoverable cohort runtime: phase blocks are operating targets, and
coordinator or validator downtime delays unfinished work instead of expiring the
cohort. Check [live status](https://api.umi.vision/v1/competition/status) and
[readiness](https://api.umi.vision/v1/competition/readiness) for the current
phase and admission state before signing or diagnosing a submission. Send a new
submission only when `admission_accepting_new` is true.

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

## Upgrade an existing miner

Linux miners managed by systemd use one updater. Choose only whether
you intend to participate in the public-model track:

```sh
curl -fsSLo /tmp/umi-miner-upgrade.py \
  https://raw.githubusercontent.com/Umi-BitSign/umi/main/deploy/miner-upgrade/upgrade.py \
  && sudo python3 /tmp/umi-miner-upgrade.py --public-model-track no
```

Use `yes` instead of `no` for public-model participation. The active signed
manifest decides which answers are allowed, and the updater stops before changing
the service if the selected track is unavailable. When endpoint participation is
allowed, the updater signs and retains the endpoint request with the running
miner hotkey, submits it to the active cohort, and checks its admission
certificate. `yes` also records public-model intent; it does not assert model
rights or upload a bundle. A model submission still needs its own signed consent,
rights decision and complete artifact.

The updater discovers the one running `umi.miner` systemd service and retains its
hotkey, model revision, serving origin, wallet, model backend and public port. It
keeps the existing service account, including an existing root-run installation.
It inspects the installed startup schema and authority before choosing a migration.
For a runtime update under the same cohort authority, it retains the exact startup
bytes, grant directory, nonce database, assignment database and finality database
in place, including custom paths. Relative paths keep the service's existing
working directory. The updater does not copy a directory-bound grant journal or
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
the miner service user before switching services. A missing compatible Python or
failed runtime check stops the upgrade while the existing miner remains selected.

The runtime installs beside the old runtime, with its directory bound to both
the source revision and scoring profile. The private state namespace remains
bound to the current transport policy. Nonce, assignment,
finality, grant and model-sidecar state from earlier policies remain intact.

Rerunning the command installs a changed runtime even within the same cohort.
An existing receipt skips cutover only when its revision and the running miner's
interpreter match the selected deployment and scoring profile. An older runtime
launch without isolated Python imports also requires cutover, even if its receipt
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
and the resolved startup allowance for subsequent boots. If interrupted during
drain, the temporary protection stays in place until the service settles; rerun
the updater to complete the upgrade. Existing grants, responses and state paths
remain in place.
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

If a signed manifest offers only public-model participation, the updater rejects
`no`, records model-track intent, and leaves the existing endpoint service
unchanged as a recoverable prior deployment. The model submission still requires
the operator's signed rights declaration and selected bundle. Signed manifests,
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
