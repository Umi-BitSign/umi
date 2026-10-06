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
response or retirement state to upgrade or recover delayed work.

The previous certified allocation remains effective until the active cohort
produces a certified successor row. Acceptance under an earlier policy does not
accept the current policy or terms. Participants must retain the acceptance
receipt for the active policy. Registration, acceptance, selection, scoring and
reward activation are separate events.

## Upgrade an existing miner

Standard Linux miners managed by systemd use one updater. Choose only whether
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
fetches the current canonical manifest, checks its policy and profile against
the public competition status, and selects that matching deployment's exact
runtime revision. It installs the runtime beside the old runtime and creates a
new private state namespace for the current transport policy. Nonce, assignment,
finality, grant and model-sidecar state from earlier policies remain intact.

Rerunning the command installs a changed runtime even within the same cohort.
An existing receipt skips cutover only when its revision and the running miner's
interpreter match the selected deployment. Retained enrollment, nonce, assignment
and grant state stay in the same namespace.

The updater also handles the standard Unix-socket model sidecar. It binds a new
sidecar socket and capacity descriptor to the current transport policy before
starting the miner. It verifies exact policy, transport, model, finality and
sidecar health. If any check fails, it restores the prior systemd commands and
restarts the previous miner and sidecar. Rerunning the updater is idempotent.

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

The automatic path stops before mutation when it finds a custom or ambiguous
deployment, including multiple miner services, a root-run miner, a non-systemd
sidecar or an unrecognized entry point. Container and custom service operators
should apply the same [current upgrade manifest](../../deploy/miner-upgrade/current.json):
use its exact runtime and policy inputs, create fresh policy-bound protocol state,
preserve the previous deployment for rollback, and require the health contract
below before switching traffic.

The public TLS edge must proxy `POST /v1/translate`,
`POST /v1/competition/cohorts/assignments`, the response-recovery route, and the
retirement route without changing paths, bodies or authentication headers. A
static edge `/healthz` response does not prove those routes work.

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
