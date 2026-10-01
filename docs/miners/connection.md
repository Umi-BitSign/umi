[Documentation](../README.md) / Current miner connection guide

# Current miner connection guide

Public C5 intake accepts endpoint-service and public-model submissions. C5 uses a
recoverable cohort runtime: phase blocks are operating targets, and coordinator
or validator downtime delays unfinished work instead of expiring the cohort.
Check [live status](https://api.umi.vision/v1/competition/status) and
[readiness](https://api.umi.vision/v1/competition/readiness) before signing or
diagnosing a submission.

C4 remains the effective reward cohort until C5 produces a certified successor
row. A C4 acceptance does not accept C5's policy or version 3 terms. Submit and
retain a fresh C5 acceptance. Registration, acceptance, selection, scoring and
reward activation are separate events.

## Upgrade an existing miner

Standard Linux miners managed by systemd use one updater. Choose only whether
you intend to participate in the public-model track:

```sh
curl -fsSLo /tmp/umi-miner-upgrade.py \
  https://raw.githubusercontent.com/Umi-BitSign/umi/main/deploy/miner-upgrade/upgrade.py \
  && sudo python3 /tmp/umi-miner-upgrade.py --public-model-track no
```

Use `yes` instead of `no` for public-model participation. C5 accepts either
answer. The choice records intent; it does not assert model rights or upload a
bundle. A model submission still needs its signed consent, rights decision and
complete artifact.

The updater discovers the one running `umi.miner` systemd service and retains its
hotkey, model revision, serving origin, wallet, model backend and public port. It
fetches the current canonical manifest, checks it against the public competition
status, installs the pinned runtime beside the old runtime, and creates a new
private state namespace for the current transport policy. Nonce, assignment,
finality, grant and model-sidecar state from earlier policies remain intact.

The updater also handles the standard Unix-socket model sidecar. It binds a new
sidecar socket and capacity descriptor to the current transport policy before
starting the miner. It verifies exact policy, transport, model, finality and
sidecar health. If any check fails, it restores the prior systemd commands and
restarts the previous miner and sidecar. Rerunning the updater is idempotent.

The updater installs itself at `/usr/local/libexec/umi-miner-upgrade`. Use that
same file for C6 and later cohorts; the current manifest supplies each cohort's
inputs and allowed tracks:

```sh
sudo /usr/local/libexec/umi-miner-upgrade --public-model-track yes
```

C6 has no endpoint pathway: every C6 participant uses the public-model track.
Its manifest therefore rejects `no`, records the model-track intent, and leaves
the C5 endpoint service unchanged as a recoverable prior deployment. The C6 model
submission still requires the operator's signed rights declaration and selected
bundle. Future mixed or endpoint-only cohorts likewise enforce their advertised
tracks. No cohort-specific replacement script is needed.

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
- competition policy
  `61f6c05143804c297aed524b6e067233567d30fe4eb50ab3289e7bfdad8e26fa`;
- transport policy
  `f182c1cbfa3985338944735cc55b52b46b12b0207436d79dd5978087483f01a8`;
- the same model revision and serving origin as the accepted C5 submission.

No assignments are expected during intake. After roster and request phases open,
the miner retrieves signed cohort history from the public API and durably stores
each grant before inference. An unavailable coordinator or validator causes a
retry; it does not become a miner failure or terminate C5. Preserve signed
responses and grant state until certified retirement.
