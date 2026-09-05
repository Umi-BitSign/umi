# First public post-reveal result deployment

This runbook exposes one weight-disabled SN78 calibration result without making
the collector or validator evidence writer a Cloudflare Worker. Cloudflare is the
TLS, DNS, caching, rate-limit, and tunnel edge. The protocol processes retain the
durable local filesystems, SQLite state, signed release, and native replay
binaries they were designed to use.

This is not a weight-activation runbook. Every policy and process here has
`translation_weights_active: false`.

Run path-relative commands below from this `deploy/first-public-result`
directory after copying the repository to the target host.

## Topology

```text
Finney finalized RPC
        |
        v
umi-observer (durable Linux host) <-- HTTPS/replay -- validator audit origins
        |                                             ^
        v                                             |
Cloudflare Tunnel                               Cloudflare Tunnel
        |                                             ^
        v                                             |
api.umi.vision                              Caddy on 127.0.0.1:8093
        ^                                             ^
        |                                             |
Vercel allowlisted proxy                 local immutable audit docroot
                                                      ^
                                                      |
                                      umi-validator-audit-publish
```

Use a supported Linux target that exactly matches the signed inactive release.
Do not substitute D1 for the observer SQLite database or R2 for the publisher's
same-filesystem atomic document root. Those migrations require separate adapters
and conformance tests.

## Supplied assets

- `caddy/Caddyfile.audit-origin.example` serves only canonical validator indexes,
  manifests, and hashed bundle objects.
- `cloudflared/*.yml.example` expose the two loopback listeners and end in a
  fail-closed `http_status:404` rule.
- `systemd/umi-observer.service` runs the read-only observer without wallet access.
- `systemd/umi-validator-audit-publish.service` runs the publisher as the validator
  operating-system account because terminal bundles are intentionally owner-only.
  The unit denies access to wallet paths and exposes no wallet or chain-write option.
- `systemd/*.env.example` contain configuration placeholders only. Tunnel
  credentials, RPC credentials, wallets, and signing material never belong there.
- `check-placeholders.py` rejects unresolved template tokens, the example release
  authority, and the example audit origin. With `--observer-feed`, it also checks
  every publication config named by the feed.

The Caddy allowlist deliberately excludes raw media. Publish no raw video through
this origin. A separate route may be added only for objects whose consent record
explicitly grants the `public-release-approved` class, after a privacy review.

## 1. Complete the protocol prerequisites

Before provisioning the public services:

1. Retain the completed UMI identity proof from finalized block `8993215` and do
   not replace the identity with an obsolete partial record.
2. Read the live `activity_cutoff_factor` and make sure the derived cutoff is no
   longer than the policy's 360-block window stride. On 2026-09-05, the fresh
   public observer still reported a 5,000-block derived cutoff, so this prerequisite
   had not passed. These observations are not permanent chain values. Use the
   exact owner-only procedure and read-only finalized-state verifier in
   [`owner-cutoff/README.md`](owner-cutoff/README.md).
3. Build, sign, verify, and publish the target-specific inactive UMI release.
4. Materialize the policy-bound validator configurations from that release.
5. Complete the publisher, validator, miner, collateral, capacity, consent,
   mirror, and availability prerequisites in
   `../../docs/INACTIVE_LAUNCH_CHECKLIST.md`.
6. Choose stable hostnames: `api.umi.vision` and one audit hostname per validator.

The hostnames must belong to an active zone in the Cloudflare account used for
the tunnels. If DNS is still delegated elsewhere, coordinate that migration and
preserve the existing apex and `www` Vercel records; do not change nameservers as
an incidental deployment step.

Do not use older `btcli sudo set` examples for this change. The dedicated handoff
pins the tested `btcli 11.1.0` command shape, requires a dry run, and verifies the
finalized result through the fixed observer endpoint. Final protocol confirmation
still comes from the first live weight-build snapshot, which reads
`ActivityCutoffFactorMilli`, `Tempo`, and the other required fields at one explicit
finalized block through the release-pinned proof path. Its bundle must contain the
block, state root, storage proofs, and a derived cutoff no greater than the window
stride.

The observer machine needs outbound access to the configured Finney RPC and every
validator audit origin. It needs no wallet. Each audit publisher needs outbound
HTTPS for its own public readback and no inbound port.

## 2. Prepare each validator audit host

Use the validator operating-system account so the publisher can read terminal
bundles without weakening their required owner-only modes. Create the exact local
locations named by the canonical publication config on one filesystem:

```sh
sudo install -d -o root -g root -m 0755 /etc/umi
sudo install -d -o umi-validator -g umi-validator -m 0755 /srv/www/umi-audits
sudo install -d -o umi-validator -g umi-validator -m 0700 \
  /var/lib/umi-audit-publisher /var/lib/umi-audit-publisher/staging
```

Do not add ACLs, group access, or relaxed modes to the validator state tree. The
live validator and publisher share only their Unix identity; the publisher binary
has no wallet-loading, signing, RPC, or chain-write path. In the service unit,
replace or extend `InaccessiblePaths` so it names the validator's exact wallet
parent. `ProtectHome=true` already hides wallets below `/home`, `/root`, and
`/run/user`, but wallets stored elsewhere require their own absolute path.

Copy and canonicalize the real publication config as documented in
`../../docs/AUDIT_BUNDLE_PUBLICATION_OPERATOR.md`. It must name the local signed
validator config, durable SQLite database, staging root, public docroot, and exact
HTTPS audit origin. The repository example is not a deployable config.
Install the resulting `/etc/umi/audit-publication.json` as mode `0600`, owned by
`umi-validator`, and give that account read-only access to the materialized
validator config and signed release.

Install the Caddy example as `/etc/caddy/Caddyfile`. Keep its listener on loopback,
do not add `encode`, `precompressed`, directory browsing, redirects, rewrites, or a
fallback document:

```sh
sudo install -o root -g root -m 0644 caddy/Caddyfile.audit-origin.example \
  /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

Create a named, locally managed Cloudflare Tunnel from an authenticated admin
workstation. Record the returned UUID. The account-wide `cert.pem` stays on that
workstation; the origin host receives only the generated tunnel credentials JSON.

```sh
cloudflared tunnel login
cloudflared tunnel create umi-validator-REPLACE_WITH_VALIDATOR_NUMBER-audit
```

On the origin host, replace the UUID and hostname in a reviewed copy of
`cloudflared/audit-origin.yml.example`. Install that copy and the generated
credentials file. Both installed files must name the same UUID.

```sh
sudo install -d -o root -g root -m 0755 /etc/cloudflared
sudo install -o root -g root -m 0600 \
  REPLACE_WITH_GENERATED_TUNNEL_CREDENTIALS_JSON \
  /etc/cloudflared/REPLACE_WITH_AUDIT_TUNNEL_UUID.json
sudo install -o root -g root -m 0600 \
  REPLACE_WITH_REVIEWED_AUDIT_TUNNEL_CONFIG \
  /etc/cloudflared/config.yml
sudo cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
sudo cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
  https://audit-validator-REPLACE_WITH_VALIDATOR_NUMBER.umi.vision/
```

Configure the Cloudflare zone for Full (strict) TLS and no response
transformation. Allow only `GET` and `HEAD`. Cache immutable window manifests and
objects; bypass cache for `validators/*/index.json`. Do not place Cloudflare Access
in front of this public origin because protocol readback is intentionally
unauthenticated.

Install the publisher environment file and unit:

```sh
sudo install -o root -g root -m 0600 \
  systemd/umi-validator-audit-publish.env.example \
  /etc/umi/umi-validator-audit-publish.env
sudo install -o root -g root -m 0644 \
  systemd/umi-validator-audit-publish.service \
  /etc/systemd/system/umi-validator-audit-publish.service
sudoedit /etc/systemd/system/umi-validator-audit-publish.service
sudo systemctl daemon-reload
```

The unit assumes the verified release is below `/opt/umi` and validator state is
at `/var/lib/umi-validator`. Change every corresponding `ReadOnlyPaths` and
`ExecStart` value if the signed local configuration uses different paths. Replace
`/REPLACE_WITH_ABSOLUTE_WALLET_PARENT` with the exact existing wallet parent. The
unchanged nonexistent sentinel intentionally prevents startup. Any remaining `REPLACE_WITH` token is a deployment failure.

Validate signed inputs and filesystem boundaries before enabling the service:

```sh
sudo -u umi-validator /opt/umi/.venv/bin/umi-validator-audit-publish \
  --config /etc/umi/audit-publication.json --check
sudo python3 check-placeholders.py /etc/caddy/Caddyfile \
  /etc/cloudflared/config.yml \
  /etc/umi/umi-validator-audit-publish.env \
  /etc/systemd/system/umi-validator-audit-publish.service \
  /etc/umi/audit-publication.json
sudo systemd-analyze verify /etc/systemd/system/umi-validator-audit-publish.service
sudo systemd-analyze security umi-validator-audit-publish.service
```

Install the locally managed tunnel service only after the config passes those
checks. If this host already runs `cloudflared`, do not install a second service;
merge both reviewed ingress routes into its existing config and revalidate it.
On a dedicated audit host, run:

```sh
sudo cloudflared --config /etc/cloudflared/config.yml service install
sudo systemctl daemon-reload
sudo systemctl enable --now caddy.service cloudflared.service
sudo systemctl is-active --quiet caddy.service
sudo systemctl is-active --quiet cloudflared.service
sudo systemctl --no-pager --full status caddy.service cloudflared.service
sudo journalctl -u cloudflared.service -n 100 --no-pager
```

From the authenticated admin workstation, confirm that `cloudflared tunnel info`
shows a connected replica, then create the DNS route. The route command requires
the account certificate; do not copy that certificate to the origin merely to run
the command there.

```sh
cloudflared tunnel info REPLACE_WITH_AUDIT_TUNNEL_UUID
cloudflared tunnel route dns REPLACE_WITH_AUDIT_TUNNEL_UUID \
  audit-validator-REPLACE_WITH_VALIDATOR_NUMBER.umi.vision
```

Run the exact disposable-origin check in Section 4 before enabling the publisher.
The production publisher accepts only signed, proof-backed terminal bundles; the
repository does not provide a fake production-bundle generator. After the probe
has removed its file, start the publisher:

```sh
sudo systemctl enable --now umi-validator-audit-publish.service
sudo systemctl is-active --quiet umi-validator-audit-publish.service
sudo systemctl --no-pager --full status umi-validator-audit-publish.service
sudo journalctl -u umi-validator-audit-publish.service -n 100 --no-pager
```

Enter the publisher's mount namespace and prove that the configured wallet parent
is absent there. Set `UMI_WALLET_PARENT` to the same existing absolute path used in
`InaccessiblePaths`:

```sh
UMI_WALLET_PARENT=/absolute/path/to/validator-wallet-parent
test -d "${UMI_WALLET_PARENT}"
UMI_PUBLISHER_PID="$(sudo systemctl show --property MainPID --value \
  umi-validator-audit-publish.service)"
test "${UMI_PUBLISHER_PID}" -gt 1
if sudo nsenter --mount="/proc/${UMI_PUBLISHER_PID}/ns/mnt" -- \
  test -e "${UMI_WALLET_PARENT}"; then
  echo 'wallet path is visible inside publisher sandbox' >&2
  exit 1
fi
sudo -u caddy test -r /srv/www/umi-audits
if sudo -u caddy test -w /srv/www/umi-audits; then
  echo 'Caddy can write the public document root' >&2
  exit 1
fi
```

## 3. Prepare the observer host

Install the verified UMI package, complete signed release, native replay binaries,
and one unique materialized publication definition for every registered validator
feed target. Before the first observer start, finalize the complete target list and
build the canonical `/etc/umi/observer-bundle-feed.json` from
`../../docs/examples/observer-bundle-feed-config.json`. The database binds that
entire sorted set on first open; adding a validator later deliberately fails with
`feed_state_binding_mismatch`. A governed target-set change requires stopping the
service, creating a fresh empty database, and replaying every retained public index
from sequence zero. Never edit the database to bypass this binding.
Install the feed config and every locally referenced publication definition as
mode `0600`, owned by `umi-observer`; expose no validator-private credentials in
those copies.

Use durable local paths for the SQLite database and temporary download root. At
the default four-target concurrency, reserve more than `4 * 384 MiB` of temporary
space plus database, release, log, and operating-system headroom. Back up the
SQLite database together with its WAL using SQLite's supported backup mechanism.
The example feed config sets `maximum_state_database_bytes` to 4 GiB. Choose a
smaller explicit bound if the provisioned volume cannot safely accommodate that
limit plus the WAL and other host data.

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin umi-observer
sudo install -d -o root -g root -m 0755 /etc/umi
sudo install -d -o umi-observer -g umi-observer -m 0700 \
  /var/lib/umi-observer /var/lib/umi-observer/bundle-temporary \
  /var/cache/umi-observer
sudo install -o root -g root -m 0600 systemd/umi-observer.env.example \
  /etc/umi/umi-observer.env
sudo install -o root -g root -m 0644 systemd/umi-observer.service \
  /etc/systemd/system/umi-observer.service
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/umi-observer.service
```

Create the observer tunnel from the authenticated admin workstation and record its
UUID. Install only its credentials JSON and a reviewed copy of
`cloudflared/observer-api.yml.example` on the observer host.

```sh
cloudflared tunnel login
cloudflared tunnel create umi-observer-api
```

```sh
sudo install -d -o root -g root -m 0755 /etc/cloudflared
sudo install -o root -g root -m 0600 \
  REPLACE_WITH_GENERATED_TUNNEL_CREDENTIALS_JSON \
  /etc/cloudflared/REPLACE_WITH_OBSERVER_TUNNEL_UUID.json
sudo install -o root -g root -m 0600 \
  REPLACE_WITH_REVIEWED_OBSERVER_TUNNEL_CONFIG \
  /etc/cloudflared/config.yml
sudo python3 check-placeholders.py \
  --observer-feed /etc/umi/observer-bundle-feed.json \
  /etc/cloudflared/config.yml \
  /etc/umi/umi-observer.env \
  /etc/systemd/system/umi-observer.service
sudo cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
sudo cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
  https://api.umi.vision/
```

If the observer and audit origin share a host, install one reviewed cloudflared
configuration containing both ingress routes rather than overwriting one service's
config with the other example. On a dedicated observer host, install the tunnel
service and start the local API first:

```sh
sudo cloudflared --config /etc/cloudflared/config.yml service install
sudo systemctl daemon-reload
sudo systemctl enable --now umi-observer.service
sudo systemctl is-active --quiet umi-observer.service
curl --fail --silent --show-error -H 'Host: api.umi.vision' \
  http://127.0.0.1:8092/healthz
curl --fail --silent --show-error -H 'Host: api.umi.vision' \
  http://127.0.0.1:8092/readyz
sudo systemctl enable --now cloudflared.service
sudo systemctl is-active --quiet cloudflared.service
sudo systemctl --no-pager --full status umi-observer.service cloudflared.service
sudo journalctl -u umi-observer.service -n 100 --no-pager
sudo journalctl -u cloudflared.service -n 100 --no-pager
```

From the admin workstation, confirm that the replica is connected and then create
the DNS route:

```sh
cloudflared tunnel info REPLACE_WITH_OBSERVER_TUNNEL_UUID
cloudflared tunnel route dns REPLACE_WITH_OBSERVER_TUNNEL_UUID api.umi.vision
```

Bypass Cloudflare cache for `/healthz`, `/readyz`, `/openapi.json`, and `/api/*`;
preserve the observer's ETag, `Cache-Control`, and `X-UMI-*` headers. Apply a public
read rate limit without browser authentication. Then check the public listener:

```sh
curl --fail --silent --show-error https://api.umi.vision/readyz
curl --fail --silent --show-error https://api.umi.vision/api/v1/status
```

Prefer the allowlisted same-origin Vercel proxy in `../../docs/DASHBOARD_API.md`. It must
not accept arbitrary upstream URLs or paths and must preserve the observer's cache
and revision headers. If the browser calls the observer directly, add only the
exact production CORS origins to the service command.

## 4. Prove the evidence origin

Run this probe before the publisher service and before any real publication. It
creates one fixed all-zero manifest route, never creates an index entry, checks the
loopback listener and public tunnel, and removes the exact file on exit. Stop if
the probe path already exists. This tests static byte transport only and is not a
protocol bundle or evidence of validator work.

Replace only `UMI_AUDIT_HOST`, then run the entire block in one Bash process:

```bash
set -euo pipefail

UMI_AUDIT_HOST=audit-validator-REPLACE_WITH_VALIDATOR_NUMBER.umi.vision
[[ "${UMI_AUDIT_HOST}" =~ ^audit-validator-[1-9][0-9]*[.]umi[.]vision$ ]]
UMI_PROBE_ACCOUNT=0000000000000000000000000000000000000000000000000000000000000000
UMI_PROBE_WINDOW=0000000000000000000000000000000000000000000000000000000000000000
UMI_PROBE_RELATIVE="validators/${UMI_PROBE_ACCOUNT}/windows/${UMI_PROBE_WINDOW}/skipped/manifest.json"
UMI_PROBE_DIRECTORY="/srv/www/umi-audits/validators/${UMI_PROBE_ACCOUNT}/windows/${UMI_PROBE_WINDOW}/skipped"
UMI_PROBE_FILE="/srv/www/umi-audits/${UMI_PROBE_RELATIVE}"
UMI_PROBE_TEMPORARY="$(mktemp -d /tmp/umi-static-origin-probe.XXXXXXXX)"

cleanup_umi_static_probe() {
  sudo -u umi-validator rm -f -- "${UMI_PROBE_FILE}"
  sudo -u umi-validator rmdir -- \
    "${UMI_PROBE_DIRECTORY}" \
    "/srv/www/umi-audits/validators/${UMI_PROBE_ACCOUNT}/windows/${UMI_PROBE_WINDOW}" \
    "/srv/www/umi-audits/validators/${UMI_PROBE_ACCOUNT}/windows" \
    "/srv/www/umi-audits/validators/${UMI_PROBE_ACCOUNT}" 2>/dev/null || true
  rm -f -- "${UMI_PROBE_TEMPORARY}"/*
  rmdir -- "${UMI_PROBE_TEMPORARY}"
}
trap cleanup_umi_static_probe EXIT

test ! -e "${UMI_PROBE_FILE}"
printf '%s' '{"schema":"umi-static-origin-probe/1"}' \
  > "${UMI_PROBE_TEMPORARY}/expected"
sudo -u umi-validator install -d -m 0755 "${UMI_PROBE_DIRECTORY}"
sudo -u umi-validator install -m 0444 \
  "${UMI_PROBE_TEMPORARY}/expected" "${UMI_PROBE_FILE}"
sudo -u caddy test -r "${UMI_PROBE_FILE}"
cmp "${UMI_PROBE_TEMPORARY}/expected" "${UMI_PROBE_FILE}"
if sudo -u caddy test -w "${UMI_PROBE_DIRECTORY}"; then
  echo 'Caddy can write the probe directory' >&2
  exit 1
fi

verify_umi_probe_get() {
  local label="$1"
  local url="$2"
  local host_header="$3"
  local status
  local expected_bytes
  local actual_bytes
  local encoding
  local -a host_args=()
  if [[ -n "${host_header}" ]]; then
    host_args=(-H "Host: ${host_header}")
  fi
  status="$(curl --silent --show-error --max-redirs 0 \
    --header 'Accept-Encoding: identity' "${host_args[@]}" \
    --dump-header "${UMI_PROBE_TEMPORARY}/${label}.headers" \
    --output "${UMI_PROBE_TEMPORARY}/${label}.body" \
    --write-out '%{http_code}' "${url}")"
  test "${status}" = 200
  cmp "${UMI_PROBE_TEMPORARY}/expected" \
    "${UMI_PROBE_TEMPORARY}/${label}.body"
  expected_bytes="$(wc -c < "${UMI_PROBE_TEMPORARY}/expected" | tr -d '[:space:]')"
  actual_bytes="$(tr -d '\r' < "${UMI_PROBE_TEMPORARY}/${label}.headers" | \
    awk -F ':[[:space:]]*' 'tolower($1)=="content-length" {value=$2} END {print value}')"
  test "${actual_bytes}" = "${expected_bytes}"
  ! grep -Eiq '^location:' "${UMI_PROBE_TEMPORARY}/${label}.headers"
  while IFS= read -r encoding; do
    test "${encoding}" = identity
  done < <(tr -d '\r' < "${UMI_PROBE_TEMPORARY}/${label}.headers" | \
    awk -F ':[[:space:]]*' 'tolower($1)=="content-encoding" {print tolower($2)}')
}

verify_umi_probe_get local \
  "http://127.0.0.1:8093/${UMI_PROBE_RELATIVE}?probe=local" \
  "${UMI_AUDIT_HOST}"
verify_umi_probe_get public_query \
  "https://${UMI_AUDIT_HOST}/${UMI_PROBE_RELATIVE}?probe=public" ''
verify_umi_probe_get public_plain \
  "https://${UMI_AUDIT_HOST}/${UMI_PROBE_RELATIVE}" ''
cmp "${UMI_PROBE_TEMPORARY}/public_query.body" \
  "${UMI_PROBE_TEMPORARY}/public_plain.body"

test "$(curl --silent --show-error --max-redirs 0 --head \
  --output /dev/null --write-out '%{http_code}' \
  "https://${UMI_AUDIT_HOST}/${UMI_PROBE_RELATIVE}")" = 200
test "$(curl --silent --show-error --max-redirs 0 --request POST \
  --output /dev/null --write-out '%{http_code}' \
  "https://${UMI_AUDIT_HOST}/${UMI_PROBE_RELATIVE}")" = 405
test "$(curl --silent --show-error --max-redirs 0 \
  --output /dev/null --write-out '%{http_code}' \
  "https://${UMI_AUDIT_HOST}/not-a-protocol-route")" = 404
```

The publisher performs the protocol check later. For each real terminal bundle it
replays the signed bundle, reads every manifest and object back through public
HTTPS, checks the exact byte lengths and SHA-256 values, and only then appends the
validator index.

## 5. Replay from a clean external machine

Use a second supported Linux machine after the first real bundle is public. Install
the exact signed release, its native binaries, the materialized validator configs,
the observer feed config, and the audit-publication configs referenced by that
feed. These files define the trust roots and public origins. Do not copy the
production observer database, publisher database, public document tree, or any
downloaded bundle object to this machine. No wallet is needed.

Create a new replay root and derive a canonical feed config that changes only the
observer database and temporary-download paths:

```bash
set -euo pipefail
UMI_REPLAY_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
UMI_REPLAY_ROOT="/var/lib/umi-independent-replay/${UMI_REPLAY_ID}"
UMI_REPLAY_UNIT="umi-independent-replay-${UMI_REPLAY_ID}"
UMI_REPLAY_OUTPUT="$(mktemp -d /var/tmp/umi-independent-replay-output.XXXXXXXX)"
export UMI_REPLAY_ROOT
id -u umi-observer >/dev/null 2>&1 || \
  sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin umi-observer
sudo python3 check-placeholders.py \
  --observer-feed /etc/umi/observer-bundle-feed.json \
  /etc/umi/observer-bundle-feed.json
test ! -e "${UMI_REPLAY_ROOT}"
sudo install -d -o umi-observer -g umi-observer -m 0700 \
  "${UMI_REPLAY_ROOT}" \
  "${UMI_REPLAY_ROOT}/bundle-temporary" \
  "${UMI_REPLAY_ROOT}/runtime-cache"
sudo -u umi-observer env UMI_REPLAY_ROOT="${UMI_REPLAY_ROOT}" \
  /opt/umi/.venv/bin/python - <<'PY'
import os
from pathlib import Path

from umi.observer_bundle_feed import (
    ObserverBundleFeedConfig,
    load_observer_bundle_feed_config,
)
from umi.protocol import canonical_json_bytes

source = load_observer_bundle_feed_config("/etc/umi/observer-bundle-feed.json")
payload = source.model_dump(mode="json", by_alias=True)
root = Path(os.environ["UMI_REPLAY_ROOT"])
payload["state_database_path"] = str(root / "bundle-feed.sqlite3")
payload["temporary_root"] = str(root / "bundle-temporary")
config = ObserverBundleFeedConfig.model_validate(payload)
(root / "observer-bundle-feed.json").write_bytes(canonical_json_bytes(config))
PY
sudo -u umi-observer chmod 0600 \
  "${UMI_REPLAY_ROOT}/observer-bundle-feed.json"
test ! -e "${UMI_REPLAY_ROOT}/bundle-feed.sqlite3"
```

Start a transient observer against that empty database. It obtains chain state
from Finney and bundle bytes from the configured public HTTPS origins.

```bash
sudo systemd-run --unit="${UMI_REPLAY_UNIT}" --collect \
  --property=User=umi-observer \
  --property=Group=umi-observer \
  --setenv="BITTENSOR_RUNTIME_CACHE_DIR=${UMI_REPLAY_ROOT}/runtime-cache" \
  /opt/umi/.venv/bin/umi-observer \
  --listen-host 127.0.0.1 \
  --port 8094 \
  --network finney \
  --trusted-host 127.0.0.1 \
  --bundle-feed-config "${UMI_REPLAY_ROOT}/observer-bundle-feed.json" \
  --fresh-for-seconds 24 \
  --maximum-stale-seconds 120 \
  --refresh-interval-seconds 12 \
  --refresh-timeout-seconds 45 \
  --finalized-head-timeout-seconds 20 \
  --maximum-finalized-head-age-seconds 120 \
  --maximum-future-block-skew-seconds 30 \
  --log-level info
```

Wait for every configured validator feed to contain at least one independently
accepted entry and report `current`. This five-minute bound is enough for one
first-window entry per target under the supplied feed limits; a timeout is a failed
acceptance check, not permission to reuse the production database.

```bash
UMI_REPLAY_READY=0
for UMI_REPLAY_ATTEMPT in $(seq 1 150); do
  if curl --fail --silent --show-error \
    'http://127.0.0.1:8094/api/v1/windows?limit=50' \
    -o "${UMI_REPLAY_OUTPUT}/windows.json" && \
    jq -e '
      .availability == "available" and
      (.bundle_feed_health | length > 0) and
      all(.bundle_feed_health[];
        .status == "current" and .accepted_entries > 0)
    ' "${UMI_REPLAY_OUTPUT}/windows.json" >/dev/null; then
    UMI_REPLAY_READY=1
    break
  fi
  sleep 2
done
test "${UMI_REPLAY_READY}" = 1
curl --fail --silent --show-error \
  'http://127.0.0.1:8094/api/v1/status' \
  -o "${UMI_REPLAY_OUTPUT}/status.json"
jq -e '
  .service_status == "ready" and
  .protocol_state.phase == "shadow_calibration" and
  .protocol_state.translation_weights_active == false and
  .protocol_state.conformance_evidence_available == true
' "${UMI_REPLAY_OUTPUT}/status.json" >/dev/null
```

Finally, request the expected validator-attributed solution set. Replace both
values with the IDs from the public validator index, not values copied from the
production observer database.

```bash
UMI_EXPECTED_WINDOW=REPLACE_WITH_WINDOW_ID
UMI_EXPECTED_VALIDATOR=REPLACE_WITH_VALIDATOR_ACCOUNT_ID32
[[ "${UMI_EXPECTED_WINDOW}" =~ ^[0-9a-f]{64}$ ]]
[[ "${UMI_EXPECTED_VALIDATOR}" =~ ^[0-9a-f]{64}$ ]]
curl --fail --silent --show-error \
  "http://127.0.0.1:8094/api/v1/windows/${UMI_EXPECTED_WINDOW}/solutions?validator=${UMI_EXPECTED_VALIDATOR}&limit=50" \
  -o "${UMI_REPLAY_OUTPUT}/solutions.json"
jq -e --arg window "${UMI_EXPECTED_WINDOW}" \
  --arg validator "${UMI_EXPECTED_VALIDATOR}" '
    .window.window_id == $window and
    .window.validator_account_id32 == $validator and
    .score_scope == "validator_local" and
    .page.total > 0
  ' "${UMI_REPLAY_OUTPUT}/solutions.json" >/dev/null
sudo journalctl -u "${UMI_REPLAY_UNIT}.service" -n 200 --no-pager
sudo systemctl stop "${UMI_REPLAY_UNIT}.service"
```

Preserve the independent replay root, output directory, and journal output with
the release digest and public URLs used. A `current` feed proves that the clean observer fetched
and passed the production replay verifier for each accepted public bundle; the
observer API is still not a validator input or a second consensus system.

## 6. Accept the first real window

Run the complete inactive window without manual candidate or assignment changes.
After reveal and the protocol-defined audit release block:

1. Every expected validator reaches `calibration_no_weight`; no UMI weight call is
   present.
2. Every audit publisher completes public readback and appends exactly one immutable
   route to its validator index.
3. The observer independently downloads and replays every expected validator
   bundle. Feed health is `current`, not `degraded`, `stale`, or `not_started`.
4. `/api/v1/windows` contains each validator-attributed record and
   `/api/v1/incidents` agrees with terminal reason codes. Each released reveal
   result is present at `/api/v1/windows/<window_id>/solutions?validator=<account_id32>`,
   including successful hypotheses, assigned failures, exact scores, references,
   and immutable evidence URLs.
5. `/api/v1/status` identifies the phase as shadow calibration and no longer says
   public calibration has not started.
6. The clean-machine procedure in Section 5 succeeds without copied bundle or
   database state.

During calibration, `leaderboard.umi_translation` remains unavailable by design.
Display scores from window records as `validator_local`, grouped by validator and
window. Never merge them into a consensus ranking. Keep native chain economics
separately labeled as unverified or legacy/bootstrap evidence.

Only after these checks pass may the public message say that SN78 is running a
public, weight-disabled UMI calibration mechanism. Preserve the public tree,
publisher database, observer database, and logs after any failure; never rewrite a
published index or delete evidence to make a retry pass.
