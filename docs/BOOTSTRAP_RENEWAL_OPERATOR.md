# UID 200 bootstrap renewal controller

This is the coordinator-side continuity procedure for the temporary SN78 service
row. Dan installs the reviewed c77 supervisor with its corrected finality binary
and configuration, plus the worker release pinned below, once. The first sequence-2
directive and its applied signed result are produced manually. After that result
is public, this controller renews the exact same UID 200 row without routine
access to Dan's host or validator hotkey.

The controller cannot submit weights. It holds only UMI's coordinator hotkey. On
each cycle it waits for the finalized UID 200 `LastUpdate + 100` rate-limit
boundary, then creates a fresh signed authorization and a fresh operational
checkpoint. It uploads one immutable four-input bundle, appends one contiguous
signed directive to the root-owned public feed, and accepts completion only from
the validator-hotkey-signed public result. A row remains active through
`LastUpdate + 360`; renewal normally begins at `LastUpdate + 100`.

The controller is intentionally fixed to:

- Finney netuid 78, MechId 0, validator UID 200;
- weights version `4294967296`, `MinAllowedWeights = 256`, direct weights, tempo
  360, rate limit 100, and activity cutoff 360;
- worker revision `57857fce807d8ebecdf491718886b67e6d216196`, compiled into
  this controller release;
- submission namespace `3a3a007c6c1d2208688d18abff6e9b82` plus a fresh
  random 32-hex suffix; and
- the original signed manifest, owner-fence receipt, release target, and exact
  byte-identical 256-entry row.

It stops permanently on another active validator, a pending commit, a changed
UID/hotkey/origin/owner mapping, a changed or missing row, runtime drift, an
unattributed `LastUpdate`, a conflicting feed page, an ambiguous chain effect, or
insufficient hard-sunset headroom. Endpoint health and pilot replay are rebuilt
from the live finalized checkpoint for every authorization. They are never
precomputed.

## Adoption boundary

Do not start this controller before the initial sequence-2 result exists. Its
configuration must pin all of these exact local canonical files:

1. the signed frozen eligibility manifest;
2. the owner-fence receipt;
3. the pinned worker's `SupervisorReleaseTarget` JSON object;
4. Dan's installed validator-supervisor configuration;
5. signed directives 1 and 2; and
6. the submission ID of the validator-signed applied result for directive 2.

The sequence-2 operator-input URL must already be the immutable R2 path
`/validator-bootstrap-inputs/<bundle-sha256>.json`. Dan's installed supervisor
configuration must allow both `https://api.umi.vision` and
`https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev` as release origins. The
controller verifies that directive 2's hash and size identify the four records in
the signed result and that the result's applied `LastUpdate` is still the exact
current chain value. It will not synthesize, replace, or race sequence 2.

Before adoption, verify that the public feed contains both cursor pages:

```text
/api/v1/validator-directives/<UID200_ACCOUNT_ID32>/after/1/<SEQ1_SHA256>.json
/api/v1/validator-directives/<UID200_ACCOUNT_ID32>/after/2/<SEQ2_SHA256>.json
```

The controller retains every signed directive under its private state root. A
published directive that expires with no chain effect remains in the contiguous
history and receives a new submission ID in the next directive. A changed
`LastUpdate` without its exact signed result is ambiguous and terminal; it is
never retried.

## Install the controller release

Set `controller_revision` to the reviewed commit containing this file. Use a
detached, root-owned checkout and the repository's locked environment. Do not run
a moving branch.

```sh
controller_revision=REPLACE_WITH_REVIEWED_40_CHARACTER_CONTROLLER_REVISION
source_dir="/home/sam/umi-bootstrap-renewal-source-$controller_revision"
git clone --no-checkout git@github.com:Umi-BitSign/umi.git "$source_dir"
git -C "$source_dir" checkout --detach "$controller_revision"
test "$(git -C "$source_dir" rev-parse HEAD)" = "$controller_revision"
sudo install -d -o root -g root -m 0755 /opt/umi-bootstrap-renewal
sudo mv "$source_dir" /opt/umi-bootstrap-renewal/source
sudo chown -R root:root /opt/umi-bootstrap-renewal/source
sudo env UV_PROJECT_ENVIRONMENT=/opt/umi-bootstrap-renewal/.venv \
  /usr/local/bin/uv sync --project /opt/umi-bootstrap-renewal/source \
  --locked --no-dev
```

Do not copy a coldkey or validator wallet to this host. The configured wallet must
resolve only to the published coordinator hotkey
`5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4`.

The stable input-upload secret is already staged at:

```text
/home/sam/umi-validator-cutover-c77/private/validator-bootstrap-input-upload.key
```

It must remain a 65-byte, mode-0600 regular file. Do not print it. The Worker
performs digest/path-bound, create-only writes; a conflict is accepted only after
the uploader reads back the exact public bytes. Validator results use the fixed
UID 200 namespace, so no Wrangler or Worker-secret update occurs per cycle.

## Materialize and check the configuration

Copy the template outside the checkout, replace every placeholder, and calculate
each pin from the exact canonical file. `shasum -a 256 FILE` prints the required
digest. Then canonicalize once and install it root-owned:

```sh
candidate=$(mktemp)
jq -cSj . bootstrap-renewal.json >"$candidate"
sudo install -d -o root -g root -m 0755 /etc/umi
sudo install -o root -g root -m 0400 "$candidate" \
  /etc/umi/bootstrap-renewal.json
rm -f "$candidate"
```

The route root, initial sequence-1 page, sequence-2 cursor pages, and observer feed
must already be root-owned and non-writable by group or world. Run the local
checks before enabling the daemon:

```sh
sudo /opt/umi-bootstrap-renewal/.venv/bin/umi-bootstrap-renewal \
  check-config --config /etc/umi/bootstrap-renewal.json
sudo /opt/umi-bootstrap-renewal/.venv/bin/umi-bootstrap-renewal \
  initialize --config /etc/umi/bootstrap-renewal.json
sudo /opt/umi-bootstrap-renewal/.venv/bin/umi-bootstrap-renewal \
  status --config /etc/umi/bootstrap-renewal.json
```

`initialize` must report `renewal_initialized`. If the seed result is not public,
does not match directive 2, is no longer the current UID 200 result, or the row is
not the sole active exact row, stop. Do not delete state and try again.

## Enable and monitor

```sh
sudo install -o root -g root -m 0644 \
  /opt/umi-bootstrap-renewal/source/deploy/bootstrap-renewal/umi-bootstrap-renewal.service \
  /etc/systemd/system/umi-bootstrap-renewal.service
sudo systemctl daemon-reload
sudo systemctl enable --now umi-bootstrap-renewal.service
sudo systemctl status --no-pager umi-bootstrap-renewal.service
sudo journalctl -u umi-bootstrap-renewal.service -n 50 --no-pager
```

Normal status moves through `waiting_for_rate_limit`, `prepared`,
`input_published`, `directive_published`, and `result_verified`. The service is a
single-instance state machine; atomic private-state replacement, create-only
transaction artifacts, immutable R2 objects, and feed compare-and-swap checks make
restart safe. Never run `once` while the service is active.

The daemon may hold and retry an unavailable chain RPC, endpoint health check,
input upload, or result fetch. A `terminal` state is a deliberate stop in authority
even though the monitoring process remains alive. Preserve the complete state
root and all public objects, stop the service, and investigate the reason code.
Never edit `renewal-state.json`, a transaction directory, or a live feed page.

## Hard sunset

The controller stops authorizing once the current verified row covers the policy's
last active block (`hard_sunset_block - 1`). It cannot extend the original signed
hard sunset. Preserve its state and public history for audit. The separate sunset
procedure remains mandatory at the policy's hard-sunset block.
