# Public component pilot

This is the shortest honest route to a public, replayable model result while the
independent actors required by the launch policy are still missing. It does not
create a protocol window, submit weights, satisfy an activation gate, or claim
protocol conformance.

For the one-command external-miner run using the pinned public S1 model and the
checked-in `ASL BOOK` asset, use
[`EXTERNAL_MINER_COMPONENT_PILOT.md`](EXTERNAL_MINER_COMPONENT_PILOT.md). That
wrapper generates the inputs and future Quicknet rounds, verifies the signed model
release, produces the bundle, and replays it. It still runs the miner in-process and
does not prove the miner's public axon.

The observer publishes these results only under `/api/v1/pilots`. It does not put
them under `/api/v1/windows`, advance the reported protocol phase, or populate the
UMI translation leaderboard.

## Evidence boundary

Prefer fresh adult recordings whose signed consent permits public release. A
component-only bootstrap pilot may instead use a pre-existing adult recording under
an explicit license that permits redistribution and adaptation, provided the public
provenance record gives attribution and says that the clip is not fresh, lacks UMI-
specific consent and independent review, and is ineligible for a protocol window.
The checked-in [`ASL BOOK` pilot asset](pilot-media/ASL_BOOK_ATTRIBUTION.md) is one
such input.

Each request URL and its revealed references become public. Use label-free HTTPS
object URLs without credentials, and do not put private participant or consent
records in the request or ground-truth files. Pilot URLs cannot contain a query or
fragment; publish each clip at a durable, credential-free URL. The component bundle
does not embed the raw video, so an unavailable URL prevents an auditor from
inspecting the signed input even though text-score replay still works.

One pilot contains from one through 14 requests. It can exercise the real model,
signed request authentication, miner signatures, response and ground-truth
timelocks, exact CER/WER, assigned failures, and offline replay. Every published
record says:

- `evidence_class: component_test_no_weight`;
- `translation_weights_active: false`;
- `protocol_conformance: false`;
- `activation_evidence: false`;
- `validator_input_eligible: false`;
- which canonical publisher, selection, chain-anchor, retirement, rolling-score,
  and weight stages were not reached.

## Produce a real-model bundle

Complete the reference model setup in
`../umi-reference-model/docs/RUN_MINER.md` first. Use Python 3.12 in an environment
that contains both repositories. Prepare canonical `requests.json` and
`ground-truth.json` objects with a future Quicknet reveal round. The files use the
schemas already accepted by `umi-validator prepare`; every clip needs three through
five references.

Use two distinct local hotkeys so the evidence contains a real validator signature
and a real miner signature. These identities do not need to be described as
independent or registered for a component pilot.

```bash
set -euo pipefail
cd "$HOME/umi-miner/umi-reference-model"
source "$HOME/umi-miner/state/reference-miner.env"
MODEL_REVISION="$UMI_S1_INFERENCE_REVISION"
PILOT_ROOT="$HOME/Library/Application Support/UMI/pilots/first-public-pilot"

test "$(jq -er .status release/release-manifest.json)" = "baseline_no_weight"
"$HOME/umi-miner/umi-reference-model/.venv/bin/python" \
  -m bitsign_motion.umi_reference_backend probe | jq -e \
  --arg revision "$MODEL_REVISION" \
  '.status == "ready" and .inference_revision == $revision'

"$HOME/umi-miner/umi-reference-model/.venv/bin/python" \
  -m umi.component_pilot \
  --requests /absolute/private/operator-input/requests.json \
  --ground-truth /absolute/private/operator-input/ground-truth.json \
  --output "$PILOT_ROOT" \
  --validator-wallet-name umi \
  --validator-hotkey pilot-validator \
  --miner-wallet-name umi \
  --miner-hotkey miner \
  --translator bitsign_motion.umi_reference_backend:translator \
  --model-revision "$MODEL_REVISION" \
  --request-timeout 30 \
  --inference-timeout 180 \
  --reveal-timeout 600

"$HOME/umi-miner/umi-reference-model/.venv/bin/python" \
  -m umi.validator replay --bundle "$PILOT_ROOT"
shasum -a 256 "$PILOT_ROOT/manifest.json"
```

The runner has no chain client or transaction path. It runs a component-authority
miner in-process, fetches the declared HTTPS videos through the normal bounded and
DNS-pinned fetcher, waits for the real reveal, writes the normal
`umi-component-bundle/1` tree, and performs a second complete replay before it
reports success. A failure still scores zero and remains visible.

Do not edit, reserialize, or copy individual files into a completed bundle. A
changed manifest produces a new pilot ID; a changed object fails its digest.
Before enabling the feed, fetch every public video URL again and verify its exact
SHA-256, byte length, and `video/mp4` content type against the retained request.
Keep those URLs available for the full public-evidence retention period.

## Publish the bundle

With no `--pilot-feed-config` argument, the namespace is present but returns
`availability: not_started`, `reason_code: public_component_pilot_not_started`, and
an empty list. This is the canonical empty index; do not create a dummy bundle.

To make the index live, create a canonical config containing the completed bundle's
absolute path. The checked-in
`docs/examples/observer-pilot-feed-config.json` shows the server layout. The config
requires at least one completed bundle and permits at most eight.

The observer config must be canonical JSON, owned by the observer service user, and
not group- or world-writable. Bundle directories and files must have the same owner
and must not be group- or world-writable. Start or restart the observer with the
additional config; the production bundle feed remains separate.

```bash
PILOT_ROOT="$HOME/Library/Application Support/UMI/pilots/first-public-pilot"
PILOT_CONFIG="$HOME/Library/Application Support/UMI/observer-pilot-feed.json"
export PILOT_CONFIG PILOT_ROOT
install -d -m 700 "$(dirname "$PILOT_CONFIG")"
.venv/bin/python - <<'PY'
import os
from pathlib import Path

import rfc8785

config = {
    "schema": "umi-observer-pilot-feed-config/1",
    "protocol": "umi-asl/0.1",
    "mode": "component_test_no_weight",
    "translation_weights_active": False,
    "protocol_conformance": False,
    "activation_evidence": False,
    "public_origin": "https://api.umi.vision",
    "bundle_roots": [os.environ["PILOT_ROOT"]],
}
Path(os.environ["PILOT_CONFIG"]).write_bytes(rfc8785.dumps(config))
PY
chmod 600 "$PILOT_CONFIG"

"$HOME/umi-miner/umi-reference-model/.venv/bin/python" \
  -m umi.observer \
  --listen-host 127.0.0.1 \
  --port 8092 \
  --network finney \
  --trusted-host api.umi.vision \
  --bundle-feed-config /etc/umi/observer-bundle-feed.json \
  --pilot-feed-config "$PILOT_CONFIG"
```

For the macOS LaunchDaemon, select the exact interpreter that generated the
bundle. `--observer-python` renders `python -m umi.observer` directly in the plist;
it cannot be combined with `--observer-bin`.

```bash
set -euo pipefail
cd "$HOME/workspace/umi-context/umi/deploy/first-public-result/launchd"
OBSERVER_PYTHON="$HOME/umi-miner/umi-reference-model/.venv/bin/python"
test -x "$OBSERVER_PYTHON"
"$OBSERVER_PYTHON" -c 'import bitsign_motion, umi'

./manage.sh migration-check
./manage.sh install \
  --observer-python "$OBSERVER_PYTHON" \
  --pilot-feed-config "$PILOT_CONFIG"
./manage.sh check \
  --observer-python "$OBSERVER_PYTHON" \
  --pilot-feed-config "$PILOT_CONFIG"
```

The plist contains the feed-config path, not the bundle or any wallet material.
Use the same two options for every later `check` or `install --replace` operation;
otherwise the rendered plist will differ from the installed service definition.

Startup fails before listening if the config, path ownership, manifest schema,
safety fields, declared missing stages, size limits, object hashes, timelocks,
request authentication, miner signatures, bindings, or exact scores do not replay.
The accepted bytes are held as one immutable startup snapshot.

Run the observer with the same pinned Python, Unicode, `regex`, Bittensor, and UMI
scoring source versions that produced the bundle. The component manifest binds all
of them in `scoring_environment`; a different interpreter environment is rejected
instead of being treated as an independent replay.

Check the public boundary:

```bash
curl -fsS https://api.umi.vision/api/v1/pilots | jq .
curl -fsS https://api.umi.vision/api/v1/windows | jq .availability

PILOT_ID="$(curl -fsS https://api.umi.vision/api/v1/pilots | \
  jq -er '.pilots[0].pilot_id')"
curl -fsS "https://api.umi.vision/api/v1/pilots/$PILOT_ID/solutions" | jq .
```

The first response must show all four false safety claims and the full missing-stage
list. `/api/v1/windows` must remain empty unless a separate production bundle has
passed the production verifier.

## Independent replay

An auditor can reconstruct the component bundle from the content-addressed API and
run the same verifier:

```bash
set -euo pipefail
PILOT_ID="REPLACE_WITH_64_HEX_MANIFEST_HASH"
[[ "$PILOT_ID" =~ ^[0-9a-f]{64}$ ]]
ORIGIN="https://api.umi.vision/api/v1/pilots/$PILOT_ID/bundle"
AUDIT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/umi-pilot-audit.XXXXXX")"
umask 077
mkdir "$AUDIT_ROOT/bundle" "$AUDIT_ROOT/bundle/objects"

curl --fail --silent --show-error --connect-timeout 10 --max-time 60 \
  --max-filesize 1048576 \
  "$ORIGIN/manifest.json" -o "$AUDIT_ROOT/manifest.part"
test "$(wc -c < "$AUDIT_ROOT/manifest.part")" -le 1048576
test "$(shasum -a 256 "$AUDIT_ROOT/manifest.part" | awk '{print $1}')" = "$PILOT_ID"
mv "$AUDIT_ROOT/manifest.part" "$AUDIT_ROOT/bundle/manifest.json"

jq -e '
  [.. | objects |
    select(has("sha256") and has("media_type") and has("size_bytes")) |
    .sha256] as $digests |
  ($digests | length > 0) and
  all($digests[]; type == "string" and test("^[0-9a-f]{64}$"))
' "$AUDIT_ROOT/bundle/manifest.json" >/dev/null
jq -r '
  .. | objects |
  select(has("sha256") and has("media_type") and has("size_bytes")) |
  .sha256
' "$AUDIT_ROOT/bundle/manifest.json" | sort -u > "$AUDIT_ROOT/digests"
test "$(wc -l < "$AUDIT_ROOT/digests")" -le 73

OBJECT_BYTES=0
while IFS= read -r DIGEST; do
  [[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]]
  PART="$AUDIT_ROOT/bundle/objects/$DIGEST.part"
  FINAL="$AUDIT_ROOT/bundle/objects/$DIGEST"
  curl --fail --silent --show-error --connect-timeout 10 --max-time 60 \
    --max-filesize 4194304 \
    "$ORIGIN/objects/$DIGEST" -o "$PART"
  SIZE="$(wc -c < "$PART")"
  test "$SIZE" -le 4194304
  OBJECT_BYTES=$((OBJECT_BYTES + SIZE))
  test "$OBJECT_BYTES" -le 67108864
  test "$(shasum -a 256 "$PART" | awk '{print $1}')" = "$DIGEST"
  mv "$PART" "$FINAL"
done < "$AUDIT_ROOT/digests"

umi-validator replay --bundle "$AUDIT_ROOT/bundle"
printf 'verified_bundle=%s\n' "$AUDIT_ROOT/bundle"
```

This result is useful public evidence that the named miner hotkey returned signed
answers for the named videos and that anyone can reproduce their scores. The
model revision is an operator assertion: this in-process component runner does not
attest model execution or isolate the translator process from operator inputs. It
is also not evidence that the three-publisher, four-validator, retirement,
availability, chain-anchor, or activation requirements passed.
