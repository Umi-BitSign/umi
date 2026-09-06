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

To test a registered miner through the HTTPS origin in its finalized SN78 serving
record, use [`PUBLIC_ENDPOINT_MINER_PILOT.md`](PUBLIC_ENDPOINT_MINER_PILOT.md).
That profile adds a signed coordinator attestation and uses the public-pilot replay
verifier. It has the same no-weight and nonconformance boundary as the local
profile.

The observer publishes these results only under `/api/v1/pilots`. It does not put
them under `/api/v1/windows`, advance the reported protocol phase, or populate the
UMI translation leaderboard. Each record identifies its `pilot_profile` as either
`local_in_process` or `public_endpoint` and supplies the matching replay command.

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
Keep those URLs available for as long as the public evidence must be retained.

## Publish the bundle

With no `--pilot-feed-config` argument, the namespace is present but returns
`availability: not_started`, `reason_code: public_component_pilot_not_started`, and
an empty list. This is the canonical empty index; do not create a dummy bundle.

To make the index live, append the completed bundle's absolute path to the canonical
config. The checked-in
`docs/examples/observer-pilot-feed-config.json` shows the server layout. The config
requires at least one completed bundle and permits at most 256. The aggregate
uncompressed feed remains capped at 128 MiB. It accepts at most one public-endpoint
pilot for each decoded miner account and campaign ID; another SS58 prefix does not
create another identity.

The observer config must be canonical JSON, owned by the observer service user, and
not group- or world-writable. Bundle directories and files must have the same owner
and must not be group- or world-writable. Use the observer's exact Python
environment for the update. The script below first replays the current feed, writes
a private candidate config, replays every old bundle plus the new bundle, verifies
that no old pilot disappeared, saves the prior config, and atomically installs the
candidate. A failure leaves the active config unchanged.

```bash
set -euo pipefail
umask 077
export PILOT_ROOT="/absolute/path/to/completed/immutable/pilot-bundle"
export PILOT_CONFIG="$HOME/Library/Application Support/UMI/observer-pilot-feed.json"
export OBSERVER_PYTHON="/absolute/path/to/the/current/observer/python"
export PILOT_ID="$(
  openssl dgst -sha256 "$PILOT_ROOT/manifest.json" | awk '{print $NF}'
)"

[[ "$PILOT_ID" =~ ^[0-9a-f]{64}$ ]]
test -x "$OBSERVER_PYTHON"
test -d "$PILOT_ROOT/objects"
install -d -m 700 "$(dirname "$PILOT_CONFIG")"

"$OBSERVER_PYTHON" - "$PILOT_CONFIG" "$PILOT_ROOT" "$PILOT_ID" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

from umi.observer_pilot_feed import build_observer_pilot_feed
from umi.protocol import canonical_json_bytes


def write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("config write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


config_path = Path(sys.argv[1]).resolve(strict=False)
pilot_root = Path(sys.argv[2]).resolve(strict=True)
pilot_id = sys.argv[3]
if hashlib.sha256((pilot_root / "manifest.json").read_bytes()).hexdigest() != pilot_id:
    raise SystemExit("pilot ID does not match its manifest")

original = None
old_ids = set()
if config_path.exists():
    old_feed = build_observer_pilot_feed(config_path)
    old_ids = {pilot.pilot_id for pilot in old_feed.pilots}
    original = config_path.read_bytes()
    config = json.loads(original)
else:
    config = {
        "schema": "umi-observer-pilot-feed-config/1",
        "protocol": "umi-asl/0.1",
        "mode": "component_test_no_weight",
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
        "public_origin": "https://api.umi.vision",
        "bundle_roots": [],
    }

roots = config.get("bundle_roots")
if not isinstance(roots, list) or any(not isinstance(root, str) for root in roots):
    raise SystemExit("existing pilot config has an invalid bundle_roots field")
if str(pilot_root) in roots:
    if pilot_id not in old_ids:
        raise SystemExit("configured pilot root did not replay to the requested pilot ID")
    print(json.dumps({
        "pilot_config": str(config_path),
        "pilot_id": pilot_id,
        "preserved_pilot_ids": sorted(old_ids),
        "configured_pilot_ids": sorted(old_ids),
        "already_configured": True,
    }, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0)
config["bundle_roots"] = list(dict.fromkeys([*roots, str(pilot_root)]))
payload = canonical_json_bytes(config)

candidate = config_path.with_name(f".{config_path.name}.candidate-{pilot_id}")
if candidate.exists():
    raise SystemExit(f"pilot config candidate already exists: {candidate}")
try:
    write_private(candidate, payload)
    new_feed = build_observer_pilot_feed(candidate)
    new_ids = {pilot.pilot_id for pilot in new_feed.pilots}
    if not old_ids.issubset(new_ids):
        raise SystemExit("candidate config removed an existing pilot")
    if pilot_id not in new_ids:
        raise SystemExit("candidate config did not ingest the requested pilot")
    if original is not None:
        if config_path.read_bytes() != original:
            raise SystemExit("pilot config changed during the update")
        backup = config_path.with_name(f"{config_path.name}.before-{pilot_id}")
        if backup.exists():
            raise SystemExit(f"pilot config backup already exists: {backup}")
        write_private(backup, original)
    os.replace(candidate, config_path)
    directory = os.open(config_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    candidate.unlink(missing_ok=True)

print(json.dumps({
    "pilot_config": str(config_path),
    "pilot_id": pilot_id,
    "preserved_pilot_ids": sorted(old_ids),
    "configured_pilot_ids": sorted(new_ids),
    "already_configured": False,
}, sort_keys=True, separators=(",", ":")))
PY

"$OBSERVER_PYTHON" - "$PILOT_CONFIG" "$PILOT_ID" <<'PY'
import json
import sys

from umi.observer_pilot_feed import build_observer_pilot_feed

feed = build_observer_pilot_feed(sys.argv[1])
pilot_ids = [pilot.pilot_id for pilot in feed.pilots]
if sys.argv[2] not in pilot_ids:
    raise SystemExit("installed config does not contain the requested pilot")
print(json.dumps({"pilot_ids": pilot_ids}, sort_keys=True, separators=(",", ":")))
PY
```

Restart the observer through its existing service manager. Preserve the current
network, token, production bundle-feed, pilot-feed, user, and tunnel settings. Do
not start a second observer beside the managed process. For the checked-in macOS
LaunchDaemon, inspect the installed plist first and fill every value below from
that deployed definition. `--observer-python` renders `python -m umi.observer`
directly in the plist and cannot be combined with `--observer-bin`.

```bash
set -euo pipefail
export UMI_REPO="/absolute/path/to/the/announced/umi/revision"
export OBSERVER_PYTHON="/absolute/path/to/the/current/observer/python"
export PILOT_CONFIG="$HOME/Library/Application Support/UMI/observer-pilot-feed.json"
export TOKEN_FILE="/absolute/current/tunnel-token-file"
export CLOUDFLARED_BIN="/absolute/current/cloudflared"
export BUNDLE_FEED_CONFIG="/absolute/current/observer-bundle-feed.json"

test -x "$OBSERVER_PYTHON"
test -x "$CLOUDFLARED_BIN"
test -f "$PILOT_CONFIG"
test -f "$TOKEN_FILE"
if [[ -n "$BUNDLE_FEED_CONFIG" ]]; then
  test -f "$BUNDLE_FEED_CONFIG"
fi

"$OBSERVER_PYTHON" - "$UMI_REPO" "$PILOT_CONFIG" <<'PY'
import json
import sys
from pathlib import Path

import umi
from umi.observer_pilot_feed import build_observer_pilot_feed
from umi.scoring import scoring_environment

expected_source = (Path(sys.argv[1]) / "src" / "umi").resolve(strict=True)
loaded_source = Path(umi.__file__).resolve(strict=True).parent
if loaded_source != expected_source:
    raise SystemExit(f"observer Python loaded UMI from {loaded_source}, not {expected_source}")
feed = build_observer_pilot_feed(sys.argv[2])
print(json.dumps({
    "pilot_ids": [pilot.pilot_id for pilot in feed.pilots],
    "scoring_environment": scoring_environment(),
}, sort_keys=True, separators=(",", ":")))
PY

if [[ -e /Library/LaunchDaemons/vision.umi.observer.plist ]]; then
  plutil -p /Library/LaunchDaemons/vision.umi.observer.plist
fi
if [[ -e /Library/LaunchDaemons/vision.umi.cloudflared.plist ]]; then
  plutil -p /Library/LaunchDaemons/vision.umi.cloudflared.plist
fi

SERVICE_ARGS=(
  --repo-root "$UMI_REPO"
  --observer-python "$OBSERVER_PYTHON"
  --cloudflared-bin "$CLOUDFLARED_BIN"
  --token-file "$TOKEN_FILE"
  --pilot-feed-config "$PILOT_CONFIG"
)
if [[ -n "$BUNDLE_FEED_CONFIG" ]]; then
  SERVICE_ARGS+=(--bundle-feed-config "$BUNDLE_FEED_CONFIG")
fi

cd "$UMI_REPO/deploy/first-public-result/launchd"
PREVIEW_DIRECTORY="$(mktemp -d "${TMPDIR:-/tmp}/umi-launchd-preview.XXXXXX")"
trap 'rm -rf "$PREVIEW_DIRECTORY"' EXIT
./manage.sh render --output-dir "$PREVIEW_DIRECTORY" "${SERVICE_ARGS[@]}"
plutil -p "$PREVIEW_DIRECTORY/vision.umi.observer.plist"
plutil -p "$PREVIEW_DIRECTORY/vision.umi.cloudflared.plist"

./manage.sh migration-check
./manage.sh install --replace --check-public-edge "${SERVICE_ARGS[@]}"
./manage.sh check --check-public-edge "${SERVICE_ARGS[@]}"
```

Compare both rendered `ProgramArguments` arrays with the installed arrays before
running `install`. The observer interpreter or repository and the pilot-feed
config may change for this deployment. The current tunnel binary, token path, and
production bundle-feed config must remain present. If the installed observer does
not use a production bundle-feed config, set `BUNDLE_FEED_CONFIG=''` and omit it as
the script does above. Use the same `SERVICE_ARGS` for every later `check` or
`install --replace` operation; otherwise the rendered plist will differ from the
installed service definition.

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
set -euo pipefail
export PILOT_ROOT="/absolute/path/to/completed/immutable/pilot-bundle"
export PILOT_ID="$(
  openssl dgst -sha256 "$PILOT_ROOT/manifest.json" | awk '{print $NF}'
)"
export PILOT_ORIGIN="https://api.umi.vision/api/v1/pilots/$PILOT_ID"

INDEX="$(curl -fsS 'https://api.umi.vision/api/v1/pilots?limit=256')"
printf '%s\n' "$INDEX" | jq -e --arg pilot_id "$PILOT_ID" '
  .schema == "umi-observer-pilots/2" and
  .availability == "available" and
  ([.pilots[] | select(.pilot_id == $pilot_id)] | length) == 1'

DETAIL="$(curl -fsS "$PILOT_ORIGIN")"
printf '%s\n' "$DETAIL" | jq -e --arg pilot_id "$PILOT_ID" '
  .schema == "umi-observer-pilot/2" and
  .pilot.pilot_id == $pilot_id and
  .pilot.bundle_manifest_sha256 == $pilot_id and
  .pilot.translation_weights_active == false and
  .pilot.protocol_conformance == false and
  .pilot.activation_evidence == false and
  .pilot.validator_input_eligible == false and
  .pilot.deterministic_replay_verified == true'

SOLUTIONS="$(curl -fsS "$PILOT_ORIGIN/solutions")"
printf '%s\n' "$SOLUTIONS" | jq -e --arg pilot_id "$PILOT_ID" '
  .schema == "umi-observer-pilot-solutions/2" and
  .pilot.pilot_id == $pilot_id and
  .page.total > 0 and
  (.solutions | length) > 0'

test "$(
  curl -fsS "$PILOT_ORIGIN/bundle/manifest.json" | openssl dgst -sha256 | awk '{print $NF}'
)" = "$PILOT_ID"
curl -fsS https://api.umi.vision/api/v1/windows | jq .availability
```

The exact pilot detail must show all four false safety claims and the full
missing-stage list. `/api/v1/windows` must remain empty unless a separate production
bundle has passed the production verifier.

For a public-endpoint pilot, replay success means the retained evidence is valid;
it does not mean the miner returned a successful translation. Read
`public_endpoint_evidence.transport.outcome_classification`. An `ok` record carries
a verified signed response, while `signed_error` and `failed` records preserve the
corresponding public attempt.

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
test "$(wc -l < "$AUDIT_ROOT/digests")" -le 75

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

if jq -e 'has("public_endpoint_pilot")' \
  "$AUDIT_ROOT/bundle/manifest.json" >/dev/null; then
  umi-public-pilot replay --bundle "$AUDIT_ROOT/bundle"
else
  umi-validator replay --bundle "$AUDIT_ROOT/bundle"
fi
printf 'verified_bundle=%s\n' "$AUDIT_ROOT/bundle"
```

This result is useful public evidence of the named pilot attempt. When the record
contains a verified envelope, it proves that the named miner hotkey signed the
retained response; anyone can reproduce the resulting score or failure. The model
revision remains a miner/operator assertion in both pilot profiles. The campaign
does not bind an expected revision or attest that a named checkpoint executed. The
result is also not evidence that the three-publisher, four-validator, retirement,
availability, chain-anchor, or activation requirements passed.

For a public-endpoint pilot, the API exposes
`coordinator_signature_verified: true` and
`coordinator_attested_origin_match: true`. Those fields mean the observer verified
the coordinator's signature and that the signed announced and contacted origins
match. They are not portable chain storage proofs; the adjacent chain record says
`network: finney`, binds the Finney genesis block hash, and says
`storage_proofs_verified: false`.
