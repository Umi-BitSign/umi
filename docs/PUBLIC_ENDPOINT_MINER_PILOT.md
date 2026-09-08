# Public SN78 miner endpoint pilot

This is the public onboarding path for a registered SN78 miner before UMI's
translation weights activate. It sends one `btauth/1`-authenticated request with
a known ASL clip to the miner's chain-announced HTTPS axon and verifies any returned
miner response-envelope signature. When reveal, scoring, attestation, and
publication finish, UMI publishes the complete replayable bundle at
`api.umi.vision`.

The pilot proves endpoint and protocol interoperability. It is not a production
scoring window, model-quality benchmark, activation gate, validator input, or
weight result. The clip and references are public, so its score has no ranking
meaning.

Enrollment is open to every verified registered SN78 miner hotkey without a
validator permit. There is no exclusive pilot slot, and one miner does not wait
for another miner's offer to expire. The coordinator does not poll miners or send
ongoing requests. The issue bot posts a fresh payload for each readiness step.
The miner starts its pilot by signing the `READY FOR CASE` payload with the enrolled
hotkey when it is available. Each miner may complete at most one pilot in this
campaign, and each case sends at most one request after the two signed readiness
proofs described below. Bare `READY FOR CASE` and `READY TO ISSUE` comments do not
authorize the coordinator.

The coordinator issues one live request at a time. Signed issuance authorizations
for already prepared cases take priority; within the same stage, miners are
processed in authorization order. This bounded order protects the coordinator host
and does not reserve or deny pilot eligibility.

## Public workflow

1. The miner opens the public pilot issue form with its SN78 UID, hotkey,
   platform, inference device, and model revision.
2. The bot posts a random, issue-bound `READY FOR CASE` payload, the pinned UMI
   revision, and its expiration. Enrollment by itself starts no timer or request
   traffic.
3. Before signing, the miner publishes the stable public IP and port that will
   serve the case as its SN78 axon and waits until that exact origin is visible in
   finalized chain state. The case-specific service may remain stopped at this
   point, but the coordinator must be able to bind its origin during preparation.
4. When ready to load a fresh case, the issue owner signs that exact payload with
   the enrolled miner hotkey and posts the command's single-line output without
   editing it.
5. The coordinator verifies the signature, finalized SN78 registration, and
   finalized axon. It also proves that its local wallet controls the published
   coordinator hotkey, then creates one fresh timed case bound to both hotkeys and
   the announced origin.
6. The bot posts the sealed case URL, archive and manifest SHA-256 digests,
   response-close round, reveal round, and a separate `READY TO ISSUE` payload.
   The archive contains no plaintext references.
7. The miner verifies the archive, starts the exact-case service on loopback,
   exposes it through the chain-announced TLS endpoint, and signs the exact
   `READY TO ISSUE` payload. This proof binds the case manifest, endpoint origin,
   and prior case authorization.
8. UMI verifies the second hotkey signature and resolves the UID, hotkey, permit,
   and axon again from one finalized SDK snapshot. It sends one authenticated
   request to that exact origin. There is no URL override.
9. After reveal, UMI publishes the successful response or ordinary canonical
   request failure if the remaining local steps finish. An exceptional reveal,
   request-send, scoring, attachment, or publication failure leaves a verified
   non-feed attempt journal. UMI reports that incomplete state and does not rerun
   the case. A missing result never creates a retry authorization: the coordinator
   must recover and publish a terminal or incomplete result first.

Open a request at:

`https://github.com/Umi-BitSign/umi/issues/new?template=public-miner-pilot.yml`

Never post a seed phrase, private key, wallet file, password, private model URL,
or credential in the issue or case handoff.

The issue owner must post each signed proof from the same GitHub account that
opened the enrollment. That account check prevents another GitHub user from
advancing the issue. Hotkey control comes from the signature, which the coordinator
verifies independently. Do not edit the issue or a signed proof comment while its
authorization is pending. If the issue body changes, the bot will not reuse the
old binding.

## Manual coordinator procedure (disabled during bot automation)

> [!WARNING]
> Do not run the `prepare` or `run` commands in this section for an issue handled
> by the public-pilot bot and automation controller. The controller is the sole
> execution path for that deployment. Running this manual path at the same time
> could create a second case or request path. This section is retained only for a
> deliberately declared manual fallback after the bot and controller are stopped.

Only the UMI coordinator operator uses this fallback. Use a clean checkout at the
revision that will be announced and a coordinator hotkey whose public SS58 address
is already pinned in UMI's public announcement channel. Run the coordinator with
the exact Python environment used by the observer. The observer replays every
configured pilot in one process, so a different Python, Unicode, `regex`,
Bittensor, or scoring-source version cannot be added to the existing feed.
Set `PILOT_FEED_CONFIG=''` only when the observer has never served a pilot. When
the public API already lists a pilot, use its deployed config path.
Do not create the timed case from a bare readiness comment. Wait until the issue
bot has accepted the miner's signed `READY FOR CASE` proof and emitted the
HMAC-authenticated authorization marker. The `prepare` command signs and verifies
a domain-separated 32-byte possession challenge before reading the current
timelock round or creating the case directory. It fails if the selected wallet is
address-only or does not match the published coordinator hotkey.
Use one authoritative coordinator session for the campaign. Prepare no more than
two cases at once, use a distinct `HANDOFF_ROOT` for each miner, and run only one
case at a time on the current coordinator host. Before preparation, check the
public feed and the coordinator's retained case and attempt records for this miner
and campaign. Never run the same case through a second output path.
Keep this private Bash session open for the later coordinator blocks. If the
session is lost, set the same values again before continuing.

```bash
set -euo pipefail
umask 077
export UMI_REPO="/absolute/path/to/clean/umi"
export UMI_PYTHON="/absolute/path/to/the/observer/python"
export PILOT_FEED_CONFIG="/absolute/path/to/observer-pilot-feed.json"
export COORDINATOR_WALLET=YOUR_UMI_WALLET_NAME
export COORDINATOR_HOTKEY=YOUR_UMI_HOTKEY_NAME
export COORDINATOR_HOTKEY_SS58=YOUR_PUBLISHED_UMI_COORDINATOR_SS58
export COORDINATOR_WALLET_PATH="/absolute/path/to/umi/wallets"
export MINER_UID=DECIMAL_UID_FROM_ISSUE
export MINER_HOTKEY_SS58=SS58_HOTKEY_FROM_ISSUE
export HANDOFF_ROOT="/absolute/private/path/to/this-pilot"
export CASE_ROOT="$HANDOFF_ROOT/sealed-case"
export CASE_ARCHIVE="$HANDOFF_ROOT/sealed-case.tar.gz"
export RESULT_ROOT="$HANDOFF_ROOT/result"
export RESULT_JSON="$HANDOFF_ROOT/run-result.json"
export CURRENT_PILOT_INDEX="$(mktemp "${TMPDIR:-/tmp}/umi-pilot-index.XXXXXX")"
trap 'rm -f "$CURRENT_PILOT_INDEX"' EXIT

test -x "$UMI_PYTHON"
if [[ -n "$PILOT_FEED_CONFIG" ]]; then
  test -f "$PILOT_FEED_CONFIG"
fi
test -z "$(git -C "$UMI_REPO" status --porcelain=v1 --untracked-files=all)"
test ! -e "$HANDOFF_ROOT"
curl --fail --show-error --silent --max-time 30 \
  'https://api.umi.vision/api/v1/pilots?limit=256' > "$CURRENT_PILOT_INDEX"

"$UMI_PYTHON" - \
  "$PILOT_FEED_CONFIG" "$UMI_REPO" "$MINER_HOTKEY_SS58" \
  "$CURRENT_PILOT_INDEX" <<'PY'
import json
import sys
from pathlib import Path

import umi
from umi.encoding import account_id32
from umi.observer_pilot_feed import build_observer_pilot_feed
from umi.public_pilot_campaign import CAMPAIGN_ID
from umi.scoring import scoring_environment

expected_source = (Path(sys.argv[2]) / "src" / "umi").resolve(strict=True)
loaded_source = Path(umi.__file__).resolve(strict=True).parent
if loaded_source != expected_source:
    raise SystemExit(f"observer Python loaded UMI from {loaded_source}, not {expected_source}")
feed = () if not sys.argv[1] else build_observer_pilot_feed(sys.argv[1]).pilots
public_index = json.loads(Path(sys.argv[4]).read_bytes())
public_records = public_index.get("pilots")
page = public_index.get("page")
if (
    public_index.get("schema") != "umi-observer-pilots/2"
    or not isinstance(public_records, list)
    or not isinstance(page, dict)
    or page.get("total") != len(public_records)
    or page.get("returned") != len(public_records)
    or page.get("next_cursor") is not None
    or any(not isinstance(record, dict) for record in public_records)
):
    raise SystemExit("public observer did not return one complete current pilot index")
local_ids = {pilot.pilot_id for pilot in feed}
public_ids = {record.get("pilot_id") for record in public_records}
if len(public_ids) != len(public_records) or public_ids != local_ids:
    raise SystemExit("deployed observer pilot index does not match the local feed config")
miner_account = account_id32(sys.argv[3])
if any(
    pilot.public_endpoint is not None
    and pilot.public_endpoint.attestation.campaign_id == CAMPAIGN_ID
    and account_id32(pilot.miner_hotkey) == miner_account
    for pilot in feed
):
    raise SystemExit("this miner already has a result in the fixed public campaign")
print(json.dumps({
    "existing_pilot_count": len(feed),
    "existing_pilot_ids": [pilot.pilot_id for pilot in feed],
    "scoring_environment": scoring_environment(),
}, sort_keys=True, separators=(",", ":")))
PY

install -d -m 700 "$HANDOFF_ROOT"
"$UMI_PYTHON" -m umi.public_pilot_coordinator prepare \
  --output "$CASE_ROOT" \
  --wallet-name "$COORDINATOR_WALLET" \
  --hotkey "$COORDINATOR_HOTKEY" \
  --wallet-path "$COORDINATOR_WALLET_PATH" \
  --expected-coordinator-hotkey "$COORDINATOR_HOTKEY_SS58" \
  --expected-miner-uid "$MINER_UID" \
  --expected-miner-hotkey "$MINER_HOTKEY_SS58" \
  --setup-allowance 1800 \
  --response-window 300 \
  --reveal-margin 60 | tee "$HANDOFF_ROOT/prepare-result.json"

jq -e --arg coordinator "$COORDINATOR_HOTKEY_SS58" \
  '.status == "public_endpoint_pilot_case_prepared" and
   .coordinator_hotkey == $coordinator' \
  "$HANDOFF_ROOT/prepare-result.json"
tar -czf "$CASE_ARCHIVE" -C "$HANDOFF_ROOT" "$(basename "$CASE_ROOT")"

export UMI_REVISION="$(git -C "$UMI_REPO" rev-parse HEAD)"
export CASE_MANIFEST_SHA256="$(
  openssl dgst -sha256 "$CASE_ROOT/manifest.json" | awk '{print $NF}'
)"
export CASE_ARCHIVE_SHA256="$(
  openssl dgst -sha256 "$CASE_ARCHIVE" | awk '{print $NF}'
)"
test "$CASE_MANIFEST_SHA256" = \
  "$(jq -r '.manifest_sha256' "$HANDOFF_ROOT/prepare-result.json")"

"$UMI_PYTHON" - "$CASE_ROOT" <<'PY'
import json
import sys

import bittensor as bt

from umi.public_pilot_campaign import load_public_pilot_campaign

campaign = load_public_pilot_campaign(sys.argv[1])
print(json.dumps({
    "response_close_round": campaign.response_close_round,
    "response_close_utc": bt.timelock.reveal_time(
        campaign.response_close_round
    ).isoformat(),
    "reveal_round": campaign.reveal_round,
    "reveal_utc": bt.timelock.reveal_time(campaign.reveal_round).isoformat(),
}, sort_keys=True, separators=(",", ":")))
PY

printf 'UMI revision: %s\nmanifest SHA-256: %s\narchive SHA-256: %s\n' \
  "$UMI_REVISION" "$CASE_MANIFEST_SHA256" "$CASE_ARCHIVE_SHA256"
```

The automation controller uploads the archive as a create-only object at
`/public-pilot-cases/ARCHIVE_SHA256/sealed-case.tar.gz`, then uploads an
HMAC-authenticated `case_ready` result bound to the GitHub authorization. The
issue bot accepts only that configured public R2 origin and exact digest-keyed
path. The digest-keyed object MUST be new and MUST NOT be overwritten. The bot
posts the archive URL, both SHA-256 digests, pinned revision, endpoint, and
schedule from the authenticated result. Do not attach an alternate archive or
post a manual readiness handoff. Before allowing the run to continue, download
the bot-announced URL and verify its archive digest. The immutable archive is
publicly readable without repository or R2 credentials.

After the issue bot accepts the signed `READY TO ISSUE` proof, independently run
the finalized-chain preflight in
[Expose and announce the endpoint](#expose-and-announce-the-endpoint).
Confirm that at least 300 seconds remain before the announced response-close time.
The `run` command enforces this guard, so readiness must arrive before the nominal
30-minute setup allowance ends. If less time remains, let the case expire and
prepare a fresh one without issuing the old case. Otherwise, issue the case once:

```bash
set -euo pipefail
umask 077
test ! -e "$RESULT_ROOT"
test ! -e "$RESULT_JSON"

"$UMI_PYTHON" -m umi.public_pilot_coordinator run \
  --case "$CASE_ROOT" \
  --output "$RESULT_ROOT" \
  --wallet-name "$COORDINATOR_WALLET" \
  --hotkey "$COORDINATOR_HOTKEY" \
  --wallet-path "$COORDINATOR_WALLET_PATH" \
  --network finney \
  --request-timeout 240 | tee "$RESULT_JSON"

jq -e '
  .status == "public_endpoint_pilot_replay_ok" and
  (.outcome == "ok" or .outcome == "signed_error" or .outcome == "failed") and
  .translation_weights_active == false and
  .protocol_conformance == false and
  .activation_evidence == false and
  .validator_input_eligible == false' "$RESULT_JSON"
jq '{outcome, summary, miner_uid, miner_hotkey, announced_origin,
     finalized_block_number, finalized_block_hash, bundle_manifest_sha256}' \
  "$RESULT_JSON"
```

A zero exit status means the retained bundle replayed and its endpoint attestation
verified. It does not mean the translation succeeded. Inspect `.outcome` and
`.summary`, retain `RESULT_JSON`, and hand the complete immutable `RESULT_ROOT` to
the observer operator. Follow the pilot-feed procedure in
[`COMPONENT_PILOT.md`](COMPONENT_PILOT.md); do not copy selected files alone.

Once the command could have issued its request, never run it again for that case,
including after a timeout, interruption, `signed_error`, or `failed` outcome. If
the terminal state is uncertain, treat the request as issued and stop. If preflight
fails unambiguously before issuance, record that on the issue and prepare a fresh
case only after the cause is fixed.

If the command exits with `${RESULT_ROOT}.incomplete/attempt-journal` present,
verify that journal without contacting the miner again:

```bash
set -euo pipefail
export UMI_PYTHON="/absolute/path/to/the/observer/python"
export HANDOFF_ROOT="/absolute/private/path/to/this-pilot"
export RESULT_ROOT="$HANDOFF_ROOT/result"
export ATTEMPT_JOURNAL="${RESULT_ROOT}.incomplete/attempt-journal"
export ATTEMPT_JSON="$HANDOFF_ROOT/incomplete-attempt.json"

"$UMI_PYTHON" -m umi.public_pilot_coordinator inspect-attempt \
  --journal "$ATTEMPT_JOURNAL" | tee "$ATTEMPT_JSON"
jq -e '
  .status == "public_endpoint_attempt_journal_ok" and
  .attempt_count == 1 and
  .feed_eligible == false and
  .replayable_score == false and
  .translation_weights_active == false and
  .protocol_conformance == false and
  .activation_evidence == false and
  .validator_input_eligible == false' "$ATTEMPT_JSON"
```

Retain the complete `.incomplete` directory and post the inspected phase, failure
stage, request digest, and journal-manifest SHA-256 on the enrollment issue. The
journal proves which signed request was prepared and preserves any bounded response
material recorded before the later failure. It is deliberately ineligible for the
observer feed and does not become a score bundle. Do not delete it or prepare a
replacement attempt for the same miner and campaign.

If `completed_through` is `base_component_complete`, the `.incomplete` directory
also contains `base-component-bundle`. That intermediate tree lacks the signed
public-endpoint attestation. Keep it with the journal for investigation; do not
publish its score or add it to the observer feed.

## Miner prerequisites

The miner must have:

- a hotkey registered on Finney SN78 without a validator permit;
- a stable, globally routable IPv4 or IPv6 address without carrier-grade NAT and
  an inbound TCP port that can be announced for that hotkey;
- inbound TCP port 80 while obtaining or renewing an IP-address certificate;
- a valid Web PKI X.509 certificate for that literal public IP address;
- a TLS proxy that forwards only to the loopback pilot service;
- Python 3.12, Git, `curl`, `jq`, `openssl`, and the exact UMI revision
  from the case announcement;
- direct outbound DNS and HTTPS access to the case's video origin, plus direct
  outbound Finney access for the UMI environment;
- a synchronized system clock and a host that will stay awake until UMI confirms
  receipt of the response; and
- an async UMI translator or a private Unix-socket model sidecar.

Release CI exercises the protocol service on Linux x86_64 and Apple Silicon
macOS. Linux arm64 uses the same Python service but is not release-tested in CI;
its operator must complete every install and health check before asking UMI to
prepare a case. Model runtime support is the model operator's responsibility. A
Mac may use MPS in its translator, but automatic sleep must be disabled for the
full case window. CUDA miners may use any compatible CUDA stack. The model
environment does not have to match the UMI environment when the Unix-socket
boundary is used.

The pilot HTTP clients do not inherit proxy environment variables. A hostname-only
endpoint, shared CDN hostname, carrier-grade NAT address, or outbound-only tunnel
does not satisfy the chain-announced literal-IP requirement.

## Install the announced UMI revision

Use a dedicated directory and Python environment. Replace the revision with the
40-character commit published on the issue.

```bash
set -euo pipefail
umask 077
export PILOT_UMI_REVISION=40_LOWERCASE_HEX_FROM_UMI
export PILOT_ROOT="$HOME/umi-public-pilot"
export PILOT_UV_ENV="$PILOT_ROOT/uv-bootstrap"

[[ "$PILOT_UMI_REVISION" =~ ^[0-9a-f]{40}$ ]]
mkdir -p "$PILOT_ROOT"
cd "$PILOT_ROOT"
git clone https://github.com/Umi-BitSign/umi.git
git -C umi fetch --force origin "$PILOT_UMI_REVISION"
git -C umi checkout --detach "$PILOT_UMI_REVISION"
test "$(git -C umi rev-parse HEAD)" = "$PILOT_UMI_REVISION"
test -z "$(git -C umi status --porcelain=v1 --untracked-files=all)"

cd "$PILOT_ROOT/umi"
python3.12 -m venv "$PILOT_UV_ENV"
"$PILOT_UV_ENV/bin/python" -m pip install uv==0.12.9
python3.12 -m venv .venv
"$PILOT_UV_ENV/bin/uv" sync --locked
.venv/bin/python -m umi.public_pilot_miner --help >/dev/null
.venv/bin/umi-public-pilot-miner authorize --help >/dev/null
.venv/bin/python -m umi.public_pilot_coordinator --help >/dev/null
```

Keep the checkout detached and clean until the result is complete. The published
bundle records the coordinator's scoring environment. A miner response separately
binds the model revision declared below.

## Sign the READY FOR CASE payload

The bot's challenge comment shows the exact UMI revision, campaign ID, expiration,
and a `Challenge payload` token. Check those visible fields, then copy only the
token into the command below. Use the wallet name and hotkey alias that resolve to
the public miner hotkey in the enrollment issue.

Do not sign this payload until the stable HTTPS IP and port are visible as this
hotkey's axon in finalized SN78 state. The coordinator discovers and binds that
origin before it creates the case. The case-specific process may remain stopped
until the sealed archive is published.

```bash
set -euo pipefail
export PILOT_ROOT="$HOME/umi-public-pilot"
export READY_FOR_CASE_PAYLOAD='BASE64URL_TOKEN_FROM_BOT_COMMENT'
export MINER_WALLET=YOUR_WALLET_NAME
export MINER_HOTKEY=YOUR_HOTKEY_NAME

"$PILOT_ROOT/umi/.venv/bin/umi-public-pilot-miner" authorize \
  --payload-token "$READY_FOR_CASE_PAYLOAD" \
  --wallet-name "$MINER_WALLET" \
  --hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets"
```

The command checks the canonical payload encoding, field types, campaign, expiry,
and wallet identity before signing. It prints one line beginning
`UMI-PILOT-READINESS-V1`. Post that line as a new issue comment with no code fence,
prefix, suffix, or extra whitespace. Do not edit it. The signature authorizes case
preparation only. It does not authorize a request.

## Connect a model

For an in-process model, expose an importable async callable. It receives the
verified MP4 bytes and request, and returns only the English hypothesis.

```python
from umi.protocol import TranslationRequest

MODEL_REVISION = "64_lowercase_hex_characters"


class PilotTranslator:
    model_revision = MODEL_REVISION

    async def __call__(self, video: bytes, request: TranslationRequest) -> str:
        return await my_model.translate(video)


translator = PilotTranslator()
```

Install that package in the UMI environment and use
`--translator my_package.pilot:translator`. The callable must be asynchronous.
UMI intentionally provides no synchronous opt-in in this public path because a
hung Python thread cannot be terminated safely.

For a separate model environment, follow the Unix-socket contract in
[`MINER_MODEL_INTEGRATION.md`](MINER_MODEL_INTEGRATION.md). The public pilot uses
one miner inference slot. Start the sidecar first, then pass
`--translator-unix-socket /absolute/private/path/model.sock` instead of
`--translator`.

The model revision is the operator's declaration: a lowercase SHA-256 identity for
the exact model, preprocessing, decoder, and relevant inference configuration. Do
not use a random value. The translator or sidecar must return the same value
supplied to `--model-revision`, and a successful signed response and public report
carry that value. The campaign does not bind an expected model revision, and the
field alone does not attest that the named checkpoint executed.

The public S1 bootstrap is one optional backend. Its Linux and Apple Silicon
setup guides live in the `umi-reference-model` repository. The special pilot
command in this document replaces the normal `umi-miner` launch command; it does
not change the model setup or artifact checks.

### Optional Linux/AMD64 S1 r2 adapter

This adapter runs `umi-s1-public-finetune-v1-r2` for the public pilot on a
Linux/AMD64 host. First complete Sections 1 through 5 of the reference model's
[`RUN_MINER.md`](https://github.com/Umi-BitSign/umi-reference-model/blob/umi-s1-public-finetune-v1-r2/docs/RUN_MINER.md).
Use the verified tag `umi-s1-public-finetune-v1-r2`, which resolves to commit
`20307ea05684e098ab362fa6bfc174c2aced3b9e`. Those sections verify the release,
build and bind the local extractor, download the pinned MediaPipe task, run the
backend probe, and create `$HOME/umi-miner/state/reference-miner.env`.

The model's base release revision is not the revision served by a locally built
extractor. The rebind step derives a new identity for that exact local image.
Use `UMI_S1_INFERENCE_REVISION` from `reference-miner.env` everywhere this guide
asks for `MODEL_REVISION`.

The reference-model environment contains both the model and the older signed
inactive-release UMI source. Build a separate combined environment for this
pilot so imports resolve to the UMI revision announced on the enrollment issue.
The lockfile comparison below must pass. Stop if it does not; do not resolve a
dependency mismatch by changing either lockfile.

```bash
set -euo pipefail
umask 077
export PILOT_ROOT="$HOME/umi-public-pilot"
export MODEL_ROOT="$HOME/umi-miner/umi-reference-model"
export PILOT_UMI_REVISION=40_LOWERCASE_HEX_FROM_UMI
export PILOT_UV="$PILOT_ROOT/uv-bootstrap/bin/uv"
export PILOT_R2_ENV="$PILOT_ROOT/r2-venv"
export PILOT_R2_PYTHON="$PILOT_R2_ENV/bin/python"

test -x "$PILOT_UV"
test "$(git -C "$MODEL_ROOT" rev-parse HEAD)" = \
  20307ea05684e098ab362fa6bfc174c2aced3b9e
test -z "$(git -C "$MODEL_ROOT" status --porcelain=v1 --untracked-files=all)"
test "$(git -C "$PILOT_ROOT/umi" rev-parse HEAD)" = "$PILOT_UMI_REVISION"
test -z "$(git -C "$PILOT_ROOT/umi" status --porcelain=v1 --untracked-files=all)"
cmp "$HOME/umi-miner/umi/uv.lock" "$PILOT_ROOT/umi/uv.lock"
test ! -e "$PILOT_R2_ENV"

install -d -m 700 "$PILOT_ROOT/requirements"
(
  cd "$MODEL_ROOT"
  "$PILOT_UV" export --frozen --no-dev --no-emit-project \
    --output-file "$PILOT_ROOT/requirements/model.txt"
)
(
  cd "$PILOT_ROOT/umi"
  "$PILOT_UV" export --frozen --no-dev --no-emit-project \
    --output-file "$PILOT_ROOT/requirements/umi.txt"
)
"$PILOT_UV" venv --python 3.12 "$PILOT_R2_ENV"
"$PILOT_UV" pip install \
  --python "$PILOT_R2_PYTHON" \
  --require-hashes \
  --requirement "$PILOT_ROOT/requirements/model.txt" \
  --requirement "$PILOT_ROOT/requirements/umi.txt"

PURELIB="$(
  "$PILOT_R2_PYTHON" -c \
    'import sysconfig; print(sysconfig.get_paths()["purelib"])'
)"
MODEL_PTH="$PURELIB/umi-reference-model-source.pth"
PILOT_UMI_PTH="$PURELIB/umi-public-pilot-source.pth"
printf '%s\n' "$MODEL_ROOT/src" > "$MODEL_PTH"
printf '%s\n' "$PILOT_ROOT/umi/src" > "$PILOT_UMI_PTH"
chmod 600 "$MODEL_PTH" "$PILOT_UMI_PTH"
unset PYTHONPATH

"$PILOT_R2_PYTHON" - "$MODEL_ROOT" "$PILOT_ROOT/umi" <<'PY'
import sys
from pathlib import Path

import bitsign_motion
import umi

model_root = Path(sys.argv[1]).resolve(strict=True)
umi_root = Path(sys.argv[2]).resolve(strict=True)
assert Path(bitsign_motion.__file__).resolve().is_relative_to(model_root)
assert Path(umi.__file__).resolve().is_relative_to(umi_root)
PY

source "$HOME/umi-miner/state/reference-miner.env"
PROBE="$(
  "$PILOT_R2_PYTHON" -m bitsign_motion.umi_reference_backend probe
)"
printf '%s\n' "$PROBE" | jq .
printf '%s\n' "$PROBE" | jq -e \
  --arg revision "$UMI_S1_INFERENCE_REVISION" '
  .status == "ready" and
  .claim_status == "component_test_no_weight" and
  .inference_revision == $revision'
```

Prepare this environment before the case arrives. After completing **Verify the
sealed case** below, return here and use this command instead of the generic
**Start the exact-case miner** command:

```bash
set -euo pipefail
umask 077
export PILOT_ROOT="$HOME/umi-public-pilot"
export PILOT_R2_PYTHON="$PILOT_ROOT/r2-venv/bin/python"
export CASE_ROOT="$PILOT_ROOT/case"
export MINER_WALLET=YOUR_WALLET_NAME
export MINER_HOTKEY=YOUR_HOTKEY_NAME
source "$HOME/umi-miner/state/reference-miner.env"
export MODEL_REVISION="$UMI_S1_INFERENCE_REVISION"

install -d -m 700 "$PILOT_ROOT/state"
"$PILOT_R2_PYTHON" -m umi.public_pilot_miner \
  --case "$CASE_ROOT" \
  --wallet-name "$MINER_WALLET" \
  --hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets" \
  --translator bitsign_motion.umi_reference_backend:translator \
  --model-revision "$MODEL_REVISION" \
  --video-origin https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev \
  --nonce-db "$PILOT_ROOT/state/nonces.sqlite3" \
  --assignment-db "$PILOT_ROOT/state/assignments.sqlite3" \
  --inference-timeout 180 \
  --backend-lifecycle-timeout 60 \
  --listen-host 127.0.0.1 \
  --port 8091
```

Run the local and public health checks below with
`MODEL_REVISION="$UMI_S1_INFERENCE_REVISION"`. Keep
`reference-miner.env` loaded in the terminal that runs the service.

## Verify the sealed case

UMI publishes a digest-keyed public R2 URL and both announced hashes only after the
operator is ready. Copy the public URL from UMI's unedited
issue comment. The default case leaves 30 minutes for setup and five minutes for
the response, then waits one minute before reveal. Do not reuse an expired case.

```bash
set -euo pipefail
umask 077
export PILOT_ROOT="$HOME/umi-public-pilot"
export CASE_ARCHIVE_URL='HTTPS_R2_URL_FROM_THE_UMI_BOT'
export CASE_ARCHIVE="$PILOT_ROOT/case.tar.gz"
export CASE_ARCHIVE_PART="$PILOT_ROOT/.case.tar.gz.download"
export CASE_ARCHIVE_SHA256=64_LOWERCASE_HEX_FROM_UMI
export CASE_MANIFEST_SHA256=64_LOWERCASE_HEX_FROM_UMI
export CASE_ROOT="$PILOT_ROOT/case"

test ! -e "$CASE_ARCHIVE"
test ! -e "$CASE_ARCHIVE_PART"
curl --fail --location --show-error --silent \
  --proto '=https' \
  --proto-redir '=https' \
  --max-filesize 100663296 \
  --max-time 60 \
  --output "$CASE_ARCHIVE_PART" \
  "$CASE_ARCHIVE_URL"
test "$(openssl dgst -sha256 "$CASE_ARCHIVE_PART" | awk '{print $NF}')" = \
  "$CASE_ARCHIVE_SHA256"
mv "$CASE_ARCHIVE_PART" "$CASE_ARCHIVE"

"$PILOT_ROOT/umi/.venv/bin/python" - "$CASE_ARCHIVE" "$CASE_ROOT" <<'PY'
import sys
from pathlib import Path

from umi.public_pilot_archive import extract_evidence_archive

extract_evidence_archive(
    Path(sys.argv[1]),
    Path(sys.argv[2]),
    archive_root="sealed-case",
)
PY

test "$(openssl dgst -sha256 "$CASE_ROOT/manifest.json" | awk '{print $NF}')" = \
  "$CASE_MANIFEST_SHA256"
"$PILOT_ROOT/umi/.venv/bin/python" -m umi.public_pilot_coordinator \
  inspect-case \
  --case "$CASE_ROOT"
```

Check that the printed UID and hotkey are yours and that the coordinator hotkey
matches the one in UMI's pinned announcement. The command checks the sealed case's
static campaign metadata and content bindings. It does not check the current time.
Compare the announced response-close time with a synchronized clock before
continuing. Miner startup rejects a case after its response-close round.

## Start the exact-case miner

Create durable private state. Do not place the databases in `/tmp` or in a shared
directory.

```bash
set -euo pipefail
umask 077
export PILOT_ROOT="$HOME/umi-public-pilot"
export CASE_ROOT="$PILOT_ROOT/case"
export MODEL_REVISION=64_LOWERCASE_HEX_FROM_YOUR_MODEL_RELEASE
export MODEL_TRANSLATOR=my_package.pilot:translator
export MINER_WALLET=YOUR_WALLET_NAME
export MINER_HOTKEY=YOUR_HOTKEY_NAME

install -d -m 700 "$PILOT_ROOT/state"
"$PILOT_ROOT/umi/.venv/bin/python" -m umi.public_pilot_miner \
  --case "$CASE_ROOT" \
  --wallet-name "$MINER_WALLET" \
  --hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets" \
  --translator "$MODEL_TRANSLATOR" \
  --model-revision "$MODEL_REVISION" \
  --video-origin https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev \
  --nonce-db "$PILOT_ROOT/state/nonces.sqlite3" \
  --assignment-db "$PILOT_ROOT/state/assignments.sqlite3" \
  --listen-host 127.0.0.1 \
  --port 8091
```

The process refuses a wallet other than the case's miner hotkey. It accepts only
the exact case request signed by the case's coordinator hotkey. It also enforces
durable nonce replay protection, assignment limits, one inference slot, response
timelocking, response signing, video digest verification, and bounded request,
response, fetch, and inference limits.

In another terminal, check local health:

```bash
export MODEL_REVISION=64_LOWERCASE_HEX_FROM_YOUR_MODEL_RELEASE

curl --fail --show-error --silent \
  --connect-timeout 3 \
  --max-time 10 \
  --max-filesize 65536 \
  http://127.0.0.1:8091/healthz | \
  jq -e --arg model_revision "$MODEL_REVISION" '
  .ok == true and
  .runtime_mode == "public_component_pilot" and
  .translation_weights_active == false and
  .protocol_conformance == false and
  .activation_evidence == false and
  .model_revision == $model_revision and
  .window_authority == "ExactComponentWindowAuthority" and
  .finality_service == "component_authority"'
```

## Expose and announce the endpoint

Terminate TLS at a hardened reverse proxy or IP-level edge and forward to
`127.0.0.1:8091`. The repository includes a concrete Caddy 2.10-or-later example
at
[`deploy/public-endpoint-pilot/Caddyfile.example`](../deploy/public-endpoint-pilot/Caddyfile.example).
The proxy must:

- present a certificate whose subject alternative name contains the exact public
  IP contacted by validators;
- preserve `POST /v1/translate`, the body bytes, request target, Host header, and
  all `X-Bittensor-*` headers;
- disable redirects, request-body transformations, and response compression;
- accept at most 16 KiB of request headers and 64 KiB of request body;
- enforce finite header, body, connection, and upstream timeouts; and
- expose no local database, wallet, model, case object, or filesystem path.

One certificate path is Certbot 5.4 or later with Let's Encrypt's short-lived IP
address profile. Port 80 must be reachable at the same public IP and free for the
standalone HTTP-01 listener while these commands run:

```bash
export PUBLIC_IP=YOUR_BARE_PUBLIC_IP_WITHOUT_IPV6_BRACKETS

certbot --version
sudo certbot certonly \
  --standalone \
  --preferred-profile shortlived \
  --ip-address "$PUBLIC_IP"
sudo certbot certificates
```

Use the certificate and private-key paths printed by `certbot certificates` in
the TLS proxy. Certbot obtains the files but does not install them in the proxy.
Configure an automatic `certbot renew` schedule and a successful deploy hook that
reloads the proxy, then test it with `sudo certbot renew --dry-run`. These IP
certificates are valid for six days. Follow Let's Encrypt's
[`Certbot IP-address certificate instructions`](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)
before exposing the service.

For the checked-in Caddy example, set the three environment variables consumed by
the file in the Caddy service manager, validate the installed configuration with
the same environment, and reload Caddy. `PILOT_PUBLIC_ORIGIN` is the complete
literal-IP HTTPS origin, including brackets around IPv6 and the public port. The
certificate files must be readable by the Caddy service account. Do not start a
second foreground Caddy process on an address already owned by the service.

```bash
set -euo pipefail
export PILOT_ROOT="$HOME/umi-public-pilot"
export PILOT_PUBLIC_ORIGIN=https://YOUR_LITERAL_IP_WITH_REQUIRED_IPV6_BRACKETS:YOUR_PUBLIC_PORT
export PILOT_TLS_CERTIFICATE=/etc/letsencrypt/live/YOUR_CERT_NAME/fullchain.pem
export PILOT_TLS_PRIVATE_KEY=/etc/letsencrypt/live/YOUR_CERT_NAME/privkey.pem

CADDY_VERSION="$(caddy version)"
python3.12 - "$CADDY_VERSION" <<'PY'
import re
import sys

match = re.match(r"^v?(\d+)[.](\d+)[.](\d+)(?:\s|$)", sys.argv[1])
if match is None or tuple(map(int, match.groups())) < (2, 10, 0):
    raise SystemExit(f"Caddy 2.10.0 or later is required, found {sys.argv[1]!r}")
PY
sudo --preserve-env=PILOT_PUBLIC_ORIGIN,PILOT_TLS_CERTIFICATE,PILOT_TLS_PRIVATE_KEY \
  caddy validate \
  --config "$PILOT_ROOT/umi/deploy/public-endpoint-pilot/Caddyfile.example" \
  --adapter caddyfile
```

The version output must be Caddy 2.10 or later because the body-limit directive
was introduced in 2.10. The example exposes only `GET`/`HEAD /healthz` and
`POST /v1/translate`; it deliberately has no rewrite or request-header mutation.
How the validated file and environment are installed and reloaded depends on the
host's service manager. Record that exact reload command as Certbot's deploy hook.

From another network, verify the public origin. An IPv6 literal must be enclosed
in brackets in an HTTPS URL, while `btcli --ip` takes the bare address:

```bash
set -euo pipefail
export PUBLIC_IP=YOUR_BARE_PUBLIC_IPV4_OR_IPV6
export PUBLIC_PORT=YOUR_PUBLIC_PORT
export MODEL_REVISION=64_LOWERCASE_HEX_FROM_YOUR_MODEL_RELEASE

if [[ "$PUBLIC_IP" == *:* ]]; then
  export PUBLIC_ORIGIN="https://[$PUBLIC_IP]:$PUBLIC_PORT"
else
  export PUBLIC_ORIGIN="https://$PUBLIC_IP:$PUBLIC_PORT"
fi

curl --fail --show-error --silent \
  --connect-timeout 10 \
  --max-time 30 \
  --max-filesize 65536 \
  "$PUBLIC_ORIGIN/healthz" | \
  jq -e --arg model_revision "$MODEL_REVISION" '
  .ok == true and
  .runtime_mode == "public_component_pilot" and
  .translation_weights_active == false and
  .protocol_conformance == false and
  .activation_evidence == false and
  .model_revision == $model_revision and
  .window_authority == "ExactComponentWindowAuthority" and
  .finality_service == "component_authority"'
```

If the current chain axon is missing or different, the registered hotkey owner can
publish the endpoint. This is hotkey-signed; it does not require the subnet owner.
First preview the write, then submit it:

```bash
set -euo pipefail
export PILOT_ROOT="$HOME/umi-public-pilot"
export PUBLIC_IP=YOUR_BARE_PUBLIC_IPV4_OR_IPV6
export PUBLIC_PORT=YOUR_PUBLIC_PORT
export MINER_WALLET=YOUR_WALLET_NAME
export MINER_HOTKEY=YOUR_HOTKEY_NAME
export BTCLI="$PILOT_ROOT/umi/.venv/bin/btcli"

SERVE_AXON_ARGS=(
  --netuid 78
  --ip "$PUBLIC_IP"
  --port "$PUBLIC_PORT"
  --network finney
  --wallet "$MINER_WALLET"
  --wallet-hotkey "$MINER_HOTKEY"
  --wallet-path "$HOME/.bittensor/wallets"
  --no-mev-shield
)

"$BTCLI" tx serve-axon "${SERVE_AXON_ARGS[@]}" --dry-run
"$BTCLI" tx serve-axon "${SERVE_AXON_ARGS[@]}"
```

Use plain `serve-axon` for this pilot. `serve-axon-tls` publishes a compact neuron
certificate public key on chain. That value is not an X.509 certificate and does
not establish the Web PKI HTTPS connection required here.

Wait for the serve transaction to finalize, then run the same finalized discovery
used by the coordinator. Fill in the SS58 address and decimal UID from the issue:

```bash
set -euo pipefail
export PILOT_PYTHON="/absolute/path/to/announced/umi/.venv/bin/python"
export MINER_HOTKEY_SS58=YOUR_PUBLIC_SS58_HOTKEY
export MINER_UID=YOUR_DECIMAL_SN78_UID
export PUBLIC_IP=YOUR_BARE_PUBLIC_IPV4_OR_IPV6
export PUBLIC_PORT=YOUR_PUBLIC_PORT

if [[ "$PUBLIC_IP" == *:* ]]; then
  export PUBLIC_ORIGIN="https://[$PUBLIC_IP]:$PUBLIC_PORT"
else
  export PUBLIC_ORIGIN="https://$PUBLIC_IP:$PUBLIC_PORT"
fi

CHAIN_RESULT="$("$PILOT_PYTHON" - "$MINER_HOTKEY_SS58" <<'PY'
import asyncio
import json
import sys
from dataclasses import asdict

from umi.chain import discover_miner_finalized

endpoint = asyncio.run(
    discover_miner_finalized(sys.argv[1], network="finney", netuid=78)
)
print(json.dumps(asdict(endpoint), sort_keys=True, separators=(",", ":")))
PY
)"

printf '%s\n' "$CHAIN_RESULT" | jq -e \
  --arg hotkey "$MINER_HOTKEY_SS58" \
  --arg origin "$PUBLIC_ORIGIN" \
  --argjson uid "$MINER_UID" '
    .network == "finney" and
    .hotkey == $hotkey and
    .uid == $uid and
    .origin == $origin and
    .validator_permit == false'
printf '%s\n' "$CHAIN_RESULT" | jq \
  '{hotkey, uid, origin, validator_permit,
    finalized_block_number, finalized_block_hash}'
```

Compare `CHAIN_RESULT` with the bot's `READY TO ISSUE` challenge. The challenge
must name the same literal-IP HTTPS origin and the manifest SHA-256 from the case
you loaded. It also binds the prior case authorization. If any value differs, do
not sign it.

Copy the new `Challenge payload` token and sign it with the same miner hotkey:

```bash
set -euo pipefail
export PILOT_ROOT="$HOME/umi-public-pilot"
export READY_TO_ISSUE_PAYLOAD='BASE64URL_TOKEN_FROM_BOT_COMMENT'
export MINER_WALLET=YOUR_WALLET_NAME
export MINER_HOTKEY=YOUR_HOTKEY_NAME

"$PILOT_ROOT/umi/.venv/bin/umi-public-pilot-miner" authorize \
  --payload-token "$READY_TO_ISSUE_PAYLOAD" \
  --wallet-name "$MINER_WALLET" \
  --hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets"
```

Post the command's exact single-line `UMI-PILOT-READINESS-V1 ...` output as a
new comment without other text. Do not edit the issue or proof comment while the
authorization is pending. This is the one-shot request authorization. UMI resolves
the endpoint again from finalized chain state; the coordinator has no command-line
endpoint override. You may post the finalized block number and hash separately for
operator context, but that prose does not authorize issuance.

## What UMI publishes

An ordinary miner request outcome is a signed response or a bounded canonical
failure. If reveal, scoring, public-endpoint attestation, and publication all
finish, the completed public bundle includes:

- the exact request and `btauth/1` record;
- the miner-signed timelock envelope and revealed plaintext, when the miner
  returned a structurally valid signed response;
- the ground-truth timelock and revealed references;
- every edit-distance input, trace, and exact rational score;
- the observed finalized block, UID, hotkey, permit, and chain-announced origin;
- a coordinator signature over the public endpoint attestation; and
- explicit false flags for conformance, activation evidence, validator input, and
  translation weights.

The chain observation is an internally cross-checked finalized Bittensor SDK read.
It is labeled `storage_proofs_verified: false`. The response receipt time and claim
that UMI made no omitted attempt remain coordinator assertions. The signature
authenticates those assertions; it does not turn them into chain proofs.

Anyone can replay a published bundle with the exact announced UMI revision:

```bash
export PILOT_PYTHON="/absolute/path/to/announced/umi/.venv/bin/python"

"$PILOT_PYTHON" -m umi.public_pilot_coordinator replay \
  --bundle /absolute/path/to/downloaded/bundle
```

Public results appear only under `GET https://api.umi.vision/api/v1/pilots`. They
never populate `/windows`, change the translation leaderboard, or activate
weights.

After the exact public checks in `COMPONENT_PILOT.md` pass, the controller uploads
one immutable, HMAC-authenticated `pilot_complete` result. Scheduled issue-bot
reconciliation posts its fixed summary and evidence URL if the direct workflow
run ended first. Close the issue only after the evidence and observer URLs work
without GitHub or observer credentials. An outcome classified as `signed_error`
or `failed` is not a successful translation.

If request sending raises after possible contact, or a later local reveal,
attachment, or publication step fails, the controller verifies and uploads the
retained journal and an authenticated `pilot_incomplete` result. The bot posts a
fixed non-feed summary and attempt-journal URL. That summary does not appear under
`/pilots`, carries no replayable score, and does not permit a retry.

## Restore or clear the serving record

Keep the miner and TLS proxy available until UMI confirms that it received the
response. After that confirmation, restore the hotkey's previous production axon
or clear the temporary pilot axon. Do not leave the chain pointing at a stopped
pilot service.

Both `serve-axon` and `reset-axon` are chain writes subject to the subnet's serving
rate limit. Query the current value before changing a production record; do not
assume the value from an earlier pilot:

```bash
set -euo pipefail
export PILOT_ROOT="$HOME/umi-public-pilot"
export BTCLI="$PILOT_ROOT/umi/.venv/bin/btcli"

"$BTCLI" subnets metagraph 78 --network finney --json | \
  jq -e '.serving_rate_limit'
```

Changing an existing production axon for the pilot interrupts that endpoint, and
the rate limit can delay restoration. Record the old IP and port before the pilot
and plan the maintenance window. To restore an old endpoint, preview and then
submit one `serve-axon` transaction with the recorded values:

```bash
set -euo pipefail
export PILOT_ROOT="$HOME/umi-public-pilot"
export BTCLI="$PILOT_ROOT/umi/.venv/bin/btcli"
export MINER_WALLET=YOUR_WALLET_NAME
export MINER_HOTKEY=YOUR_HOTKEY_NAME

"$BTCLI" tx serve-axon \
  --netuid 78 \
  --ip PREVIOUS_PUBLIC_IP \
  --port PREVIOUS_PUBLIC_PORT \
  --network finney \
  --wallet "$MINER_WALLET" \
  --wallet-hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets" \
  --no-mev-shield \
  --dry-run

"$BTCLI" tx serve-axon \
  --netuid 78 \
  --ip PREVIOUS_PUBLIC_IP \
  --port PREVIOUS_PUBLIC_PORT \
  --network finney \
  --wallet "$MINER_WALLET" \
  --wallet-hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets" \
  --no-mev-shield
```

If there was no prior endpoint, preview and then submit `reset-axon` instead:

```bash
set -euo pipefail
export PILOT_ROOT="$HOME/umi-public-pilot"
export BTCLI="$PILOT_ROOT/umi/.venv/bin/btcli"
export MINER_WALLET=YOUR_WALLET_NAME
export MINER_HOTKEY=YOUR_HOTKEY_NAME

"$BTCLI" tx reset-axon \
  --netuid 78 \
  --network finney \
  --wallet "$MINER_WALLET" \
  --wallet-hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets" \
  --no-mev-shield \
  --dry-run

"$BTCLI" tx reset-axon \
  --netuid 78 \
  --network finney \
  --wallet "$MINER_WALLET" \
  --wallet-hotkey "$MINER_HOTKEY" \
  --wallet-path "$HOME/.bittensor/wallets" \
  --no-mev-shield
```

Choose one branch. Do not reset and immediately try to republish the previous
endpoint, because the second transaction can be rejected by the serving rate
limit. Wait for finality and verify the resulting record before shutting down the
TLS proxy.

## Failure rules

Do not silently replace failed inference with a canned translation. UMI accepts a
signed encrypted error as an ordinary protocol response. Its error code and zero
score appear in a completed bundle if the remaining local steps finish. A timeout,
bad signature, malformed envelope, wrong identity, or unreachable endpoint likewise
becomes a bounded failure when the coordinator reaches reveal and publication. A
later local coordinator failure uses the preserved non-feed journal procedure
above.

If finalized chain discovery fails before a request is issued, no pilot bundle
exists. UMI records the preflight reason on the public enrollment issue and does
not claim that the endpoint was tested. A fresh case may be prepared after the
operator fixes the registration or axon.
