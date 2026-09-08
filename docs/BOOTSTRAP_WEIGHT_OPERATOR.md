# Operate the seven-day SN78 bootstrap service row

This runbook covers the temporary `bootstrap_service_binary` path in
[BOOTSTRAP_WEIGHT_ADDENDUM.md](BOOTSTRAP_WEIGHT_ADDENDUM.md). It does not start
translation scoring. A successful public endpoint pilot and a post-publication
miner opt-in produce binary service eligibility. Every eligible hotkey receives
the same raw u16 value, `65535`.

Call the bootstrap live only after one validator's exact entry has left its queue,
the finalized reveal event exists, the stored MechId 0 row byte-matches the signed
manifest, and the terminal bundle is public. Commit acceptance alone leaves it
pending.

## Roles and authority

| Role | Required action | Authority boundary |
|---|---|---|
| Release operator | Publish the addendum, pinned UMI revision, concrete policy, and policy hash | No wallet or chain write |
| Miner | Sign one policy-bound opt-in with the hotkey from its successful public endpoint pilot | Does not choose a UID, row, or deadline |
| Coordinator | Verify every opt-in and pilot, check finalized chain state and HTTPS health, then sign the complete manifest | Cannot submit validator weights |
| SN78 owner | Change `WeightsVersionKey` from `0` to `1` after policy publication | Cannot restore the root-controlled subnet-emission flag |
| Validator | Verify the complete input, anchor the manifest hash, submit the exact raw CRv4 row, and publish terminal evidence | Must hold the permit and hotkey it uses |
| Const/root operator | Restore `subnet_emission_enabled` after an applied row and its evidence are public | The SN78 owner cannot perform this call |

Repository tooling cannot supply four external authorizations: miner opt-in
signatures, the owner-signed version change, a permitted validator's hotkey
submission, or Const/root's emission-restoration call. Old pending entries and
active rows must also clear on chain. Treat each as a launch dependency with a
named operator and status.

Use a clean checkout at the revision named by the public release. Replace every
uppercase placeholder and sample absolute path below. Do not publish wallet names,
wallet paths, passwords, or keys.

### Preferred pinned container

The preferred validator and coordinator runtime is the repository's linux/amd64
image. It fixes CPython 3.12.14, uv 0.12.9, Bittensor 11.1.0, regex 2026.9.3,
and the scoring source hash used by the published pilot bundles.

```bash
test "$(id -u)" -ne 0
git clone git@github.com:Umi-BitSign/umi.git
cd umi
git checkout --detach PINNED_UMI_REVISION
test -z "$(git status --porcelain=v1 --untracked-files=all)"
docker build \
  --platform linux/amd64 \
  --build-arg UMI_GIT_REVISION=PINNED_UMI_REVISION \
  --file deploy/bootstrap-validator/Dockerfile \
  --tag umi-bootstrap-validator:PINNED_UMI_REVISION \
  .
docker run --rm --platform linux/amd64 \
  --entrypoint cat \
  umi-bootstrap-validator:PINNED_UMI_REVISION \
  /opt/umi-image-revision
```

The last command must print the pinned revision. The image defaults to UID/GID
65532. The examples below override it with the invoking user's unprivileged IDs so
bind-mounted output remains writable; never run the operator as root. Create
separate input and output directories. Mount public inputs read-only and the
output directory read-write. Read-only commands receive no wallet mount:

```bash
docker run --rm --platform linux/amd64 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --mount type=bind,src=/absolute/path/to/inputs,dst=/inputs,readonly \
  --mount type=bind,src=/absolute/private/path/to/outputs,dst=/outputs \
  umi-bootstrap-validator:PINNED_UMI_REVISION \
  verify-manifest --manifest /inputs/signed-manifest.json \
  --current-block CURRENT_FINALIZED_BLOCK
```

Add the wallet directory as a read-only mount only for `opt-in`, `manifest`,
`submit`, `terminal`, or `sunset-status`:

```bash
docker run --rm -it --platform linux/amd64 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --mount type=bind,src=/absolute/path/to/inputs,dst=/inputs,readonly \
  --mount type=bind,src=/absolute/private/path/to/outputs,dst=/outputs \
  --mount type=bind,src=/absolute/path/to/wallets,dst=/wallets,readonly \
  umi-bootstrap-validator:PINNED_UMI_REVISION \
  opt-in --policy /inputs/policy.json \
  --pilot-id PILOT_ID_64_LOWERCASE_HEX \
  --signed-at-block CURRENT_FINALIZED_BLOCK \
  --output /outputs/opt-in.json \
  --wallet-name YOUR_MINER_WALLET_NAME \
  --hotkey YOUR_MINER_HOTKEY_NAME \
  --wallet-path /wallets
```

Use the same mount pattern for the later commands, changing only the subcommand
and paths. For `submit`, mount one persistent private directory read-write at
`/state` and pass `--state-dir /state`. Do not mount the repository, SSH agent,
Docker socket, or unrelated wallets into the container. The command needs outbound
HTTPS and Finney access for pilot replay, health checks, finalized reads, and live
submission.

### Equivalent native environment

The native path must reproduce the same interpreter and locked environment:

```bash
test "$(id -u)" -ne 0
test "$(uv --version | awk '{print $1 " " $2}')" = "uv 0.12.9"
uv python install 3.12.14
UV_PROJECT_ENVIRONMENT=.venv \
  uv sync --locked --no-dev --python 3.12.14
.venv/bin/python --version
.venv/bin/umi-bootstrap-weights --help
```

The Python command must print `Python 3.12.14`. Public pilot replay is bound to
that CPython version and the lockfile's exact `regex`, Bittensor, and scoring
environment. Another interpreter can reject a valid published bundle or produce a
different replay result. Install uv 0.12.9 through a trusted distribution channel
before running this block. Keep every policy, input, output, receipt, and state
directory outside the checkout. Chain-reading operator commands reject a dirty or
revision-mismatched native checkout, including untracked files.

## 1. Publish and verify the policy

Publish these immutable objects together:

- the pinned 40-character UMI revision;
- this addendum and runbook from that revision;
- the canonical `umi-bootstrap-weight-policy/1` object;
- its domain-separated `policy_sha256`;
- the finalized `published_at_block` header and hash;
- the miner opt-in instructions and evidence origin; and
- the exact `activation_block`, `commit_stop_block`, and `hard_sunset_block` in
  both block and estimated UTC form.

The concrete policy must use Finney, netuid 78, MechId 0,
`weights_version_key: 1`, `translation_weights_active: false`, and
`service_weights_active: true`. Its activation-to-sunset interval must be exactly
50,400 blocks. Its final 1,440 blocks are terminal clearance, during which no new
commit is allowed.

Create the canonical policy after selecting finalized publication and schedule
blocks:

```bash
.venv/bin/umi-bootstrap-weights policy \
  --campaign-id 483f38fc41356d3272bf95a0e47ae1f0aadbc1fec7ac2b5014631ce5097b847a \
  --public-evidence-origin https://api.umi.vision \
  --coordinator-hotkey 5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4 \
  --umi-git-revision PINNED_UMI_REVISION \
  --weights-version-key 1 \
  --published-at-block FINALIZED_PUBLICATION_BLOCK \
  --activation-block FUTURE_ACTIVATION_BLOCK \
  --commit-stop-block FIXED_COMMIT_STOP_BLOCK \
  --hard-sunset-block FIXED_HARD_SUNSET_BLOCK \
  --health-ttl-blocks POLICY_HEALTH_TTL_BLOCKS \
  --manifest-ttl-blocks POLICY_MANIFEST_TTL_BLOCKS \
  --output /absolute/path/to/policy.json
```

The command enforces the fixed 50,400-block active interval and 1,440-block
terminal clearance. It refuses to replace an existing output file.

Check the downloaded policy before asking anyone to sign it:

```bash
.venv/bin/python - /absolute/path/to/policy.json <<'PY'
import sys
from pathlib import Path

from umi.bootstrap_weights import BootstrapWeightPolicy, bootstrap_policy_hash
from umi.protocol import canonical_json_bytes

path = Path(sys.argv[1])
raw = path.read_bytes()
policy = BootstrapWeightPolicy.model_validate_json(raw, strict=True)
if canonical_json_bytes(policy) != raw:
    raise SystemExit("policy is not exact RFC 8785 bytes")
print(bootstrap_policy_hash(policy))
PY
```

The printed value must match the published `policy_sha256`. A policy published
after its own `published_at_block`, an unpublished revision, or a hash mismatch
stops the launch.

## 2. Owner cutover to WeightsVersionKey 1

The SN78 owner performs this after the policy is public. First preview the exact
owner call:

```bash
.venv/bin/btcli tx set-hyperparameter \
  --network finney \
  --netuid 78 \
  --name weights_version \
  --value 1 \
  --wallet YOUR_OWNER_WALLET_NAME \
  --wallet-path /absolute/path/to/wallets \
  --dry-run
```

Review the signer, netuid, parameter, old value, and new value. Submit the same
call without `--dry-run`:

```bash
.venv/bin/btcli tx set-hyperparameter \
  --network finney \
  --netuid 78 \
  --name weights_version \
  --value 1 \
  --wallet YOUR_OWNER_WALLET_NAME \
  --wallet-path /absolute/path/to/wallets \
  --yes
```

Retain the extrinsic hash, finalized block, block hash, and events. Verify the
finalized value independently:

```bash
.venv/bin/btcli subnets hyperparameters 78 \
  --network finney \
  --json
```

Do not reuse version `0`, and reserve version `2` for the later governed
translation mechanism. The owner must not claim that this change restores
emission or activates translation weights.

## 3. Clear old MechId 0 state

Before the first bootstrap commit, all pre-bootstrap MechId 0 pending entries
must be gone and all old rows must be inactive. Each participating validator must
also have no unresolved event-ledger entry.

These reads are useful for triage:

```bash
.venv/bin/btcli query timelocked-weight-commits \
  --network finney --netuid 78 --mechid 0 --json
.venv/bin/btcli query weights \
  --network finney --netuid 78 --mechid 0 --json
.venv/bin/btcli query metagraph \
  --network finney --netuid 78 --json
.venv/bin/btcli subnets hyperparameters 78 \
  --network finney --json
```

These commands help identify a clean cutover block. Freeze the coherent finalized
SDK checkpoint only after the old state is clear:

```bash
.venv/bin/umi-bootstrap-weights cutover \
  --policy /absolute/path/to/policy.json \
  --checkpoint-block CLEAN_FINALIZED_CUTOVER_BLOCK \
  --output /absolute/path/to/cutover-checkpoint.json
```

Publish the canonical checkpoint with its block and hash. Its
`storage_proofs_verified` field is deliberately `false`. This reduced-trust
bootstrap accepts repeatable finalized SDK observations; it does not inherit that
exception into translation-weight activation or earn Section 14 credit. Every
validator replays the checkpoint before submission.

## 4. Collect miner opt-ins

Only a miner with a successful replayable `public_endpoint` pilot may opt in. A
local component pilot, an enrollment issue, or an old `READY FOR CASE` comment is
insufficient. The opt-in must be signed after the policy was published, using the
same hotkey named by the pilot.

The miner runs:

```bash
.venv/bin/umi-bootstrap-weights opt-in \
  --policy /absolute/path/to/policy.json \
  --pilot-id PILOT_ID_64_LOWERCASE_HEX \
  --signed-at-block CURRENT_FINALIZED_BLOCK \
  --output /absolute/private/path/to/opt-in.json \
  --wallet-name YOUR_MINER_WALLET_NAME \
  --hotkey YOUR_MINER_HOTKEY_NAME \
  --wallet-path /absolute/path/to/wallets
```

The miner publishes `opt-in.json` in its existing enrollment issue. The
coordinator checks its canonical bytes, signature, policy hash, pilot ID, hotkey,
and block bounds, then records the public receipt time and surrounding finalized
block. Never infer consent from a pilot completed before policy publication.

## 5. Freeze and sign one complete manifest

At one finalized freeze block, the coordinator must:

1. enumerate every valid opt-in received before that block;
2. replay each referenced public pilot from `https://api.umi.vision`;
3. verify current SN78 registration, UID, lack of validator permit, and exact
   chain-announced HTTPS origin;
4. perform a bounded, no-redirect `GET /healthz`, validate the public-IP TLS
   certificate, and retain the response and certificate evidence; and
5. produce one canonical `BootstrapEligibilityEntry` per eligible miner.

After the replay, chain, and health evidence has been captured and reviewed, build
each schema-checked entry:

```bash
.venv/bin/umi-bootstrap-weights entry \
  --policy /absolute/path/to/policy.json \
  --opt-in /absolute/path/to/opt-in.json \
  --uid MINER_UID \
  --origin https://PUBLIC_IP:443 \
  --pilot-block FINALIZED_PILOT_BLOCK \
  --health-block FINALIZED_HEALTH_OBSERVATION_BLOCK \
  --output /absolute/path/to/entry-1.json
```

The `entry` command verifies the opt-in and local field bindings. It does not
fetch or replay the pilot, query chain state, or perform the health request. A
reviewed evidence producer must supply those inputs. Do not infer them or hand-edit
the entry. Missing pilot-replay or health evidence blocks manifest publication.

Once those exact canonical entry files exist, sign the complete manifest:

```bash
.venv/bin/umi-bootstrap-weights manifest \
  --policy /absolute/path/to/policy.json \
  --entry /absolute/path/to/entry-1.json \
  --entry /absolute/path/to/entry-2.json \
  --frozen-at-block FINALIZED_FREEZE_BLOCK \
  --frozen-at-block-hash 0xFINALIZED_BLOCK_HASH \
  --output /absolute/private/path/to/signed-manifest.json \
  --wallet-name YOUR_COORDINATOR_WALLET_NAME \
  --hotkey YOUR_COORDINATOR_HOTKEY_NAME \
  --wallet-path /absolute/path/to/wallets
```

Add another `--entry` argument for every eligible miner. The command rejects an
empty row, duplicates, stale health, bad opt-ins, and an unequal raw row. It sorts
entries by decoded miner account and the row by UID. Publish the signed manifest,
all entries, all opt-ins considered, replay reports, health evidence, and
omitted-miner reason records at the public evidence origin.

Anyone can verify the signed object without a wallet:

```bash
.venv/bin/umi-bootstrap-weights verify-manifest \
  --manifest /absolute/path/to/signed-manifest.json \
  --current-block CURRENT_FINALIZED_BLOCK
```

## 6. Validator read-only preflight

Each participating validator independently downloads and verifies every public
object. It must repeat every pilot replay, chain mapping check, and HTTPS health
check even when the coordinator signature is valid.

Run the finalized-chain preflight with the validator's public hotkey address:

```bash
.venv/bin/umi-bootstrap-weights preflight \
  --manifest /absolute/path/to/signed-manifest.json \
  --cutover-checkpoint /absolute/path/to/cutover-checkpoint.json \
  --validator-hotkey VALIDATOR_HOTKEY_SS58 \
  --require-clean-current-state \
  > /absolute/private/path/to/preflight.json
```

Build the exact unsigned raw CRv4 material without touching the wallet or chain:

```bash
.venv/bin/umi-bootstrap-weights build-call \
  --manifest /absolute/path/to/signed-manifest.json \
  --cutover-checkpoint /absolute/path/to/cutover-checkpoint.json \
  --validator-hotkey VALIDATOR_HOTKEY_SS58 \
  --require-clean-current-state \
  --output /absolute/private/path/to/call-material.json
```

Inspect both outputs. The UID list must equal the manifest's UID-sorted list, and
every raw weight must be `65535`. `build-call` reads one finalized schedule and
does not anchor or submit anything.

Use `--require-clean-current-state` only for the subnet's first bootstrap commit.
It confirms that the current global state is still as clean as the historical
cutover. Later validators and later refreshes omit that option because an earlier
bootstrap row or commit may legitimately exist. Every run still replays the
published cutover. If this validator has an active row from an earlier bootstrap
commit, add:

```text
--prior-terminal /absolute/path/to/that-validator-signed-applied-terminal.json
```

The live `submit` command repeats pilot replay and finalized chain checks before
anchoring. After anchor finality it verifies the exact stored SHA-256 anchor,
repeats finalized chain checks and every HTTPS health probe, then takes the
schedule snapshot and constructs the call. Any failed replay, mapping, permit,
health, anchor, schedule, or timing check stops before the weight commit.

## 7. Anchor and submit the exact raw CRv4 row

After all blockers above are closed, and while both the manifest TTL and commit
interval remain open, the validator runs exactly one live command:

```bash
.venv/bin/umi-bootstrap-weights submit \
  --manifest /absolute/path/to/signed-manifest.json \
  --cutover-checkpoint /absolute/path/to/cutover-checkpoint.json \
  --receipt-output /absolute/private/path/to/submission-receipt.json \
  --call-material-output /absolute/private/path/to/submitted-call-material.json \
  --state-dir /absolute/private/path/to/validator-state \
  --require-clean-current-state \
  --live-submit \
  --acknowledgement 'SUBMIT SN78 BOOTSTRAP SERVICE WEIGHTS' \
  --wallet-name YOUR_VALIDATOR_WALLET_NAME \
  --hotkey YOUR_VALIDATOR_HOTKEY_NAME \
  --wallet-path /absolute/path/to/wallets
```

Keep `validator-state` private, writable, and persistent. The command uses it to
serialize submissions for this validator and policy. Use the
`--require-clean-current-state` option only on the subnet's first bootstrap
submission. Use `--prior-terminal` as described above when refreshing an active
row.

The command verifies the signed manifest, replays the pilots, checks finalized
chain state and live HTTPS health, anchors the inner `manifest_sha256`, and waits
for anchor finality. It then verifies the stored anchor, repeats the chain and
health checks, persists the exact call material, takes a fresh finalized schedule
snapshot, builds the mechanism-aware raw CRv4 call, submits it with the validator
hotkey, and waits for commit finality. Plain `set_weights` and the convenience
`CommitWeights` intent are forbidden.

The receipt status `commit_finalized_pending_terminal_verification` proves only
finalized commit acceptance. The row remains pending. Do not retry after a
finalized `TimelockedWeightsCommitted` event.

## 8. Verify terminal state and publish evidence

After the expected reveal, ask the validator to create a signed terminal
observation:

```bash
.venv/bin/umi-bootstrap-weights terminal \
  --manifest /absolute/path/to/signed-manifest.json \
  --receipt /absolute/private/path/to/submission-receipt.json \
  --call-material /absolute/private/path/to/submitted-call-material.json \
  --output /absolute/private/path/to/signed-terminal-BLOCK.json \
  --wallet-name YOUR_VALIDATOR_WALLET_NAME \
  --hotkey YOUR_VALIDATOR_HOTKEY_NAME \
  --wallet-path /absolute/path/to/wallets
```

The command performs one finalized observation and refuses to replace its output.
If the nested classification is `pending`, wait for more finalized blocks and run
it again with a new output filename. Do not retry the weight commit. A terminal
check must run within 2,048 blocks of commit inclusion. A terminal `applied` result
affirms all of these checks:

- the exact pending entry is absent from its recorded epoch key;
- one commit event matches the exact block and extrinsic index, with no duplicate;
- one matching `TimelockedWeightsRevealed` event exists;
- every finalized `RevealPeriodEpochs` observation from inclusion through removal
  matches the submitted schedule;
- every destination hotkey still resolves to the expected MechId 0 UID;
- the stored raw row byte-matches the manifest's `[uid, 65535]` pairs; and
- the receipt, call material, ciphertext, reveal round, manifest, validator, and
  terminal observation all bind to one another.

The signed output records `sdk_finalized_reads_verified: true` and
`storage_proofs_verified: false`. This is the addendum's disclosed reduced-trust
boundary. A `failed` result is an incident and blocks the Const/root restoration
request. Only `applied` can advance the launch.

Within one tempo of the terminal block, publish one immutable, content-addressed
bundle containing the validator-signed terminal wrapper and every object it binds:
the policy and publication reference, cutover checkpoint, opt-ins, pilot replays,
health receipts, signed manifest, validator preflight, manifest anchor, call
material, submission receipt, and finalized event and row observations. Publish a
small index that names every object URL, SHA-256, media type, and byte length. The
repository has no upload command; publication to immutable GitHub or
content-addressed R2 is a required operator step.

The public index must expose the policy and manifest hashes, validator anchor,
expected raw row, applied raw row, terminal classification, and replay links. It
must say:

```json
{
  "translation_weights_active": false,
  "service_weights_active": true,
  "service_weight_kind": "bootstrap_service_binary",
  "section_14_gate_credit": false
}
```

Do not populate the translation leaderboard from this row.

## 9. Ask Const/root to restore subnet emission

Send the request only after the first `applied` terminal bundle is public and
independently retrievable. Include:

- SN78 and MechId 0;
- the pinned UMI revision;
- the addendum, policy, and signed-manifest URLs and hashes;
- the validator terminal-bundle URL and hash;
- the finalized manifest-anchor, commit, reveal, and applied-row blocks;
- the public immutable index URL; and
- a plain statement that the row measures temporary binary service eligibility,
  that translation quality remains inactive, and that service commits stop at the
  published cutoff.

Suggested request:

> SN78 now has a public, replayable MechId 0 service row under the seven-day UMI
> bootstrap policy. The signed manifest, miner opt-ins, validator anchor, raw CRv4
> commit, finalized reveal, and exact applied row are linked below. It reports
> equal binary endpoint eligibility. ASL-quality scoring and translation weights
> remain inactive. Please review the evidence and, if acceptable, restore
> the root-controlled `subnet_emission_enabled` flag for netuid 78.

Only the chain sudo key or its authorized root flow can perform the mutation. The
root operator can preview, submit, and verify with:

```bash
btcli tx set-subnet-emission-enabled \
  --network finney \
  --netuids 78 \
  --enabled \
  --wallet YOUR_ROOT_SUDO_WALLET_NAME \
  --wallet-path /absolute/path/to/wallets \
  --dry-run

btcli tx set-subnet-emission-enabled \
  --network finney \
  --netuids 78 \
  --enabled \
  --wallet YOUR_ROOT_SUDO_WALLET_NAME \
  --wallet-path /absolute/path/to/wallets

btcli query subnet-emission-enabled \
  --network finney \
  --netuid 78 \
  --json
```

Const/root decides whether to run that call. Repository publication, the owner
version change, a pending validator commit, or an observer status update cannot
replace it.

## 10. Maintain the row through the service interval

A single applied row ages out under the 360-block activity cutoff. Until
`commit_stop_block`, repeat Sections 5 through 8 when a fresh row is needed:

1. include every eligible opt-in received before a new freeze block;
2. repeat all pilot, chain, origin, and health checks and sign a fresh manifest;
3. wait until the validator's preceding commit has a signed terminal result;
4. run preflight and submit no more than once for that validator in an observed
   epoch; and
5. publish the signed terminal result and its immutable index within one tempo.

When the validator's previous bootstrap row is still active, pass its signed
`applied` terminal file to `preflight`, `build-call`, and `submit`:

```text
--prior-terminal /absolute/path/to/prior-signed-applied-terminal.json
```

Omit `--require-clean-current-state` after the first bootstrap commit. Never reuse
an expired manifest, submit while a prior entry is pending, or refresh after
`commit_stop_block`.

## 11. Stop at the hard sunset

Configure an external scheduler before the first live commit to disable manifest
production and validator submission before `commit_stop_block`. The process name
and scheduler are deployment-specific, so this runbook does not invent a service
command.

At `commit_stop_block`:

1. stop new manifest and commit work;
2. leave terminal watchers running;
3. classify and publish every pending result;
4. alert on any submission included at or after the cutoff; and
5. ask Const/root to disable `subnet_emission_enabled` when the hard-sunset block
   arrives.

At `hard_sunset_block`:

1. report `service_weights_active: false` regardless of local configuration;
2. record finalized SDK observations showing every bootstrap pending entry is
   absent;
3. record finalized SDK observations showing every bootstrap-updated row is
   inactive;
4. publish the coordinator-signed sunset checkpoint required by the addendum; and
5. verify `subnet_emission_enabled: false`.

A future governed mechanism requires a separately published superseding amendment;
it does not alter these sunset checks.

The root operator previews and performs the sunset mutation with the same command
used for restoration, changing `--enabled` to `--no-enabled`:

```bash
btcli tx set-subnet-emission-enabled \
  --network finney \
  --netuids 78 \
  --no-enabled \
  --wallet YOUR_ROOT_SUDO_WALLET_NAME \
  --wallet-path /absolute/path/to/wallets \
  --dry-run

btcli tx set-subnet-emission-enabled \
  --network finney \
  --netuids 78 \
  --no-enabled \
  --wallet YOUR_ROOT_SUDO_WALLET_NAME \
  --wallet-path /absolute/path/to/wallets

btcli query subnet-emission-enabled \
  --network finney \
  --netuid 78 \
  --json
```

At or after `hard_sunset_block`, the coordinator signs the final SDK-observed
status. Supply a validator hotkey that is still registered on SN78:

```bash
.venv/bin/umi-bootstrap-weights sunset-status \
  --manifest /absolute/path/to/final-signed-manifest.json \
  --validator-hotkey REGISTERED_VALIDATOR_HOTKEY_SS58 \
  --output /absolute/private/path/to/signed-sunset-status.json \
  --wallet-name YOUR_COORDINATOR_WALLET_NAME \
  --hotkey YOUR_COORDINATOR_HOTKEY_NAME \
  --wallet-path /absolute/path/to/wallets
```

Publish the signed status with an immutable final index listing every manifest and
terminal-bundle hash. The required status is
`sunset_clean_sdk_observation`, with zero pending entries, no active MechId 0
rows, `service_weights_active: false`, and `subnet_emission_enabled: false`.
`storage_proofs_verified` remains `false` under the same disclosed bootstrap
boundary.

Although the command can produce pre-sunset phase diagnostics, keep those outputs
private and do not publish them as mechanism status. They do not ingest the
applied-terminal index, so their `service_weights_active: false` field is not a
pre-sunset service-status claim. The public applied-terminal index remains
authoritative until the hard sunset.

Any other sunset status is a public incident. It cannot extend the policy, and
local UMI code cannot change the root-controlled flag.

## Go/no-go record

The same-day launch may proceed only when all boxes below are checked:

- [ ] Clean pinned revision and full test suite pass.
- [ ] Addendum, concrete policy, policy hash, and block schedule are public.
- [ ] Owner change to `WeightsVersionKey = 1` is final and independently verified.
- [ ] Global old-entry and old-row cutover checkpoint is public.
- [ ] Every weighted miner has a successful public endpoint pilot and a valid
  post-publication hotkey opt-in.
- [ ] Complete coordinator entry evidence and signed manifest are public.
- [ ] Validator replay, chain, and post-anchor health checks pass for every entry.
- [ ] Manifest anchor and one raw CRv4 commit finalize without retry.
- [ ] Exact-key removal, reveal event, mapping, and applied raw row all agree.
- [ ] Signed terminal bundle is public and replayable.
- [ ] Const/root receives the evidence-backed restoration request.
- [ ] Commit-stop automation, root-disable handoff, and sunset checkpoint path
  are tested.

Any unchecked item keeps the mechanism in `bootstrap pending` status. Translation
rankings remain inactive throughout this bootstrap.
