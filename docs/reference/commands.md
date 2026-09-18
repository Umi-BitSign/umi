[Documentation](../README.md) / CLI reference

# Competition CLI reference

These are operator and local-rehearsal recipes except for the explicitly marked
live first-round endpoint intake section. Start with the
[launch checklist](../competition/launch.md).

<a id="live-first-round-intake"></a>

## Live first-round endpoint intake

The reviewed endpoint-intake origin is `https://api.umi.vision`. It has been
publicly reachable since block `9,085,463`. A submission or replacement must be
accepted on or after that opening block and by block `9,135,843` to guarantee
consideration for round one. The
coordinator may close the roster at any later poll through block `9,135,903`, so
an acceptance in that interval is not guaranteed first-round inclusion. The
same hotkey must still be registered on SN78 in the finalized roster-close
snapshot, and the submission must remain valid through evaluation.

Read the bounded status and finalized registration head, then extract the exact
canonical policy:

```sh
origin=https://api.umi.vision
curl --fail --silent --show-error --max-time 20 \
  "$origin/v1/competition/status" > competition-status.json
jq -e '
  .admission_phase == "open" and
  .admission_accepting_new == true and
  (.deployment.umi_git_revision | test("^[0-9a-f]{40}$")) and
  (.deployment.umi_source_tree_sha256 | test("^[0-9a-f]{64}$"))
' competition-status.json >/dev/null
jq -c '.policy' competition-status.json > competition-policy.json
head_block="$(curl --fail --silent --show-error --max-time 20 \
  "$origin/v1/competition/readiness" | jq -r '.registration_source.block')"
```

If the status is `not_open`, `closed` or `unverified`, do not create a new
submission. An identical retry of an already accepted signed object remains
safe. The service enforces the source-tree digest at startup. The displayed Git
revision is an operator declaration that the deployment procedure must verify
against that exact tree; a repository branch name does not identify a release.

Set the three operator values below. `model_revision` is the SHA-256 revision of
the exact model served at the credential-free HTTPS origin. Then prepare the
canonical endpoint submission:

```sh
hotkey=YOUR_REGISTERED_HOTKEY
endpoint=https://YOUR_PUBLIC_ORIGIN
model_revision=YOUR_64_HEX_MODEL_REVISION

jq -n -c \
  --arg hotkey "$hotkey" --arg endpoint "$endpoint" \
  --arg model_revision "$model_revision" --argjson from "$head_block" \
  '{schema:"umi-competition-submission/1",network:"finney",netuid:78,
    policy_sha256:"81c118c5b45527650d7f304a6574d04223de30fbad76c69df09e7f2ae4897fa0",
    hotkey:$hotkey,track:"endpoint",sequence:1,valid_from_block:$from,
    valid_through_block:9156243,model_revision:$model_revision,
    endpoint_url:$endpoint,model_bundle:null,
    accepted_terms_sha256:"61f333f6105c8e8a06db9d51a7a47a3cf0c5c0c72d7794fe1e5e6744eafcca62"}' \
  > submission.json
```

The fixed validity end covers the first evaluation close and is within the
policy's 72,000-block lifetime for submissions admitted during the announced
intake. Do not reuse this template after the first roster closes.

Sign with the registered hotkey only, save the public object, and submit it:

```sh
umi-competition --policy competition-policy.json sign-submission \
  --submission submission.json \
  --wallet-name YOUR_WALLET --hotkey-name YOUR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS > signed-submission.json

umi-competition --policy competition-policy.json submit \
  --submission signed-submission.json --origin "$origin" \
  | tee admission-receipt.json
```

Success is `accepted_no_weight`. Keep the exact signed submission and receipt,
and keep the endpoint, model revision and registered hotkey available through
evaluation. A receipt does not promise inclusion, score or payment. To replace a
submission, increment its sequence and wait at least 360 blocks after the prior
acceptance. The roster uses the latest accepted submission for each hotkey and
track. A bad or expired replacement does not revive an older submission. There
is no rollback or cancellation operation. The replacement must be accepted by
the guaranteed deadline and remain valid through evaluation to guarantee
first-round consideration. Its hotkey must also remain registered on SN78 in the
finalized roster-close snapshot; an admission receipt does not preserve a slot
after deregistration.

The public log retains complete signed submissions and receipts. It exposes the
hotkey, endpoint URL, model revision, signature and finalized registration
snapshot. Use a credential-free HTTPS root with no secret in its host, path,
query or fragment. Do not put credentials, private provenance, private dataset
details or confidential review evidence in these fields. Endpoint intake stores
metadata and does not upload model bytes. Never upload a seed phrase, coldkey or
wallet file.

<a id="live-first-round-model-contribution"></a>

### Model-manifest preparation; artifact intake is not open

Model-artifact intake and evaluation are not operational for the first round.
The exact canonical runtime and its immutable, reconstructible environment have
not been published. Do not sign or submit a model-track object to the live
endpoint-intake origin. The 30% model share remains burned, does not accrue, and
cannot be awarded retroactively. A future opening will publish its own runtime,
cutoffs and submission route.

The manifest below is an advance-preparation aid only. Read the
[model preparation and rights checklist](../contributors/models.md). Do not
include training data, credentials or confidential review evidence in it.

Create `model-bundle.json` with this exact shape:

```json
{
  "schema": "umi-model-bundle/1",
  "profile": "offline_bundle/1",
  "parent_baseline_sha256": "CURRENT_BASELINE_MODEL_SHA256",
  "license_id": "ONE_POLICY_ACCEPTED_IDENTIFIER",
  "files": [
    {
      "path": "config.json",
      "role": "config",
      "sha256": "EXACT_FILE_SHA256",
      "size_bytes": 123
    }
  ]
}
```

`files` must be the complete sorted inventory of the runnable artifact. Paths
are relative POSIX paths. The manifest needs at least one file in each of these
roles: `weights`, `config`, `processor`, `inference`, `environment`, `license`
and `provenance`. Additional files use the closest role or `dependency`. Use the
current value of `.baseline.model_sha256` from `competition-status.json` as the
parent. The policy's `.accepted_model_licenses` lists the identifiers eligible
for review. An eligible identifier is not a rights approval.

Validate the manifest and compute its domain-separated revision from a checkout
of this repository with its environment installed:

```sh
model_revision="$(python - <<'PY'
from pathlib import Path

from umi.open_competition import ModelBundle, digest

bundle = ModelBundle.model_validate_json(Path("model-bundle.json").read_bytes())
print(digest(bundle))
PY
)"
printf '%s\n' "$model_revision"
```

Compare every listed size and SHA-256 digest to the immutable source files
before retaining it for a future opening. Do not publish private datasets,
credentials or confidential provenance in the manifest. The future review route
will retrieve and rehash declared files under bounded limits. An exact tie
between the highest qualifying new candidates promotes neither candidate, and
the model share remains burned for that round.

## Assignment and publication rehearsal

These commands operate on reviewed local artifacts. No live feed URL or
successor policy is supplied by these examples, and no command submits weights.
Assignment delivery is not yet public. Do not start a production miner with the
placeholder feed values below. UMI will publish an exact signed feed
configuration and tested miner command before evaluation, with operating lead
time. A coordinator, feed or evaluator delay is not a miner failure.

An endpoint proof check uses the owned finality sidecar and storage verifier:

```sh
umi-competition --policy policy.json check-endpoint-origin \
  --submission signed-endpoint.json --chain-config endpoint-chain.json
```

Use a dedicated private state directory in `endpoint-chain.json`. IP origins
must match the finalized Axon. For DNS origins, the port must match and the
resolved public addresses must include the finalized Axon IP. The hostname is
bound by the miner's signed submission; DNS is recorded as a local observation,
not a chain storage proof. The dispatcher connects to the captured IP without
resolving the hostname again, retaining the hostname for TLS verification and
HTTP routing. TLS identity, availability and authenticated miner responses still
need transport checks. See [hostname requirements](../miners/model.md#miner-endpoint-hostnames).
The storage layout is defined by the pinned runtime metadata; see the
[Subtensor storage definitions](https://github.com/opentensor/subtensor/blob/main/pallets/subtensor/src/lib.rs).

The local assignment feed serves a journal populated by the
[continuous dispatcher](../operators/dispatch.md#open-competition-dispatch) through typed publication,
observation and claim APIs. These APIs require concrete verifier-owned block
observations. There is no public publication or dispatch endpoint.

```sh
umi-competition --policy policy.json serve-assignment-feed \
  --legacy-policy legacy-policy.json --state /ABSOLUTE/PRIVATE/SCHEDULER \
  --nonce-path /ABSOLUTE/PRIVATE/FEED/nonces.sqlite3

umi-competition --policy policy.json discover-assignments \
  --legacy-policy legacy-policy.json --origin https://REVIEWED_ASSIGNMENT_HOST \
  --wallet-name YOUR_WALLET --hotkey-name YOUR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS
```

The server binds loopback port 8099 and requires an operator-managed HTTPS proxy
with ingress limits before external use. Discovery signs a fresh read query
using the named hotkey; it needs no per-miner credential. Add
`--publication PUBLICATION_SHA256` to retrieve and verify one exact signed
publication. Treat its output as private operational data because video URLs
can carry delivery credentials. This command does not install the authorization
into a running miner or start inference.

For ongoing discovery inside the no-weight miner process, use the separate
[`--competition-feed` mode](../miners/model.md#miner-model-integration--successor-assignment-discovery-rehearsal).
It does not change this CLI command's behavior or activate competition rewards.

Use one miner and one usable issuance window per signed publication for this
feed. A multi-miner audience is refused; a future case within a larger publication
holds the complete document until every included issuance is verified. Retrieval
also refuses stale observations and publications without remaining unclaimed
work. The retained historical publication remains available to local audit APIs.

Cutoff and settlement certificates can be checked without signing anything:

```sh
umi-competition --policy policy.json verify-cutoff-publication \
  --certificate signed-cutoff.json --roster roster.json \
  --replay-limits publication-limits.json

umi-competition --policy policy.json verify-settlement-publication \
  --certificate signed-settlement.json --cutoff-certificate signed-cutoff.json \
  --roster roster.json --evidence independent-evidence.json \
  --retained-settlement retained-settlement.json \
  --replay-limits publication-limits.json
```

The roster is a `PublicationRoster`; the evidence wrapper is
`PublicationEvidenceInputs` in `competition_cli.py`. Each entry carries either
scored independent evidence or a complete independently certified void; both
remain bound to the exact frozen roster. The settlement and package commands
accept this same mixed evidence. Scored evaluation commands still reject voids.
Limits use
`PublicationReplayLimits` in `competition_publication.py`. A successful replay
does not prove publication timing or authorize a row. Real evaluation and
preservation evidence must support the retained settlement.

### Immutable settlement package rehearsal

These are coordinator rehearsal commands, not miner enrollment or validator
installation steps. They prepare a fixed-file package from retained evidence
and run a wallet-free settlement replay. They do not execute a model, access
the network, publish a release or submit weights.

```sh
umi-competition --policy policy.json prepare-settlement-package \
  --cutoff-certificate signed-cutoff.json \
  --certificate signed-settlement.json \
  --retained-settlement retained-settlement.json \
  --roster roster.json --evidence independent-evidence.json \
  --replay-limits publication-limits.json \
  --release-identity expected-release.json \
  --package-limits package-limits.json \
  --destination /ABSOLUTE/PRIVATE/PACKAGES

umi-competition --policy policy.json replay-settlement-package \
  --package /ABSOLUTE/PRIVATE/PACKAGES/PACKAGE_SHA256 \
  --expected-package-sha256 PACKAGE_SHA256 \
  --release-identity expected-release.json \
  --package-limits package-limits.json \
  --worker-capacity worker-capacity.json \
  --state /ABSOLUTE/PRIVATE/REPLAY_WORKER
```

Use the package path and digest returned by preparation. The expected policy
digest comes from `--policy`. Use the schemas `CompetitionPackageLimits` and
`CompetitionReleaseIdentity` in `competition_package.py`, and
`CompetitionWorkerCapacity` in `competition_worker.py`. All storage limits are
explicit. The preparation CLI additionally limits each source JSON file to
64 MiB; neither this command nor the package profile changes the old supervisor's
16 MiB bootstrap-input limit.

The package loader checks exact filenames, private ownership and permissions,
single-link regular files, canonical bytes, size/hash bounds and semantic
bindings. It refuses extra files, path traversal, links and mismatched expected
identities. The retained settlement must agree with its signed certificate and
pass full replay. Agreement does not establish independent custody or execution.

Preparation claims a digest-named directory exclusively. An interrupted write
leaves a mode-0700 partial directory that the loader refuses. The operator must
inspect and quarantine that exact partial directory before retrying preparation;
the command never overwrites or deletes it. Accepted directories are sealed at
mode 0500 with mode-0400 files. These permissions detect accidental changes;
they are not protection against a compromised owning account.

The worker retains an immutable local receipt. A retry returns the same
historical receipt and separately reports the journal's current conflict hold.
Always check `current_status`; an earlier successful receipt cannot clear a
later conflict. Restart can repeat interrupted arithmetic replay because this
worker has no external effect, but it cannot select different evidence for an
existing package identity.

Journal limits count reserved receipt/manifest bytes and retained certificate
bytes. SQLite overhead, backup space and filesystem quotas remain deployment
requirements. Capacity exhaustion stops new work without evicting history.

Release and platform fields are local equality bindings, not runtime
attestation. Results keep `runtime_identity_authenticated: false` and
`chain_submission_authorized: false`. These local commands do not connect a
worker to the shared supervisor feed. Use the separate publication and host
upgrade procedures, including the actual Linux sandbox checks, for a handoff.

## Local rehearsal commands

Use `python -m umi.competition_cli` from an installed checkout, or the installed
`umi-competition` entrypoint. Python 3.10 through 3.14 are supported.
Every command requires a reviewed policy JSON file. Input schemas are the
Pydantic models in [open_competition.py](../../src/umi/open_competition.py).

```sh
umi-competition --policy policy.json inspect-policy

umi-competition --policy policy.json verify-bundle \
  --manifest model-bundle.json --source /ABSOLUTE/MODEL/DIRECTORY

umi-competition --policy policy.json preserve-bundle \
  --manifest model-bundle.json --source /ABSOLUTE/MODEL/DIRECTORY \
  --archive /ABSOLUTE/UMI/ARCHIVE

umi-competition --policy policy.json initialize-baseline \
  --state /ABSOLUTE/PRIVATE/STATE --archive /ABSOLUTE/UMI/ARCHIVE \
  --manifest baseline-bundle.json
```

The source model directory contains exactly the files named by the bundle
manifest. The manifest itself is supplied separately. An archived version has
`<model-digest>/manifest.json` and `<model-digest>/model/`. Initial baseline import
does not invent a miner contributor or assign a reward recipient.

The state directory must be private, mode 0700. Use a dedicated directory with
no wallet material. Each store is bound to one policy hash; changing the policy
requires an explicit state transition, not editing its metadata in place.

Miners can sign a prepared submission with their own hotkey:

```sh
umi-competition --policy policy.json sign-submission \
  --submission submission.json \
  --wallet-name YOUR_WALLET --hotkey-name YOUR_HOTKEY \
  --wallet-path /ABSOLUTE/PATH/TO/WALLETS
```

The command prints the signed public object. It does not upload anything or
access the coldkey. Never send wallet files or seed phrases to a registry.

Once a reviewed intake origin is published, submit that saved public object:

```sh
umi-competition --policy policy.json submit \
  --submission signed-submission.json --origin https://REVIEWED_INTAKE_HOST
```

This is a command example, not a live enrollment URL. The client refuses
redirects, oversized replies, mismatched receipts and any receipt claiming
chain submission is authorized. Version 2 receipts retain the registration
snapshot and its source marker. The client checks the snapshot digest and the
submitting hotkey's UID, and refuses fixture-source receipts. A source marker is
still a server claim over TLS, not a portable proof. No personal API key is
needed. A successful receipt says `accepted_no_weight`; it does not certify
evaluation or earnings.

For a local rehearsal using an explicitly supplied registration snapshot:

```sh
umi-competition --policy policy.json admit \
  --state /ABSOLUTE/PRIVATE/STATE --snapshot snapshot.json \
  --submission signed-submission.json --current-block 12345

umi-competition --policy policy.json serve-rehearsal \
  --state /ABSOLUTE/PRIVATE/STATE --snapshot snapshot.json --port 8098
```

The fixture server binds only `127.0.0.1`. A snapshot file is a rehearsal input,
not a finality proof. Its receipts are permanently marked `rehearsal_snapshot`;
putting this service behind a proxy does not make the miner client accept them.
Old version 1 receipts remain unchanged and cannot be upgraded by a retry.
The fixture CLI cannot select the verified-source marker or enable public binding.

### Owned-finality intake service

The separate service entrypoint accepts a strict
`umi-competition-service-config/2` local configuration:

```sh
umi-competition --policy policy.json serve-intake --config intake.json
```

Use the schemas in [competition_service.py](../../src/umi/competition_service.py)
and [competition_chain.py](../../src/umi/competition_chain.py). Configuration must
bind the exact policy digest, Finney genesis, runtime metadata, finality
checkpoint and both verifier binaries. Give intake and chain evidence separate,
private state directories. There are no wallet fields or fixture-provider
overrides in the configuration. `public_deployment` carries the published code
identity, round schedule, eligible tracks and readiness flags. The intake store
durably binds only its immutable public launch identity: schedule and eligible
tracks. A later code deployment may update its declared revision and source-tree
digest without changing those launch semantics. `retained_state` binds the
expected baseline promotion and the complete set of submission digests present
at deployment. The database must already exist; the service refuses a new path,
another baseline or a ledger missing any anchored submission. The required
`submission_head_checkpoint_directory` is a pre-existing, private external
journal disjoint from intake and finality state.

<a id="owned-finality-intake-v2-cutover"></a>

#### Version 1 store to writer-generation 2 cutover

This is a quiesced database migration. First disable the public submission
route and drain its in-flight request. Stop every old process that can open the
intake store, including intake, round coordinator, evaluator exchange with
`intake_directory`, successor publisher, and scheduled or manual store commands.
Stopping only the HTTP intake process is insufficient. Run the following blocks
in order in one dedicated shell. Record the stopped units and require `lsof` to
find no open handle:

```sh
set -eu
umask 077
state=/ABSOLUTE/PRIVATE/INTAKE
database="$state/competition.sqlite3"
if sudo lsof +D "$state"; then
  printf '%s\n' 'intake state is still open; stop every writer' >&2
  exit 1
fi
```

Do not continue while an old process has the database, WAL, or shared-memory
file open. Keep all old units stopped for the whole cutover. They must never be
started against a writer-generation 2 store.

Set fresh paths outside the intake and finality state trees. The cutover
directory is the retained audit and rollback copy. The checkpoint directory is
the external submission-head journal named by the version 2 service config:

```sh
policy=/ABSOLUTE/PRIVATE/POLICY.json
config=/ABSOLUTE/PRIVATE/INTAKE-V2.json
cutover=/ABSOLUTE/PRIVATE/INTAKE-CUTOVER
checkpoint=/ABSOLUTE/PRIVATE/SUBMISSION-HEAD-CHECKPOINT
backup="$cutover/competition-v1.sqlite3"
restore_state="$cutover/restore-test"
restore_database="$restore_state/competition.sqlite3"
restore_checkpoint="$cutover/restore-checkpoint"
restore_config="$cutover/restore-config.json"

test -f "$database"
test ! -L "$database"
test ! -e "$cutover"
test ! -e "$checkpoint"
install -d -m 0700 \
  "$cutover" "$restore_state" "$restore_checkpoint" "$checkpoint"
jq -e --arg state "$state" --arg checkpoint "$checkpoint" '
  .schema == "umi-competition-service-config/2" and
  .state_directory == $state and
  .submission_head_checkpoint_directory == $checkpoint
' "$config" >/dev/null
```

Use SQLite's backup API through `.backup`; copying only
`competition.sqlite3` is unsafe in WAL mode. Restore that backup into a fresh
database before trusting it:

```sh
sqlite3 -batch -noheader "$database" 'PRAGMA wal_checkpoint(FULL);' \
  > "$cutover/wal-checkpoint.txt"
test "$(awk -F'|' 'NR == 1 { print $1 }' "$cutover/wal-checkpoint.txt")" = 0
test "$(sqlite3 "$database" 'PRAGMA integrity_check;')" = ok
sqlite3 "$database" ".backup '$backup'"
chmod 0600 "$backup"

sqlite3 "$restore_database" ".restore '$backup'"
test "$(sqlite3 "$restore_database" 'PRAGMA integrity_check;')" = ok
```

Capture the current promotion head and the complete sorted submission set from
both databases. The restored values must match the stopped source exactly:

```sh
sqlite3 -noheader "$database" \
  'SELECT digest FROM promotions ORDER BY sequence DESC LIMIT 1;' \
  > "$cutover/source-baseline.txt"
sqlite3 -noheader "$restore_database" \
  'SELECT digest FROM promotions ORDER BY sequence DESC LIMIT 1;' \
  > "$cutover/restored-baseline.txt"
sqlite3 -noheader "$database" \
  'SELECT digest FROM submissions ORDER BY digest;' \
  > "$cutover/source-submissions.txt"
sqlite3 -noheader "$restore_database" \
  'SELECT digest FROM submissions ORDER BY digest;' \
  > "$cutover/restored-submissions.txt"

cmp "$cutover/source-baseline.txt" "$cutover/restored-baseline.txt"
cmp "$cutover/source-submissions.txt" "$cutover/restored-submissions.txt"
test "$(wc -l < "$cutover/source-baseline.txt" | tr -d ' ')" = 1
test -s "$cutover/source-submissions.txt"
```

Build the exact retained-state value from that inventory and compare it with
the reviewed version 2 config. This check must pass before migration:

```sh
IFS= read -r baseline < "$cutover/source-baseline.txt"
jq -Rn --arg baseline "$baseline" '
  [inputs | select(length > 0)] as $submissions |
  {
    schema: "umi-competition-retained-intake-state/1",
    baseline_promotion_sha256: $baseline,
    required_submission_sha256s: $submissions
  }
' < "$cutover/source-submissions.txt" > "$cutover/retained-state.json"

jq -e --slurpfile expected "$cutover/retained-state.json" \
  '.retained_state == $expected[0]' "$config" >/dev/null
```

Derive a rehearsal config that changes only the database and checkpoint
directories. The rehearsal must not initialize the live checkpoint:

```sh
jq -cS --arg state "$restore_state" --arg checkpoint "$restore_checkpoint" '
  .state_directory = $state |
  .submission_head_checkpoint_directory = $checkpoint
' "$config" > "$restore_config"
chmod 0600 "$restore_config"
jq -e --arg state "$restore_state" --arg checkpoint "$restore_checkpoint" \
  --slurpfile expected "$cutover/retained-state.json" \
  --slurpfile live "$config" '
    .schema == "umi-competition-service-config/2" and
    .state_directory == $state and
    .submission_head_checkpoint_directory == $checkpoint and
    .retained_state == $expected[0] and
    ((. | del(.state_directory, .submission_head_checkpoint_directory)) ==
      ($live[0] | del(.state_directory, .submission_head_checkpoint_directory)))
  ' "$restore_config" >/dev/null

umi-competition-store-migrate \
  --policy "$policy" --state "$restore_state" \
  --service-config "$restore_config" \
  --confirm-quiesced-backup > "$cutover/restore-migration.json"
jq -e '
  .status == "writer_generation_and_submission_checkpoint_migrated" and
  .restart_services_without_migration == true and
  .retained_submission_head.external_checkpoint_durable == true
' "$cutover/restore-migration.json" >/dev/null
jq -S '.retained_submission_head' "$cutover/restore-migration.json" \
  > "$cutover/restored-submission-head.json"
```

Run the same one-shot command on the still-quiesced source with the reviewed
live config. `--service-config` binds the public launch, exact retained state,
and checkpoint path. An ordinary service start never initializes a missing
checkpoint:

```sh
umi-competition-store-migrate \
  --policy "$policy" --state "$state" --service-config "$config" \
  --confirm-quiesced-backup > "$cutover/source-migration.json"

jq -S '.retained_submission_head' "$cutover/source-migration.json" \
  > "$cutover/retained-submission-head.json"
jq -e '
  .status == "writer_generation_and_submission_checkpoint_migrated" and
  .restart_services_without_migration == true and
  .retained_submission_head.external_checkpoint_durable == true
' "$cutover/source-migration.json" >/dev/null
cmp "$cutover/restored-submission-head.json" \
  "$cutover/retained-submission-head.json"
cmp "$restore_checkpoint/submission-head.json" \
  "$checkpoint/submission-head.json"
chmod 0600 "$cutover"/*.json "$cutover"/*.txt
```

Retain the backup, inventory, config, and migration output on storage separate
from the live intake tree. Configure
`submission_head_checkpoint_directory` as the separate `0700` directory created
above. The migration writes canonical `submission-head.json` there only if the
database still has exactly the configured retained submissions. The checkpoint
commits both their sorted identities and the exact immutable admission records
and receipts. Version 2 startup requires that file and fails on a missing,
corrupt, or ahead checkpoint. Never delete that journal to make a rollback pass.
The restore config and restore checkpoint are bounded rehearsal evidence. Never
run a service against them.

Validate the external checkpoint before starting any service:

```sh
jq -e \
  --slurpfile retained "$cutover/retained-state.json" \
  --slurpfile head "$cutover/retained-submission-head.json" '
    .schema == "umi-competition-submission-head-checkpoint/1" and
    .policy_sha256 == $head[0].policy_sha256 and
    .submission_sha256s == $retained[0].required_submission_sha256s and
    (.admission_record_sha256s | length) == $head[0].record_count and
    all(.admission_record_sha256s[]; test("^[0-9a-f]{64}$")) and
    .record_count == $head[0].record_count and
    .submission_set_sha256 == $head[0].submission_set_sha256 and
    .head_sha256 == $head[0].head_sha256 and
    (.public_launch_sha256 | test("^[0-9a-f]{64}$"))
  ' "$checkpoint/submission-head.json" >/dev/null
```

Start only the version 2 intake unit. Keep public submissions disabled and leave
the coordinator, exchange, and publisher stopped until both public responses
match the retained cutover state:

```sh
origin=https://REVIEWED_INTAKE_HOST
curl --fail --silent --show-error --max-time 20 \
  "$origin/v1/competition/readiness" > "$cutover/readiness-v2.json"
curl --fail --silent --show-error --max-time 20 \
  "$origin/v1/competition/status" > "$cutover/status-v2.json"

IFS= read -r baseline < "$cutover/source-baseline.txt"
submission_count="$(wc -l < "$cutover/source-submissions.txt" | tr -d ' ')"
jq -e \
  --slurpfile retained "$cutover/retained-state.json" \
  --slurpfile head "$cutover/retained-submission-head.json" '
    .schema == "umi-competition-readiness/2" and
    .retained_state == $retained[0] and
    .retained_submission_head == $head[0] and
    .chain_submission_authorized == false
  ' "$cutover/readiness-v2.json" >/dev/null
jq -e --arg baseline "$baseline" --argjson count "$submission_count" \
  --slurpfile head "$cutover/retained-submission-head.json" '
    .schema == "umi-competition-status/2" and
    .baseline.promotion_sha256 == $baseline and
    .accepted_submission_count == $count and
    .retained_submission_head == $head[0] and
    .chain_submission_authorized == false
  ' "$cutover/status-v2.json" >/dev/null
```

After those checks, configure the version 2 coordinator, every intake-enabled
exchange, and the publisher with the exact same
`submission_head_checkpoint_directory` as the intake service. Then start those
units and re-enable submissions. Relay-only exchanges omit the complete intake
binding triplet. Keep `submission-head.json`, its lock file, and the cutover
evidence. Do not treat a successful process start as a cutover check.

Any manual `umi-competition` store command against this migrated live database
must also carry `--public-launch /ABSOLUTE/PUBLIC-LAUNCH.json` and
`--submission-head-checkpoint-directory "$checkpoint"`. The public-launch file
must be the canonical `umi-competition-public-launch/1` identity derived from
the reviewed service deployment; omitting either argument is a startup error,
not a way around the fence.

Rollback to the backup is allowed only while submissions remain disabled and no
version 2 writer has accepted new work. Once the head advances, restoring this
backup would discard durable records and the external checkpoint will reject
it. For a pre-admission rollback, stop every version 2 store user, confirm no
open handle with `lsof +D "$state"`, and preserve the failed database files:

```sh
if sudo lsof +D "$state"; then
  printf '%s\n' 'intake state is still open; stop every writer' >&2
  exit 1
fi
failed="$cutover/failed-v2"
test ! -e "$failed"
install -d -m 0700 "$failed"
cmp "$restore_checkpoint/submission-head.json" \
  "$checkpoint/submission-head.json"
mv "$database" "$failed/competition.sqlite3"
if test -e "${database}-wal"; then
  mv "${database}-wal" "$failed/competition.sqlite3-wal"
fi
if test -e "${database}-shm"; then
  mv "${database}-shm" "$failed/competition.sqlite3-shm"
fi

sqlite3 "$database" ".restore '$backup'"
chmod 0600 "$database"
test "$(sqlite3 "$database" 'PRAGMA integrity_check;')" = ok
umi-competition-store-migrate \
  --policy "$policy" --state "$state" --service-config "$config" \
  --confirm-quiesced-backup > "$cutover/rollback-migration.json"
jq -e '
  .status == "writer_generation_and_submission_checkpoint_migrated" and
  .restart_services_without_migration == true and
  .retained_submission_head.external_checkpoint_durable == true
' "$cutover/rollback-migration.json" >/dev/null
jq -S '.retained_submission_head' "$cutover/rollback-migration.json" \
  > "$cutover/rollback-submission-head.json"
cmp "$cutover/retained-submission-head.json" \
  "$cutover/rollback-submission-head.json"
cmp "$restore_checkpoint/submission-head.json" \
  "$checkpoint/submission-head.json"
```

Restart the same version 2 intake and repeat both `/2` response checks. Reuse
the preserved external checkpoint; do not start a version 1 writer or skip the
migration after restoring the version 1 backup.

The service runs one loopback worker behind an operator-managed HTTPS proxy.
It does not trust forwarded headers. New admissions require a current verified
head; restarting cannot make old persisted finality fresh. Each capture checks
the subnet size and every forward and inverse UID/hotkey mapping against the
same state root. Runtime metadata and proof evidence are retained locally by
digest. The bounded cache fails closed when full; it never silently evicts
evidence. Ongoing backup/export and retention beyond this cutover still need a
deployment design.

`GET /v1/competition/readiness` returns
`schema: "umi-competition-readiness/2"` and reports bounded provenance without
private paths or RPC addresses. Its evidence class is
`verifier_attested_finality`, not a portable offline finality proof. It reports
`evaluation_ready: false` and `rewards_active: false`. This route does not
publish the full retained proof archive. A working route is not a production
launch gate by itself.

`GET /v1/competition/status` returns
`schema: "umi-competition-status/2"`. It includes the deployment, public
schedule, eligible-track gates, accepted-submission count and an admission phase
of `not_open`, `open`, `closed`, `capacity_exhausted` or `unverified`. Public GET
routes read a bounded verified cache and never initiate finality collection. A
new POST starts or joins one fresh collection, so status polling cannot take its
proof capacity.

HTTP routes:

| Method and path | Purpose |
|---|---|
| `GET /v1/competition/status` | Explicit no-weight status, policy and preserved baseline |
| `POST /v1/competition/submissions` | Signed submission, no personal API key |
| `GET /v1/competition/submissions?offset=0&limit=20` | Paginated public admission log |
| `GET /v1/competition/submissions/{digest}` | One complete signed submission and its receipt |
| `GET /v1/competition/rounds/{digest}?offset=0&limit=20` | Bounded result identities, conflict status and recorded group equivocations |
| `GET /v1/competition/settlements/{round_digest}` | Immutable settlement and separate current dispute status, or 404 |

List and status responses contain bounded summaries; they do not embed every
model manifest or the complete evaluation history in each page.

Retry the exact signed body after network or snapshot failure. Successful
retries return the original receipt, including its original acceptance block;
they do not refresh expiry. Authenticated retries of a recorded admission do
not need a fresh proof capture; the saved snapshot and source stay unchanged.
New admissions still fail closed when current proofs are unavailable. A receipt
never certifies miner quality.

The remaining CLI subcommands are `close-round`, `replay-evaluation`, `promote`,
`project-weights` and `status`; each exposes its required files through `--help`.
Projection takes the current contributor from the local promotion store, not a
user-supplied reward-recipient flag. It requires the exact durably closed round
and reads its promotion head in the same transaction; a supplied roster alone
cannot establish that admission was complete.

## Conflict evidence and recovery

`AttestedResult` collects signatures on one common `EvaluationResult`.
The signed content includes each `CaseOutput.elapsed_ms`, the shared
`finished_block` and `runtime_sha256`. It has no separate per-evaluator run
records. Co-signers endorse those recorded observations; the schema does not
assert that separate runs had identical timings or prove those runs happened.
Do not remove timing fields from an existing signed result or describe them as
unsigned metadata.

`IndependentEvaluationEvidence` wraps that unchanged certificate plus one
separately signed `EvaluatorRunRecord` per common-result signer. Run signatures
use their own digest domain. Each record binds the policy, round, submission,
common result, suite, model, incumbent and runtime, plus its own interval,
outputs, timings and execution-evidence digest. Signer sets must match exactly,
with one key per authorized control group and no submitting hotkey evaluating
itself. All runs must agree on case identities, statuses and hypotheses. Their
timings may differ, but per-case resource eligibility and exact replayed scores
must agree. A signed evidence digest is still a claim: operators must retain
and independently inspect the underlying execution evidence.

The evidence slot is `(policy, round, submission)`. The store validates each
quorum certificate's signatures, control groups, historical interval and
immutable bindings before changing evidence state. It stores the canonical
result separately from its signatures. Signature order, extra signatures or
another key in the same group do not create a new result or extra group votes.

Two distinct valid quorum results for the same slot permanently mark that
round conflicted in this policy's store. Disjoint quorums also trigger the hold;
the detector does not depend on finding a shared double-signing key. Invalid
input and non-quorum dissent cannot poison the round. Recorded signatures
retain proof when a group signs conflicting results under different keys.

Evidence commits in its own transaction before any promotion or projection
transaction. Payability, snapshot, rights, archive and replay-expiry failures
cannot roll back independently authenticated evidence. Batch projection
records valid certificates even when another supplied entry is invalid.
Both action paths read the stored results and check the hold atomically.

For a local rehearsal, including evidence received after a reward window:

```sh
umi-competition --policy policy.json record-evaluation \
  --state /ABSOLUTE/PRIVATE/STATE --submission signed-submission.json \
  --round round.json --suite revealed-suite.json \
  --evaluation attested-result.json --observed-block 12345

umi-competition --policy policy.json round-status \
  --state /ABSOLUTE/PRIVATE/STATE --round-sha256 ROUND_SHA256
```

The observation block must be at or after reveal and cannot backdate the
store's observed block. The historical result must satisfy its original
assignment interval; accepting late evidence never renews its reward validity.
The CLI block remains a rehearsal input, not a finality proof.

A late conflict cannot retract a projection already returned to a caller or
an already-finalized chain payment. It blocks subsequent actions. If the
disputed round produced a preserved baseline, the store holds that baseline
and its descendants without rewriting the promotion history or deleting model
files. `baseline.held_for_conflict` exposes that state in status. There is no
clear-hold command; recovery requires an explicit policy transition and review.

On reopening an older rehearsal store, signed results retained in promotion
records populate the ledger. Their original record hashes and contents remain
unchanged, including records using the earlier nested `schema_` field spelling.
Historical projections were not retained and cannot be reconstructed from
that database. The pure arithmetic replay helper remains stateless; production
integration must use the durable guard and a separately specified settlement
procedure, not treat a helper's returned row as authorization.

## Local cutoff and settlement

`EvidenceCutoffSchedule` fixes one explicit cutoff for one complete round.
Record it before closing the round and no later than the submission-close
block. The cutoff must be at or after reveal and within the round's validity.
No default number of blocks or launch allocation is chosen by these commands.

```sh
umi-competition --policy policy.json fix-evidence-cutoff \
  --state /ABSOLUTE/PRIVATE/STATE --round round.json \
  --schedule cutoff.json --observed-block 12340

umi-competition --policy policy.json record-independent-evaluation \
  --state /ABSOLUTE/PRIVATE/STATE --submission signed-submission.json \
  --round round.json --suite revealed-suite.json \
  --evaluation independent-evidence.json --observed-block 12400

umi-competition --policy policy.json settle-round \
  --state /ABSOLUTE/PRIVATE/STATE --inputs settlement-inputs.json \
  --snapshot snapshot.json --current-block 12410

umi-competition --policy policy.json settlement-status \
  --state /ABSOLUTE/PRIVATE/STATE --round-sha256 ROUND_SHA256
```

These block numbers are illustrative local inputs, not finalized observations.
`SettlementInput` in [competition_cli.py](../../src/umi/competition_cli.py) contains
the round, revealed suite and one signed-submission/independent-evidence pair
for every roster entry. Evidence must have been durably recorded by the fixed
cutoff. Retrying later cannot backdate its first observation.

Settlement replays retained evidence and binds the exact roster, result and
run-evidence identities, suite, registration snapshot, promotion head and row
in one transaction. It preserves the original artifact across retries and
restarts. Different inputs cannot overwrite it. Valid quorum certificates are
retained even when stronger run-evidence or settlement checks reject an action.
Late conflicts block subsequent actions and are exposed separately from the
immutable historical record. There is no clear-hold command.

These local cutoff and settlement objects remain weight-disabled. The separate
`SignedCutoffPublication` and `SignedSettlementPublication` contracts authenticate
and replay statements about them; see the publication rehearsal commands above.
Production publication and its observation evidence are separate from this
local rehearsal. None of these objects alone authorizes chain submission.

## Signed endpoint authorization rehearsal

The miner entrypoint accepts `--competition-policy`,
`--competition-authorization` and `--serving-origin` together, with the exact
submitted `--model-revision`. These supplement the existing transport policy,
finality observer, video-origin allowlist, backend and durable ledger arguments.
`python -m umi.miner --help` lists the complete required options. They are
rehearsal options; no live successor policy or assignment feed is published.

The authorization file uses `SignedEndpointAuthorization` from
[competition_authorization.py](../../src/umi/competition_authorization.py). It
contains a reference-free case list, the frozen round, miner-signed endpoint
submissions and the exact requests, signed by the policy's evaluator-group
quorum. The file is bounded to 16 MiB and must be canonical, locally owned JSON.
Never include private keys or reference labels in it.

Each request's batch and challenge IDs bind the successor policy, round,
submission and evaluator, with the challenge also binding its case. The wire
`scoring_policy_hash` remains the actual legacy transport hash. A new successor
round cannot reuse an old cached assignment under another identity.

The HTTP handler passes the verified btauth caller into authorization before
reserving resources, fetching video or invoking the model. The exact signed
assignment and the concrete legacy finalized-block/Quicknet schedule must both
pass. The miner narrows inference and output limits to the successor policy.
Existing durable nonce, request-count and encrypted-response caches remain in
use; restarting does not reset those limits or rerun a cached answer.

This mode is `competition_no_weight`. The configured serving origin is matched
to the miner-signed submission; it is not an Axon storage proof. The first local
load time is not independently proven publication timing. Elapsed issue slots
are excluded on reload, so later usable assignments can still run. A publication
with no usable local assignments is rejected. This finite-file mode does not
supply the live scheduler, automatic assignment discovery or evidence binding
the protected suite's release to the successor block and Quicknet schedule.

## Signed model retrieval

`retrieve-bundle` downloads declared model files without executing them:

```sh
umi-competition --policy policy.json retrieve-bundle \
  --submission signed-model-submission.json \
  --source-base-url https://REVIEWED_ARTIFACT_HOST/IMMUTABLE_MODEL_DIRECTORY \
  --archive /ABSOLUTE/PRIVATE/ARCHIVE \
  --maximum-files REVIEWED_FILE_LIMIT \
  --maximum-file-bytes REVIEWED_FILE_BYTE_LIMIT \
  --maximum-total-bytes REVIEWED_TOTAL_BYTE_LIMIT \
  --request-timeout-seconds REVIEWED_REQUEST_TIMEOUT \
  --total-download-timeout-seconds REVIEWED_DOWNLOAD_TIMEOUT
```

The operator must supply numeric limits. The source URL is an untrusted location
hint; the signed manifest authenticates the exact bytes. Retrieval uses HTTPS on
port 443, rejects redirects and private DNS answers, pins the resolved address,
and disables environment proxies. Each streamed file must match its exact size
and SHA-256 digest. Files remain private data throughout retrieval.

The completed stage is verified before atomic content-addressed preservation.
An existing verified archive is returned without downloading again. Failure or
cancellation removes only this retrieval's staging directory; prior archives
remain intact. Peak disk space must allow roughly twice the bundle size for
staging and the verified copy, plus retained history and filesystem overhead.
The byte limits do not reserve disk space or replace filesystem quotas. A
preserved bundle still needs reconstruction, evaluation and rights review.

## CPU inference adapter contract

`OfflineCpuRuntime` pins an installed OCI image by digest and declares CPU,
memory, process, scratch-space and video-size limits. Its digest must equal the
policy's `evaluation_runtime_sha256`. The image is installed by the evaluator
operator; a miner cannot request an unreviewed image pull.

Runtime `umi-offline-cpu-runtime/2` supports CPU frameworks that create POSIX
semaphores or shared-memory buffers. It assigns up to one quarter of the declared
scratch budget (capped at 64 MiB) to private `/dev/shm`, with the remainder at
`/tmp`. Both mounts are bounded, non-executable tmpfs filesystems; their combined
allowance never exceeds `scratch_bytes`. Mount sizes are rounded down to 64 KiB
units. IPC remains private and the model/input trees remain read-only.
Runtime v1 retains its original single `/tmp` mount and read-only shared memory.
The version changes the runtime digest, so selecting v2 requires a policy that
binds it explicitly. It does not alter an existing signed policy.

The initial adapter supports exactly one manifest file with role `inference`,
ending in `.py`. The pinned image supplies `/usr/local/bin/python3` and all
runtime dependencies. The program receives `/input/video.mp4` as its only
argument and writes one English hypothesis to stdout. The complete model is
read-only at `/model`. No reference text is supplied to the container.

On the separate Linux evaluation host, the explicit single-case command is:

```sh
umi-competition --policy policy.json run-offline-case \
  --runtime offline-runtime.json --manifest model-bundle.json \
  --archive /ABSOLUTE/UMI/ARCHIVE --video assigned-video.mp4 \
  --case-id ASSIGNED_CASE_SHA256 --video-sha256 ASSIGNED_VIDEO_SHA256
```

This command executes the contributed inference code inside the declared
container. Run it only after the evaluator host and pinned image are reviewed.
Its output is a case observation; it does not sign an evaluation quorum or
promote a model automatically.

Cold start is included in the per-case deadline. Network access and proxy
inheritance are disabled. Output and runtime are bounded; failure cleanup
removes only the randomly named case container and waits through repeated
cancellation. A separate [Podman timeout](https://docs.podman.io/en/v4.3/markdown/podman-run.1.html#timeout-seconds)
limits container lifetime if the Python evaluator dies. Its seconds-based
limit does not extend the policy's millisecond scoring deadline.
Run this on a separate
wallet-free Linux evaluation host. Do not run arbitrary models inside either
existing validator VM or on a machine containing coldkeys.

## Paired-model execution rehearsal

`ModelEvaluationJob` in [competition_execution.py](../../src/umi/competition_execution.py)
contains the frozen round, signed model submission, incumbent manifest, runtime
and evaluator identity. Its ordered case list contains case IDs, video hashes
and strata only. It contains no references, wallet paths or video URLs. Supply
each clip as `<video-sha256>.mp4` in an operator-controlled directory. Each clip
is read with a size limit, checked against its hash and copied into the
single-video sandbox input; the source directory is never mounted.

```sh
umi-competition --policy policy.json run-model-evaluation \
  --job model-job.json --chain-config chain-config.json \
  --archive /ABSOLUTE/UMI/ARCHIVE --videos /ABSOLUTE/PRIVATE/CLIPS \
  --state /ABSOLUTE/PRIVATE/EXECUTION_STATE

umi-competition --policy policy.json execution-status \
  --state /ABSOLUTE/PRIVATE/EXECUTION_STATE --execution-key EXECUTION_SHA256
```

Use a separate wallet-free Linux host, outside the UID 0 and UID 54 VMs. The
evaluator needs its own reviewed runtime, archived models, protected clips and
approved chain pins. No such live evaluator configuration or inference image is published by
this change. A local job file is not an authenticated round announcement.

The runner reserves one attempt per evaluator/round/submission before starting
the finalized observer. Startup waits, within its configured deadline, for a
new owned verified head. It then runs the candidate and incumbent sequentially
on each case, checking finalized boundaries around every invocation. Cold
start is timed; archive verification and finality collection are outside the
inference timer but must still fit within the round. Large models need a
throughput rehearsal because the adapter rechecks the archive before each case.

Each returned execution retains its bounded stdout prefix, outcome, elapsed
time and model/runtime/video digests. Stdout is persisted before the next
finality read. If that read fails, the pending observation remains in the
journal and the job fails without assigning miner blame. Missing evidence
after an abrupt crash never permits an automatic rerun. Completed retries
return the original evidence without reading models or starting the observer.
Keep the journal and the finalized provider's proof cache together in reviewed
backups. Boundary digests alone are not portable finality proofs.

The journal defaults to 1,024 jobs and 1 GiB of reserved logical receipt space;
`--maximum-jobs` and `--maximum-evidence-bytes` can set operator-reviewed limits.
Capacity includes worst-case JSON escaping. It excludes model/video archives
and database overhead. Full journals reject new jobs without deleting history.
The [continuous evaluator](../operators/evaluation.md#open-competition-evaluator) now advances signed
orders through execution, reveal and peer agreement. Coordinator order delivery
and fleet-wide evaluator capacity management still need deployment wiring.

After the authorized reveal, local proposal commands check the retained cases
against the full committed suite:

```sh
umi-competition --policy policy.json propose-execution-result \
  --inputs executions.json --suite revealed-suite.json --current-block OBSERVED_BLOCK

umi-competition --policy policy.json prepare-execution-record \
  --execution execution.json --result common-result.json \
  --suite revealed-suite.json --current-block OBSERVED_BLOCK
```

`executions.json` contains an `executions` array of complete retained evidence
objects. The proposal requires distinct authorized evaluator groups, identical
outputs/statuses and matching per-case resource eligibility. It uses the
maximum observed elapsed time for each case and the latest completion block.
Each evaluator checks this proposal against its own run before co-signing.
The second command prepares the separate unsigned run record whose execution
digest identifies the retained artifact. Command output wraps the proposed
object in `object`; extract that member when preparing `common-result.json`.

Neither command opens a wallet, signs, publishes evidence, changes a promotion
head or submits weights. `--current-block` here is a local replay input, not
proof that reveal occurred. A production signing/release service still needs
its owned finalized reveal check and authenticated evidence exchange. CLI JSON
inputs, including an aggregate `executions` file, are capped at 64 MiB; choose
and rehearse the release's case/quorum/output bounds accordingly.

## Intake capacity configuration

`CompetitionServiceConfig` has operator-controlled `admission_capacity` and
`api_limits` fields. These are service bounds, not a miner reward rule:

| Bound | Default |
| --- | --- |
| Retained admissions | 65,536 |
| Canonical signed-submission plus receipt bytes | 2 GiB |
| Concurrent submissions / reads / readiness checks | 8 / 16 / 2 |
| Concurrent finalized registration collections | 1 |
| Maximum page offset / page size | 65,536 / 100 |
| Loopback socket backlog | 128 |

Admission accounting and insertion share one SQLite transaction. Quota failures
do not advance the sequence or observed-block state. Historical authenticated
retries return their original receipts even if quotas are lowered below current
usage. Capacity exhaustion returns a bounded 503 response. Operators must
provision capacity and a retention plan; restarting does not erase the ledger.
The loopback listener has no undifferentiated connection ceiling that public GET
traffic could consume ahead of a POST. Route-specific application semaphores
bound submissions, reads and readiness work independently. The listener must
remain reachable only through the reviewed HTTPS tunnel or proxy, which bounds
headers, slow connections and per-source traffic; do not expose it directly.

## Release checks

```sh
python -m pytest -q tests/test_open_competition.py tests/test_competition_*.py
python -m pytest -q tests/test_publication.py
make -C whitepaper
```

Before production activation, complete Section 10 of the successor whitepaper
and publish the exact evidence. Continue the current bridge until an explicit
signed replacement or revocation. Historical finite policies keep their own
cutoffs. No local CLI result changes either schedule.
