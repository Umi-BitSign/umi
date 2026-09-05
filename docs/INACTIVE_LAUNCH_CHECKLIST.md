# SN78 inactive calibration launch checklist

This checklist is the go/no-go record for starting UMI's public, weight-disabled
calibration on SN78. It does not authorize translation weights. Every process in
this launch uses a policy with `translation_weights_active: false`, and the live
validator contains no weight-call capability.

Three milestones must stay separate:

1. **Repository release ready:** the code, model adapter, tests, and signed Linux
   runtime release are reproducible.
2. **Public calibration ready:** the required independent operators and data plane
   are live, and a complete window can end in a replayable
   `calibration_no_weight` bundle.
3. **Weight activation ready:** every gate in whitepaper Section 14 has passed and
   a later governed active policy has been published. This checklist does not
   claim that milestone.

## 1. Freeze the repository and baseline miner

- [ ] Import the baseline model only after its checkpoint, architecture/config,
  tokenizer or vocabulary, preprocessing/decoder, license, and provenance have
  been reviewed together. Restricted data and weights must remain outside the
  public repository unless their grant covers the exact distribution.
- [ ] Use an immutable model-owned release identity that binds the checkpoint,
  architecture/config, tokenizer/vocabulary, preprocessing/decoder runtime, and
  license/provenance material. If the model repository has no stricter canonical
  manifest, build `umi-model-release/1` from those five component digests. Use the
  resulting SHA-256 as `model_revision` on both the model backend and miner.
- [ ] Pass one known eligible MP4 through the real model, `umi-miner`, signed
  response timelock, reveal, decryption, and exact score calculation.
- [ ] Pass timeout, model exception, non-text output, over-limit output, sidecar
  restart, exact retry, and log-privacy tests. Poor accuracy is acceptable for
  inactive calibration; a fabricated fallback answer is not.
- [ ] Run the full Python, Rust, dependency, conformance, wheel-install, console
  entry-point, whitepaper-build, link, secret, and large-file checks from the
  exact clean commit intended for release.
- [ ] Create the signed, target-specific Linux release by following
  [SHADOW_CALIBRATION_OPERATOR.md](SHADOW_CALIBRATION_OPERATOR.md). Record its git
  revision, manifest SHA-256, release-authority hotkey, target triple, and public
  download location.
- [ ] Tag and publish the reviewed commit only after repository-owner approval.

## 2. Verify the public SN78 identity and live parameters

The owner identity update is complete. Finalized block `8993215`, block hash
`0xacdbccd65638585a820d1c18d29c57e45010bfa6ee9b6474c9a3a6e4fd1c3db3`,
contains successful extrinsic
`0xb9db7098a6c65de5a2694cf74c0b4d1b414400cd492cdcf1cc12c31e2f10ecec`
and `SubnetIdentitySet(78)`. The resulting identity names UMI, links the public
repository and `https://www.umi.vision`, and retains the live Discord and logo
fields. Do not rerun an old replacement command: identity updates replace the
whole record and can erase fields that are already correct.

The group reported that the subnet owner identity and hyperparameters were updated
and that the services were running. The public observer confirms the identity and
is serving fresh finalized state. Its read at block `8995150`, block hash
`0x66e448a52cb4f650b8fdcd9d3bf03cac1fb6e1ec131e6aad5ad6dc605754bd7f`,
on 2026-09-04 still showed one separate launch requirement unmet: the live
`activity_cutoff_factor` remained `13889`, which derives a 5,000-block cutoff at
tempo 360. `subnet_emission_enabled` also remained false. Lower the cutoff to one
360-block tempo in a separate preview and submission:

```bash
btcli tx set-hyperparameter \
  --network finney \
  --wallet YOUR_OWNER_WALLET \
  --wallet-path /absolute/path/to/wallets \
  --netuid 78 \
  --name activity_cutoff_factor \
  --value 1000 \
  --dry-run
```

Run that change comfortably outside the runtime's final ten-block admin freeze
window, then follow the live-submission and finalized-state verification steps in
[`../deploy/first-public-result/owner-cutoff/README.md`](../deploy/first-public-result/owner-cutoff/README.md).
If a token-symbol change is wanted, choose an unused live-catalog symbol explicitly
and dry-run `btcli tx update-symbol` separately; renaming the subnet does not change
its symbol.

- [x] Confirm the identity at one finalized block and retain the transaction
  events and block hash.
- [ ] Confirm MechId 0, commit-reveal state, runtime version, tempo, weight rate,
  activity cutoff, immunity period, and subnet emission flags at that same block.
- [ ] Keep existing chain incentive and emission numbers labeled as native,
  unverified economics. They are not UMI translation results.
- [ ] Ask the relevant chain operator to restore subnet emission only after the
  public inactive mechanism is observable. Restoration does not activate UMI
  translation weights and is not evidence that the activation gates passed.

The identity and symbol transactions change public chain state. They require an
explicit owner decision and are not performed by repository tooling.

## 3. Fix the inactive policy and operator registry

A conforming activation-evidence window needs the policy roles below. A founding
group can run component tests before they exist, but several hotkeys controlled by
one team still count as one control group and cannot produce a valid two-group
window.

| Role | Launch minimum | Required evidence |
|---|---:|---|
| Publisher | Exactly 3 hotkeys in exactly 3 independently administered control groups | Registration/ownership, funded voluntary collateral and floor, disclosure, signed capacity statement |
| Validator | At least 4 independently administered permitted hotkeys | Signed capacity statement, mirror readiness, signed release binding, operator configuration |
| Miner | At least 3 active miners from at least 2 independent implementations for the activation gate | Serving record, policy-bound authentication, real model response |

- [ ] Set the policy activation block far enough ahead for release signing,
  distribution, operator startup, finality catch-up, capacity signing, pool
  preparation, and window-zero announcement.
- [ ] Pin the exact validator and publisher registries, control groups, collateral
  floor, capacity-set root, mirror discovery digest, fixtures, binaries, cadence,
  limits, deadlines, and economics schedule.
- [ ] Obtain all publisher-capacity and validator-capacity signatures before the
  release authority signs the final inactive release.
- [ ] Verify that no account is represented as independent when beneficial
  ownership, administration, wallet or collateral custody, privileged pre-reveal
  ground-truth access, or operational decision authority is shared. Disclose every
  funding relationship and apply the arm's-length compensation test in whitepaper
  Sections 1.1 and 4.3 before assigning control groups.
- [ ] Publish one signed `umi-publisher-control-disclosure/1` object per group
  before the soak announcement, verify every required payer countersignature, and
  byte-match its canonical hash to `control_disclosure_sha256` in that group's
  capacity statement. Byte-match the group ID, administrator, publisher-hotkey
  list, and shadow-policy hash across both objects. A replacement disclosure also
  requires a replacement signed capacity statement.
- [ ] Establish the public material-change notice path. Affected publishers pause
  proposals immediately; validators check it at pool close and weight build, void
  affected unrevealed windows, and pause UMI submissions until replacement
  disclosure, capacity, and policy evidence is valid.

Any registry, cadence, scoring, resource, or economics change after the soak starts
requires a new policy and restarts the soak.

## 4. Deploy the data and evidence plane

- [ ] Materialize each validator's private startup configuration from the verified
  signed release. The local bindings may name the intended window-specific mirror
  header path before that file exists.
- [ ] Before the announcement, start `umi-validator-live --prime-next-window` with
  the signed validator config alone so the finality observer retains the exact
  announcement header. Confirm afterward that every validator records the same
  window ID at `pool_and_selection` before qualification. Do not pass an operator
  config or wallet to this planner-only command.
- [ ] Build candidate batches with
  [PUBLISHER_BATCH_OPERATOR.md](PUBLISHER_BATCH_OPERATOR.md). Keep consent records,
  contributor identities, prompts, and unrevealed references out of public
  artifacts.
- [ ] Run qualification and collect the unique quorum certificate using
  [PUBLISHER_AVAILABILITY_OPERATOR.md](PUBLISHER_AVAILABILITY_OPERATOR.md).
- [ ] Before the first qualification transfer, append the publisher's signed
  disclosure-quarantine record with the window, batch, commitment, reveal round,
  disclosure evidence, all 14 video hashes, all 14 frame digests, and all 16
  actual and reserved script hashes.
- [ ] Reconcile the proposed inventory against the publisher's private
  disclosure-quarantine ledger and reject every video, frame, or script hash hit,
  while leaving the canonical validator spent root unchanged.
- [ ] Put every certified object on the authenticated mirror origins and make the
  distinct miner-delivery origins ready using
  [MIRROR_SERVICE_OPERATOR.md](MIRROR_SERVICE_OPERATOR.md).
- [ ] Verify the signed mirror-readiness set from each validator's final network
  location. The release, pool-anchor, index, discovery, publisher, digest, signer,
  retrieval-origin, and delivery-origin bindings must all match.
- [ ] Anchor each final publisher pool using
  [PUBLISHER_POOL_ANCHOR_OPERATOR.md](PUBLISHER_POOL_ANCHOR_OPERATOR.md), then retain
  the finalized inclusion and closing-block storage proof.
- [ ] Put all public HTTP services behind TLS with bounded header/body reads,
  connection and request limits, no redirects, and narrowly scoped credentials.
  Validate DNS from the deployed network and pin the resolved public address for
  each request.
- [ ] Run media qualification on a supported Linux release so FFmpeg and FFprobe
  inherit the repository's finite address-space, CPU, and core-dump limits.

## 5. Deploy miners and validators

- [ ] Start the model sidecar under its own supervisor, memory limit, inference
  deadline, and restart policy. Start `umi-miner` with the same model revision,
  scoring-policy digest, validator slot count, and exact delivery-origin allowlist.
  Follow [MINER_MODEL_INTEGRATION.md](MINER_MODEL_INTEGRATION.md).
- [ ] For an Apple Silicon miner, follow
  [MACOS_MINER_OPERATOR.md](MACOS_MINER_OPERATOR.md), resolve the signed Darwin
  miner target, and pass the 112-request capacity rehearsal on that host. A Mac
  Studio validator runs inside a dedicated native ARM64 Linux VM and follows the
  ordinary signed Linux validator procedure; a host-native Darwin validator is
  not conforming.
- [ ] Verify that exact miner retries return the original ciphertext and never run
  inference twice. Verify that model and protocol logs contain neither video nor
  hypotheses before reveal.
- [ ] After the window-specific mirror readiness and private headers are installed,
  run `umi-validator-live --check` as the final operator account, then start the
  process under a supervisor. A successful prime does not satisfy this full
  readiness gate.
- [ ] Start `umi-validator-audit-publish` with a disjoint private staging root,
  public document root, durable state database, and HTTPS origin. Follow
  [AUDIT_BUNDLE_PUBLICATION_OPERATOR.md](AUDIT_BUNDLE_PUBLICATION_OPERATOR.md).
- [ ] Start the read-only observer API and configure `umi.vision` as a same-origin
  proxy. It must keep native chain economics separate from validator-local UMI
  calibration evidence.
- [ ] Confirm that no inactive validator process or dependency object exposes a
  weight builder, weight signer, generic extrinsic submitter, or weight submission
  credential.

## 6. Run the launch window

- [ ] Before announcement, verify finality health, proof verification, commitment
  space, mirror readiness, disk capacity, clock synchronization, TLS validity, and
  process resource headroom on every participating host.
- [ ] Run the complete window without manual candidate removal or assignment
  changes. Missing miner work stays in the denominator as zero.
- [ ] Confirm assignment, request, and sealed-response anchors reached finality at
  their required boundaries.
- [ ] Confirm that responses and ground truth stayed sealed until the common reveal
  round, every candidate retired, and spent and publisher-fault transitions agree
  across validators.
- [ ] Confirm every validator reached `calibration_no_weight`, captured a finalized
  no-weight interval, and produced a signed bundle that a fresh verifier replays
  exactly.
- [ ] Confirm that no UMI weight commit or set-weights call was emitted.
- [ ] Confirm each public bundle and per-validator index reads back byte-for-byte
  over its public HTTPS route, and that the observer shows the window and any
  incidents with validator attribution.

If any required check fails, publish the bounded incident, preserve the evidence,
and keep new window intake paused until the documented recovery procedure succeeds.
Do not replace missing evidence with a hand-edited status or fallback row.

For a failed qualification, short quorum, failed aggregation, failed mirror
readiness, late or rejected anchor, or abandoned anchor attempt, record the
terminal outcome against the existing disclosure-quarantine record. Confirm that
the material did not return to publisher inventory. Do not append the private
record to canonical spent state or use it to change validator candidate selection,
scores, or weights.

## 7. Public launch message

The first announcement should state all of the following plainly:

- SN78 is running a public, weight-disabled UMI calibration mechanism.
- The baseline model works end to end but its accuracy is not yet an activation
  result.
- Current chain emissions and incentives are not UMI translation scores.
- Public bundles can reproduce each released validator-local result.
- Translation weights remain disabled until every published activation gate passes.

Only describe the mechanism as live after one real window completes the checks in
Section 6. Only describe UMI translation weights as active after the separate
governed activation policy and Section 14 gate record are public.
