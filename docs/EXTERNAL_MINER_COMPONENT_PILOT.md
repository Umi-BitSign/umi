# External miner component pilot

This is the shortest honest way to publish a signed, replayable result from an
external miner's local reference-model installation before the signed inactive
release exists. The command creates one challenge from the existing CC BY 3.0
`ASL BOOK` asset, derives future drand Quicknet rounds, runs the pinned S1 model,
produces the normal component bundle, and replays it before returning success.
Success also requires one decrypted `ok` response that binds the fetched video
digest and locally configured model revision. A fetch, startup, inference, or
response failure exits nonzero and leaves no publication directory.

It is a `component_test_no_weight`, not a protocol window. The miner process runs
in-process and the command does not contact its public axon. The declared UID is
not read from chain. A successful result therefore proves that the supplied miner
hotkey signed the locally generated response, but it does not prove public serving,
UID ownership, validator independence, activation readiness, or eligibility for
weights.

## Pinned first operator

The first requested run is for:

| Field | Value |
|---|---|
| Network | Finney, SN78 |
| Declared UID | `236` |
| Expected hotkey | `5G24BM47QsavXYWxZ3k9FbLb6Kpcqs5NQBuLqFxHzwKAJKsV` |
| Model tag | `umi-s1-public-finetune-v1-r2` |
| Model tag commit | `20307ea05684e098ab362fa6bfc174c2aced3b9e` |
| Model tag signer | `478B 8C18 537D 7536 A8C3 982D 58B4 4AF3 49CF 5A4D` |

The UID/hotkey values are explicit inputs rather than code constants, so the same
command can be used for a later miner. The receipt always marks the UID binding as
unverified.

## Prepare the model environment

Use a dedicated clone and Python 3.12 environment. Obtain the model tag signer's
public key through the trusted UMI release announcement, import it, and verify the
full fingerprint shown above before trusting `git verify-tag`. A short key ID or a
successful signature check without the fingerprint comparison is insufficient.

Check out the signed model release commit and the exact UMI commit named in the
pilot announcement. Do not substitute either repository's moving `main` branch.
Both checkouts must be clean when the pilot starts.

```bash
set -euo pipefail
export PILOT_UMI_REVISION=40_LOWERCASE_HEX_FROM_THE_PILOT_ANNOUNCEMENT
export MODEL_TAG=umi-s1-public-finetune-v1-r2
export MODEL_TAG_COMMIT=20307ea05684e098ab362fa6bfc174c2aced3b9e
export MODEL_SIGNER=478B8C18537D7536A8C3982D58B44AF349CF5A4D

# The announcement must authenticate MODEL_SIGNER. Fetching the matching public
# key makes it usable by GnuPG; the key server is not the source of trust.
MODEL_SIGNER_KEY="$(mktemp "${TMPDIR:-/tmp}/umi-release-signer.XXXXXX")"
trap 'rm -f "$MODEL_SIGNER_KEY"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://keys.openpgp.org/vks/v1/by-fingerprint/$MODEL_SIGNER" \
  --output "$MODEL_SIGNER_KEY"
test "$(gpg --show-keys --with-colons "$MODEL_SIGNER_KEY" | \
  awk -F: '$1 == "fpr" {print $10; exit}')" = "$MODEL_SIGNER"
gpg --import "$MODEL_SIGNER_KEY"
rm -f "$MODEL_SIGNER_KEY"
trap - EXIT
gpg --with-colons --fingerprint "$MODEL_SIGNER" | grep -F ":$MODEL_SIGNER:"

mkdir -p "$HOME/umi-miner"
cd "$HOME/umi-miner"
git clone https://github.com/Umi-BitSign/umi-reference-model.git
git clone https://github.com/Umi-BitSign/umi.git
git -C umi-reference-model verify-tag --raw "$MODEL_TAG"
test "$(git -C umi-reference-model rev-parse "$MODEL_TAG^{commit}")" = \
  "$MODEL_TAG_COMMIT"
git -C umi-reference-model checkout --detach "$MODEL_TAG_COMMIT"
git -C umi checkout --detach "$PILOT_UMI_REVISION"
test -z "$(git -C umi-reference-model status --porcelain=v1 --untracked-files=all)"
test -z "$(git -C umi status --porcelain=v1 --untracked-files=all)"

export RELEASE_GIT_REVISION="$MODEL_TAG_COMMIT"
export SOURCE_GIT_REVISION="$(jq -er .source_git_revision \
  umi-reference-model/release/release-manifest.json)"
test "$(git -C umi-reference-model rev-parse HEAD^)" = "$SOURCE_GIT_REVISION"
test "$(git -C umi-reference-model rev-list --parents -n 1 HEAD | \
  wc -w | tr -d ' ')" = 2
```

Then complete Sections 2 through 5 of the tagged reference model's
[`RUN_MINER.md`](https://github.com/Umi-BitSign/umi-reference-model/blob/umi-s1-public-finetune-v1-r2/docs/RUN_MINER.md):
install both locked projects into the model environment, verify the release
artifacts, build and bind the local extractor, download the fixed MediaPipe task,
and make the backend probe pass. Section 1's signed inactive release is required
for public miner serving, but is deliberately not treated as a prerequisite or
substitute for this local component test.

Keep the resulting environment variables in the current shell, including
`UMI_S1_INFERENCE_REVISION`. The r2 lock uses PyTorch's CUDA 12.6 dependency set,
which does not support the UID 236 host's RTX 5090. Keep `UMI_S1_DEVICE=cpu` for
this pilot. Supporting that GPU requires a later signed release tested with the
official CUDA 12.8 build; do not modify the sealed r2 lock.

## Run the one-command pilot

The miner's named Bittensor wallet must contain the private hotkey corresponding to
the expected SS58 address. Create a different, local pilot-validator hotkey if one
does not already exist. Never send either private key to UMI operators.

Run this from the verified model environment. Choose an output directory outside
both Git repositories that does not already exist.

```bash
set -euo pipefail
cd "$HOME/umi-miner/umi-reference-model"
export PILOT_UMI_REVISION=40_LOWERCASE_HEX_FROM_THE_PILOT_ANNOUNCEMENT
test -n "${UMI_S1_INFERENCE_REVISION:-}"

./.venv/bin/python -m umi.external_miner_pilot \
  --output "$HOME/umi-miner/public-evidence/uid-236-component-pilot" \
  --umi-repo "$HOME/umi-miner/umi" \
  --expected-umi-revision "$PILOT_UMI_REVISION" \
  --model-repo "$HOME/umi-miner/umi-reference-model" \
  --wallet-path "$HOME/.bittensor/wallets" \
  --validator-wallet-name umi \
  --validator-hotkey pilot-validator \
  --miner-wallet-name YOUR_MINER_WALLET_NAME \
  --miner-hotkey YOUR_MINER_HOTKEY_NAME \
  --expected-miner-uid 236 \
  --expected-miner-hotkey 5G24BM47QsavXYWxZ3k9FbLb6Kpcqs5NQBuLqFxHzwKAJKsV
```

The defaults reserve five minutes for startup plus inference and then a 30-second
reveal margin. The process waits for the derived Quicknet reveal, so several
minutes of quiet execution is expected. An `ok` hypothesis may still receive a
zero score; do not rerun merely to select a more favorable hypothesis. A transport,
fetch, startup, inference, binding, or signed-response failure exits nonzero and is
not accepted as this real-model pilot.

Before inference, the command checks all of the following:

- the exact clean UMI revision and that the running `umi` package comes from it;
- the exact signed model tag, commit, and full signer fingerprint;
- the release manifest, artifact digests, sealed history, and UMI ancestry;
- the exact clean model checkout and loaded `bitsign_motion` source path;
- the locally rebound model revision reported by the backend; and
- the checked-in and remotely fetched `ASL BOOK` byte length and SHA-256.

## Inspect and hand off the result

Success leaves only these publication artifacts:

```text
uid-236-component-pilot/
├── bundle/
│   ├── manifest.json
│   └── objects/
└── kit-receipt.json
```

The temporary plaintext input files are removed. The bundle itself contains the
revealed references and hypotheses needed for public replay. `kit-receipt.json`
pins the source, asset, miner declaration, and safety boundary. It explicitly says:

- `evidence_class: component_test_no_weight`;
- `translation_weights_active: false`;
- `protocol_conformance: false`;
- `activation_evidence: false`;
- `validator_input_eligible: false`;
- `public_miner_transport_used: false`;
- `public_axon_service_proven: false`; and
- `uid_chain_binding_verified: false`.

The receipt also says `receipt_authenticated_by_miner: false`,
`source_verification_is_operator_asserted: true`, and
`model_execution_is_operator_asserted: true`. It also marks the model revision as
operator-asserted. The receipt records the checks made by the local wrapper and
binds the bundle manifest in one direction, but the bundle does not bind or
authenticate the receipt. The observer currently ingests only `bundle/`. Do not
describe the receipt's tag, source, UID, or model-execution fields as
miner-authenticated evidence.

Compute the two handoff digests and send the complete directory to the observer
operator without editing or reserializing it:

```bash
PILOT="$HOME/umi-miner/public-evidence/uid-236-component-pilot"
sha256sum "$PILOT/bundle/manifest.json" "$PILOT/kit-receipt.json"
```

The observer operator can add `bundle/` to the component-pilot feed by following
[`COMPONENT_PILOT.md`](COMPONENT_PILOT.md). A later public-axon test must use the
remote validator path after the signed inactive release and finality artifacts are
available. This local bundle must never be presented as that test.

## Asset attribution

The pilot uses Richard Goodrow's `ASL BOOK` video under CC BY 3.0. Its immutable
source, conversion, license, and digest record is in
[`ASL_BOOK_ATTRIBUTION.md`](pilot-media/ASL_BOOK_ATTRIBUTION.md). The receipt marks
the clip as non-fresh, without UMI-specific consent or independent reference
review, and ineligible for a protocol window.
