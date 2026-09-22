[Documentation](../README.md) / Current miner connection guide

# Current miner connection guide

**Cohort 4 uses policy 8. You can prepare your miner now.** Its roster starts at finalized block **9,120,990**, followed by four hours for work preparation and a **24-hour evaluation-request window on a 48-hour cohort cadence**. Wall-clock times are estimates; finalized blocks control the schedule.

Intake is open. Coordinator service cutover and reward-path verification are still in progress. Check [live readiness](https://api.umi.vision/v1/competition/readiness) for assignment delivery and evaluation status. The downloaded deployment file is a preparation snapshot with both readiness flags false; it is not a live status feed. Competition scores and reward activation are separate.

Accepted endpoint submissions under policies 5, 6 or 7 can carry forward while their registration, terms and validity remain eligible. Updating this configuration alone does not require another intake submission. Keep your existing wallet, hotkey, model revision and submitted origin.

## Install the compatible miner

Use revision `f76e3d85f73fe6ac79dccf6de4760ec3396ebc4e` in the locked environment that runs your protocol service:

```sh
python -m pip install 'umi-subnet @ git+https://github.com/Umi-BitSign/umi.git@f76e3d85f73fe6ac79dccf6de4760ec3396ebc4e'
```

Linux requires **CPython 3.12.14**, `regex==2026.9.3`, and the package content hashes pinned in the transport policy. For a fresh environment, follow the reference model's [locked environment instructions](https://github.com/Umi-BitSign/umi-reference-model/blob/main/docs/RUN_MINER.md#2-install-the-locked-environment), using the revision above and `uv venv --python 3.12.14 .venv` explicitly. `--python 3.12` can select an incompatible distro Python. Preserve the working environment until its replacement passes startup checks. Apple Silicon operators should also follow the [Mac setup guide](macos.md).

## Download and verify the connection inputs

The [C4 input release](https://github.com/Umi-BitSign/umi/releases/tag/cohort4-miner-inputs-20260922-f5a9844) contains public policies and a signed feed profile. Run this in a directory where `umi-cohort4-inputs` does not yet exist:

```sh
python - <<'PYINPUTS'
import hashlib
import json
import os
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

os.umask(0o077)
expected = 'f5a984457a53549fb06d9076c3c446fa5149f164a902a9ed608753374adfda28'
base = 'https://github.com/Umi-BitSign/umi/releases/download/cohort4-miner-inputs-20260922-f5a9844'
root = Path('umi-cohort4-inputs')
root.mkdir(mode=0o700)
opener = build_opener(ProxyHandler({}))
opener.addheaders = [('User-Agent', 'umi-miner-setup/1')]
with opener.open(base + '/artifact-manifest.json', timeout=180) as response:
    raw = response.read(65537)
assert hashlib.sha256(raw).hexdigest() == expected
manifest = json.loads(raw)
(root / 'artifact-manifest.json').write_bytes(raw)
for name, sha in manifest['files'].items():
    assert Path(name).name == name and name.endswith('.json')
    with opener.open(base + '/' + name, timeout=180) as response:
        raw = response.read(1048577)
    assert hashlib.sha256(raw).hexdigest() == sha, name
    (root / name).write_bytes(raw)
print(root.resolve())
PYINPUTS
```

The feed-profile protocol digest is `82300a9c4f22b5b4e2053a52e56934d101f0b47b4372393387f9cd07c740f4a4`; this differs from its file SHA-256. Set `OWNED_FINALIZED_BLOCK` to a current height from your owned finality observer, then verify the profile and policy ancestry:

```sh
umi-competition --policy umi-cohort4-inputs/competition-policy-seq8.json \
  --predecessor-policy umi-cohort4-inputs/competition-policy-seq7.json \
  --predecessor-policy umi-cohort4-inputs/competition-policy-seq6.json \
  --predecessor-policy umi-cohort4-inputs/competition-policy-seq5.json \
  verify-miner-feed-profile \
  --profile umi-cohort4-inputs/signed-miner-feed-profile.json \
  --expected-profile-sha256 82300a9c4f22b5b4e2053a52e56934d101f0b47b4372393387f9cd07c740f4a4 \
  --legacy-policy umi-cohort4-inputs/transport-policy.json \
  --deployment umi-cohort4-inputs/intake-deployment.json \
  --current-block "$OWNED_FINALIZED_BLOCK"
```

## Update the existing service

Stop the old protocol process cleanly before restarting with these changes. Preserve its state and model assets. Replace the transport and competition policy arguments and include all three predecessor files:

```text
--policy /absolute/path/umi-cohort4-inputs/transport-policy.json
--competition-policy /absolute/path/umi-cohort4-inputs/competition-policy-seq8.json
--competition-predecessor-policy /absolute/path/umi-cohort4-inputs/competition-policy-seq7.json
--competition-predecessor-policy /absolute/path/umi-cohort4-inputs/competition-policy-seq6.json
--competition-predecessor-policy /absolute/path/umi-cohort4-inputs/competition-policy-seq5.json
--competition-feed https://api.umi.vision
--video-origin https://umi-competition-clips.sam-sn78.workers.dev
```

Keep only one `--competition-feed` argument and retain the other reviewed video origins. This profile requires **new assignment and owned-finality state paths** because the transport policy changed. Keep the old databases intact, and keep using your existing **nonce database**. Do not edit database metadata to force an old assignment database to accept the new transport hash.

Set `--assignment-db` to a new private C4 path. If your command supplies `--finality-state`, use a new C4 path for it too. Create a successor copy of `--competition-chain-config` with the new policy and a new private state directory. Pass your existing config and the new state directory as follows:

```sh
python - /absolute/path/existing-chain-config.json /absolute/path/new-c4-chain <<'PYCHAIN'
import os
import sys
from pathlib import Path
from umi.competition_chain import CompetitionChainConfig
from umi.protocol import canonical_json_bytes

os.umask(0o077)
old = Path(sys.argv[1])
state = Path(sys.argv[2])
assert state.is_absolute() and not state.exists()
config = CompetitionChainConfig.model_validate_json(old.read_bytes())
config = config.model_copy(update={
    'policy_sha256': 'ef91318ad9732a792d50b0153e0e0fe71ec2317a20733e563d50c90ef84e0fae',
    'state_directory': str(state),
})
raw = canonical_json_bytes(config)
CompetitionChainConfig.model_validate_json(raw)
new = old.with_name(old.stem + '-c4.json')
with new.open('xb') as output:
    output.write(raw)
print(new.resolve())
PYCHAIN
```

Point `--competition-chain-config` to the printed file. Keep the existing finality and proof binaries and chain specification. Your model does not need to move to Linux because the evaluator moved.

If your translator uses a sidecar with capacity metadata, update its transport digest to `667f727f6ebb5bee296b488ecb8f6c8ddf373c92472d38aaf3d53abd496fc81b` through its documented configuration/recovery procedure. Stop the old controller first, preserve its durable records, and use a new configuration/state namespace where required. Keep Unix socket paths short enough for the operating system. The inference allowance is **600 seconds**; a faster backend may advertise a tighter bound. The sidecar and miner must agree on transport and model identity.

## Check the running miner

Read `/healthz` directly from the protocol process, for example `curl --fail http://127.0.0.1:8091/healthz` when it listens on port 8091. Expect:

- `ok: true`, `runtime_mode: competition_no_weight`, and `finality_service: running`.
- Competition policy `ef91318ad9732a792d50b0153e0e0fe71ec2317a20733e563d50c90ef84e0fae`.
- Scoring/transport policy `667f727f6ebb5bee296b488ecb8f6c8ddf373c92472d38aaf3d53abd496fc81b`.

Before work is published for your miner, a signed feed query can return 401 / `assignment_feed_unavailable`. That alone does not require resubmission. Investigate a persistent failure after your work is published. `cached_publications: 0` is expected before assignments. The health fields `protocol_conformance`, `activation_evidence`, and `serving_origin_finality_verified` remain false in this release; they are not progress indicators.

Your TLS edge may retain its own `/healthz` for registration-bridge availability. Competition needs `POST /v1/translate` proxied to the miner with its path, body and authentication headers preserved. Monitor the protocol process separately: a static edge health response does not prove translation readiness.

These inputs passed native signature/lineage verification and connected startup, model-capacity and restart checks on UMI's owned Studio miner. Coordinator startup, real assignments, scores and on-chain competition rewards require their separate checks. The live API reports deployment readiness.

## Linux finality observer

For `x86_64-unknown-linux-gnu`, download the exact observer binary pinned by the
transport policy. It requires GLIBC 2.34 or newer and the system `libgcc_s.so.1`.
For Ubuntu, use 22.04 or newer for this artifact; Ubuntu 20.04's GLIBC 2.31
cannot run it. Check the host with `getconf GNU_LIBC_VERSION`. This release does
not provide a policy-pinned build for older glibc.
The existing [competition miner bundle release](https://github.com/Umi-BitSign/umi/releases/tag/umi-competition-miner-bundle-v1)
contains the Linux and Darwin observers, storage-proof verifiers, chain templates
and `SHA256SUMS`. Use the cohort 4 policy files above with that bundle.
A local build from the same Rust source is not guaranteed to have identical
bytes. The executable is separate from the JSON input manifest and is
also available from a [verified mirror](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/competition/artifacts/finality/x86_64-unknown-linux-gnu/67b4bb856b2230e12d9ce2ec74e0f03fb0e131043802b13326ab18bf9ec78925/umi-grandpa-finality-observer).

Run this after downloading `umi-cohort4-inputs`:

```sh
python - <<'PY'
import hashlib
import json
import os
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

os.umask(0o077)
root = Path('umi-cohort4-inputs')
policy = json.loads((root / 'transport-policy.json').read_bytes())
expected = '67b4bb856b2230e12d9ce2ec74e0f03fb0e131043802b13326ab18bf9ec78925'
assert policy['implementation_pins']['finality_verifier']['release_sha256_by_target']['x86_64-unknown-linux-gnu'] == expected
base = 'https://github.com/Umi-BitSign/umi/releases/download/umi-competition-miner-bundle-v1/'
opener = build_opener(ProxyHandler({}))
opener.addheaders = [('User-Agent', 'umi-miner-setup/1')]
with opener.open(base + 'umi-grandpa-finality-observer.x86_64-unknown-linux-gnu', timeout=180) as response:
    raw = response.read(7908289)
assert len(raw) == 7908288 and hashlib.sha256(raw).hexdigest() == expected
directory = root / 'artifacts'
directory.mkdir(mode=0o700, exist_ok=True)
target = directory / 'umi-grandpa-finality-observer'
if target.exists():
    assert not target.is_symlink() and target.read_bytes() == raw
else:
    with target.open('xb') as output:
        output.write(raw)
target.chmod(0o500)
print(target.resolve())
PY
```

Use the printed absolute path for the miner's `--finality-verifier-binary` and
the chain configuration's `finality_binary`; those paths must agree. Keep the
policy's verifier digest and use the new C4 state paths described above. This
download supplies the finality observer; it does not replace a signed validator
host release or the separate storage-proof verifier.

