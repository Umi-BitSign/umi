[Documentation](../README.md) / Cohort 3 connection update

# Cohort 3 connection update

This update prepares the stock UMI endpoint miner for competition policy 7.
The cohort 3 dispatch and evaluation services are ready for the scheduled roster
cutoff at block **9,116,910**. Assignments follow the finalized cutoff and work
authorization. Evaluation remains in no-weight mode; readiness does not mean
that a live cohort has completed or that rewards are active.

An existing accepted submission under policy 5 or 6 can carry forward. You do
not need to resubmit merely because there are no assignments or your hotkey is
absent from the first page of the submissions list.

## Release and public inputs

Use release `29c4988a528f07aab71df21ac71c8bf00a7598f9`. In the Python environment
that runs your UMI protocol service:

```sh
python -m pip install 'umi-subnet @ git+https://github.com/Umi-BitSign/umi.git@29c4988a528f07aab71df21ac71c8bf00a7598f9'
```

Download the public policies and signed connection profile into a new directory.
This checks the published manifest hash and every downloaded file:

```sh
python - <<'PY'
import hashlib
import json
import os
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

os.umask(0o077)
expected = '4388ef8c41378dcbe5aef210c170bacce601c73d4e1ad393293d14f7f9e28c47'
base = 'https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/competition/cohort3/miner-inputs/' + expected
root = Path('umi-cohort3-inputs')
root.mkdir(mode=0o700)
opener = build_opener(ProxyHandler({}))
opener.addheaders = [('User-Agent', 'umi-miner-setup/1')]
with opener.open(base + '/artifact-manifest.json', timeout=30) as response:
    raw = response.read(65537)
assert hashlib.sha256(raw).hexdigest() == expected
manifest = json.loads(raw)
(root / 'artifact-manifest.json').write_bytes(raw)
for name, sha in manifest['files'].items():
    assert Path(name).name == name and name.endswith('.json')
    with opener.open(base + '/' + name, timeout=30) as response:
        raw = response.read(1048577)
    assert hashlib.sha256(raw).hexdigest() == sha, name
    (root / name).write_bytes(raw)
print(root.resolve())
PY
```

The signed profile's protocol digest is
`29faab249b1945bd344020d13913666420bd685f949fe7e40083573155bc2cc2`.
The profile binds `https://api.umi.vision` as the feed and the permitted video
origins. Its protocol digest differs from its file SHA-256.

Verify the signature with the current finalized block from your owned finality
observer. Set `OWNED_FINALIZED_BLOCK` to that height before running:

```sh
umi-competition --policy umi-cohort3-inputs/competition-policy-seq7.json \
  verify-miner-feed-profile \
  --profile umi-cohort3-inputs/signed-miner-feed-profile.json \
  --expected-profile-sha256 29faab249b1945bd344020d13913666420bd685f949fe7e40083573155bc2cc2 \
  --legacy-policy umi-cohort3-inputs/transport-policy.json \
  --deployment umi-cohort3-inputs/intake-deployment.json \
  --current-block "$OWNED_FINALIZED_BLOCK"
```

## Update the existing service

Keep your existing wallet, hotkey, model revision, submitted serving origin,
translator, finality binaries and durable database paths. Preserve the existing
nonce, assignment, response and resource state across the restart.

Replace the existing competition policy argument and add the two predecessor
arguments, using absolute paths in your service definition:

```text
--competition-policy /absolute/path/umi-cohort3-inputs/competition-policy-seq7.json
--competition-predecessor-policy /absolute/path/umi-cohort3-inputs/competition-policy-seq6.json
--competition-predecessor-policy /absolute/path/umi-cohort3-inputs/competition-policy-seq5.json
--competition-feed https://api.umi.vision
```

Keep the existing transport policy. It must hash to
`d030da694b5dd8d0e02c4c5a9d607107ed54d8feec47e2ea0e7f6b1070630168`.
Allow the clip origin with
`--video-origin https://umi-competition-clips.sam-sn78.workers.dev`, alongside
the existing reviewed video origins. Use one `--competition-feed` argument;
it replaces `--competition-authorization`.

If your command includes `--competition-chain-config`, create a successor copy
of that config with only `policy_sha256` changed to
`9cb31c2c5cf9876d9deb3729573589ca73d4e1130f0497eaccd1dc2404ca3ee4`.
Keep all chain pins and the existing state directory. This example takes your
existing config path as its argument and writes a canonical copy beside it:

```sh
python - /absolute/path/to/existing-chain-config.json <<'PY'
import os
import sys
from pathlib import Path
from umi.competition_chain import CompetitionChainConfig
from umi.protocol import canonical_json_bytes

os.umask(0o077)
old = Path(sys.argv[1])
config = CompetitionChainConfig.model_validate_json(old.read_bytes())
config = config.model_copy(update={
    'policy_sha256': '9cb31c2c5cf9876d9deb3729573589ca73d4e1130f0497eaccd1dc2404ca3ee4'
})
raw = canonical_json_bytes(config)
CompetitionChainConfig.model_validate_json(raw)
new = old.with_name(old.stem + '-seq7.json')
with new.open('xb') as output:
    output.write(raw)
print(new.resolve())
PY
```

Point `--competition-chain-config` at the printed path. Restart the protocol
service once under the updated environment and command. Future ordinary rounds
continue through the feed without another restart.

Check `/healthz` on your miner. It should report `ok: true`,
`runtime_mode: competition_no_weight`, `finality_service: running`, and the
policy-7 digest above. Before assignments are published, a feed 401 or
`assignment_feed_unavailable` does not by itself indicate a bad hotkey or require
resubmission. A health-only endpoint still needs a working translation backend
to answer evaluation requests.

The same release, policy ancestry and preserved-state configuration have been
started on UMI's Studio miner and checked through its health endpoint. A full
cohort result is a separate readiness check.
