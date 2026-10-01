[Documentation](../README.md) / Current miner connection guide

# Current miner connection guide

Public C5 intake accepts endpoint-service and public-model submissions. C5 uses a
recoverable cohort runtime: phase blocks are operating targets, and coordinator
or validator downtime delays unfinished work instead of expiring the cohort.
Check [live status](https://api.umi.vision/v1/competition/status) and
[readiness](https://api.umi.vision/v1/competition/readiness) before signing or
diagnosing a submission.

C4 remains the effective reward cohort until C5 produces a certified successor
row. A C4 acceptance does not accept C5's policy or version 3 terms. Submit and
retain a fresh C5 acceptance. Registration, acceptance, selection, scoring and
reward activation are separate events.

## Install the C5 runtime

Use runtime revision `ea32437d294bc0108c59812ff956477bd8f90d17` in the
locked environment that runs the protocol service:

```sh
python -m pip install 'umi-subnet @ git+https://github.com/Umi-BitSign/umi.git@ea32437d294bc0108c59812ff956477bd8f90d17'
```

Linux uses CPython 3.12.14 and the dependency versions pinned by the transport
policy. Preserve the working C4 environment and state until the C5 service has
passed startup and health checks.

## Download and verify the C5 policies

Download the canonical [competition policy](../competition/C5_POLICY.json) and
[transport policy](../competition/C5_TRANSPORT_POLICY.json) from the same
repository revision as this guide. Their file SHA-256 values are:

```text
0d432e253ff8f3dd5bb08749b9452b7d0dde4139238c6b3b570cd5e1741fbd4d  C5_POLICY.json
f182c1cbfa3985338944735cc55b52b46b12b0207436d79dd5978087483f01a8  C5_TRANSPORT_POLICY.json
```

Verify both file hashes, then verify their protocol digests with the installed
runtime:

```sh
python - C5_POLICY.json C5_TRANSPORT_POLICY.json <<'PY'
import hashlib
import sys
from pathlib import Path

from umi.open_competition import CompetitionPolicy, digest
from umi.policy import ScoringPolicy, scoring_policy_hash

policy_path, transport_path = map(Path, sys.argv[1:])
policy_raw = policy_path.read_bytes()
transport_raw = transport_path.read_bytes()
assert hashlib.sha256(policy_raw).hexdigest() == '0d432e253ff8f3dd5bb08749b9452b7d0dde4139238c6b3b570cd5e1741fbd4d'
assert hashlib.sha256(transport_raw).hexdigest() == 'f182c1cbfa3985338944735cc55b52b46b12b0207436d79dd5978087483f01a8'
policy = CompetitionPolicy.model_validate_json(policy_raw)
transport = ScoringPolicy.model_validate_json(transport_raw)
assert digest(policy) == '61f6c05143804c297aed524b6e067233567d30fe4eb50ab3289e7bfdad8e26fa'
assert scoring_policy_hash(transport) == 'f182c1cbfa3985338944735cc55b52b46b12b0207436d79dd5978087483f01a8'
print('C5 policies verified')
PY
```

C5's transport permits UID54
`5FLKx6h7DwWRuqq1dcfQafsBw5i9cbchNEFAEHrqSRthGnDZ` to issue work. It is not
interchangeable with C4's UID0 transport policy.

## Create the recoverable C5 startup file

After signing and receiving a C5 endpoint acceptance, create a dedicated private
directory for C5 grants. The model revision and serving origin below must exactly
match the accepted submission. Run this as the miner service account, supplying
its hotkey, model revision, serving origin, and a new absolute grant directory:

```sh
python - YOUR_HOTKEY MODEL_REVISION https://YOUR_ORIGIN /ABSOLUTE/NEW/C5/GRANTS > cohort5-miner.json <<'PY'
import sys
from pathlib import Path

from umi.competition_cohort_intake import CohortIntakeBinding
from umi.competition_cohort_miner import CohortServiceMinerConfig
from umi.competition_cohort_miner_startup import CohortMinerStartupConfig
from umi.protocol import canonical_json_bytes

hotkey, model_revision, origin, directory = sys.argv[1:]
path = Path(directory)
assert path.is_absolute() and not path.exists()
path.mkdir(mode=0o700, parents=True)
authority = CohortServiceMinerConfig(
    schema='umi-cohort-service-miner-config/1',
    directory=str(path),
    cohorts=(CohortIntakeBinding(
        cohort_sha256='5dab3bfb836a91898f010bd229115e3e1c0406c3e17498d3b3b1975adab71428',
        authority_sha256='57d4bc831ba36a0bb45f690476f07df5cf12df923d403314fd03efbde22e6fad',
    ),),
    policy_sha256='61f6c05143804c297aed524b6e067233567d30fe4eb50ab3289e7bfdad8e26fa',
    transport_policy_sha256='f182c1cbfa3985338944735cc55b52b46b12b0207436d79dd5978087483f01a8',
    miner_hotkey=hotkey,
    model_revision=model_revision,
    serving_origin=origin,
    service_terms_sha256='5364a993a30a7e06defcc117d1447fbb000aa2894eae6224b57af7ae43dcb479',
)
startup = CohortMinerStartupConfig(
    schema='umi-cohort-miner-startup/1',
    authority=authority,
    history_origin='https://api.umi.vision',
    history_owner_hotkey='5FLKx6h7DwWRuqq1dcfQafsBw5i9cbchNEFAEHrqSRthGnDZ',
)
sys.stdout.buffer.write(canonical_json_bytes(startup))
PY
chmod 600 cohort5-miner.json
```

The command refuses to reuse an existing grant directory. Preserve that
directory with the assignment, response and nonce databases through upgrades and
restarts.

## Update the running miner

Keep the existing model backend, wallet, hotkey, nonce database and serving
origin. Replace the competition-specific inputs with:

```text
--policy /absolute/path/C5_TRANSPORT_POLICY.json
--competition-policy /absolute/path/C5_POLICY.json
--competition-cohort-config /absolute/path/cohort5-miner.json
--serving-origin https://YOUR_ORIGIN
--model-revision YOUR_ACCEPTED_MODEL_REVISION
--max-recovery-assignments 4096
```

Do not also pass `--competition-feed` or `--competition-authorization`. Use a new
C5 assignment database and a new policy-bound owned-finality state directory;
do not edit C4 database metadata to force it to accept the new transport hash.
Keep the old state intact for retained C4 evidence. Continue to use the finality
and storage-proof binaries whose exact target digests are pinned in the C5
transport policy.

The public TLS edge must proxy `POST /v1/translate`,
`POST /v1/competition/cohorts/assignments`, the response-recovery route, and the
retirement route to the miner without changing paths, bodies or authentication
headers. A static edge `/healthz` response does not prove those routes work.

## Check the running miner

Read `/healthz` directly from the protocol process. Expect:

- `ok: true`, `runtime_mode: competition_no_weight`, and
  `finality_service: running`;
- competition policy
  `61f6c05143804c297aed524b6e067233567d30fe4eb50ab3289e7bfdad8e26fa`;
- transport policy
  `f182c1cbfa3985338944735cc55b52b46b12b0207436d79dd5978087483f01a8`;
- the same model revision and serving origin as the accepted C5 submission.

No assignments are expected during intake. After roster and request phases open,
the miner retrieves signed cohort history from the public API and durably stores
each grant before inference. An unavailable coordinator or validator causes a
retry; it does not become a miner failure or terminate C5. Preserve signed
responses and grant state until certified retirement.
