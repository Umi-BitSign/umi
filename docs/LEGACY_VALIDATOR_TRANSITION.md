# Legacy SN78 validator transition hold

This procedure retires a known legacy SN78 weight writer without moving, loading,
or inspecting its wallet. It applies to an operator who controls one of the old
validator processes and knows the exact systemd unit, PM2 application, Docker
container, or other supervisor target that starts it.

The hold is not a validator and does not write to the chain. It is a standalone
Python standard-library process with no Bittensor or third-party dependency and no
wallet, network, socket, HTTP, subprocess, process-control, or chain-write code
path. It keeps a local lock and can emit a bounded public receipt.
The receipt shows only that the hold lock was observed on that host at one instant.
It does not establish that another process or host cannot use the hotkey.

Finalized chain state is the cutover authority. The first UMI bootstrap submission
remains blocked until MechId 0 has no pending commit and every legacy row is
inactive under the live activity cutoff.

## Before starting

Use a fresh detached checkout of the exact 40-character UMI commit published by
the UMI operator. Clone over SSH and replace `COMMIT` below with that value:

```bash
set -euo pipefail
git clone git@github.com:Umi-BitSign/umi.git umi-validator-transition
test "$(git -C umi-validator-transition remote get-url origin)" = "git@github.com:Umi-BitSign/umi.git"
git -C umi-validator-transition fetch origin main
git -C umi-validator-transition checkout --detach COMMIT
test "$(git -C umi-validator-transition rev-parse HEAD)" = "COMMIT"
test -z "$(git -C umi-validator-transition status --porcelain)"
```

The version 1 hold source has this SHA-256:

```text
1f88ff10a1385439efc3e3c0a8d8c87a543e03e04865f910a83dba05847da2da
```

Before executing the source, hash its bytes in a separate isolated Python process
and make the file read-only. Replace the path with the detached checkout's absolute
path:

```bash
set -euo pipefail
test "$(python3 -I -S -c 'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' /ABSOLUTE/UMI_DIRECTORY/tools/legacy_validator_hold.py)" = "1f88ff10a1385439efc3e3c0a8d8c87a543e03e04865f910a83dba05847da2da"
chmod a-w /ABSOLUTE/UMI_DIRECTORY/tools/legacy_validator_hold.py
```

Every `run`, `receipt`, and unit-render command checks the source hash again,
resolves the checkout's Git HEAD, and fails unless both match the supplied pins.
That in-process check detects later drift but cannot make modified Python safe to
execute, which is why the independent check comes first. Do not install the UMI
Python package for this procedure. Run the standalone file with the host's Python
3.10 or newer interpreter.

Record these local values before proceeding:

```text
UID                 legacy validator UID
HOTKEY              public validator SS58 address
UMI_REVISION        exact detached UMI commit
UMI_DIRECTORY       absolute path to the detached checkout
HOLD_STATE          absolute private state directory with no spaces
LEGACY_SYSTEMD_UNIT exact old systemd unit, including its `.service` suffix
LEGACY_PM2_APP      exact old PM2 application when PM2 is used
LEGACY_CONTAINER    exact old Docker container when Docker is used
```

Do not put a wallet name, wallet path, password, seed phrase, private key, or
environment dump into this workflow. Do not post process listings, full command
lines, service files, container inspection output, or the private hold-state file.

## 1. Stop the exact legacy target

Stop only the target you identified. Never use `pkill`, `killall`, a process-name
match, or a repository-wide cleanup command.

For a user systemd unit:

```bash
set -euo pipefail
systemctl --user disable --now LEGACY_SYSTEMD_UNIT
if systemctl --user is-active --quiet LEGACY_SYSTEMD_UNIT; then exit 1; fi
if systemctl --user is-enabled --quiet LEGACY_SYSTEMD_UNIT; then exit 1; fi
```

For a system systemd unit:

```bash
set -euo pipefail
sudo systemctl disable --now LEGACY_SYSTEMD_UNIT
if sudo systemctl is-active --quiet LEGACY_SYSTEMD_UNIT; then exit 1; fi
if sudo systemctl is-enabled --quiet LEGACY_SYSTEMD_UNIT; then exit 1; fi
```

For an exact PM2 application:

```bash
set -euo pipefail
pm2 stop LEGACY_PM2_APP
pm2 delete LEGACY_PM2_APP
pm2 save
if pm2 describe LEGACY_PM2_APP >/dev/null 2>&1; then exit 1; fi
```

For an exact Docker container:

```bash
set -euo pipefail
docker update --restart=no LEGACY_CONTAINER
docker stop --time 30 LEGACY_CONTAINER
test "$(docker inspect --format '{{.State.Running}}' LEGACY_CONTAINER)" = "false"
test "$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' LEGACY_CONTAINER)" = "no"
```

If Docker Compose, cron, a deployment agent, or another parent service recreates
the target, disable that exact parent entry too. Do not continue until the old
process has exited and a supervisor restart cannot recreate it. Leave the old
checkout and wallet untouched.

## 2. Install the wallet-free hold

The renderer writes a new systemd user unit without starting it. Replace every
placeholder with an absolute value. The output must not already exist.

```bash
set -euo pipefail
python3 -I -S /ABSOLUTE/UMI_DIRECTORY/tools/legacy_validator_hold.py render-systemd-user \
  --uid UID \
  --hotkey HOTKEY \
  --umi-revision UMI_REVISION \
  --expected-source-sha256 1f88ff10a1385439efc3e3c0a8d8c87a543e03e04865f910a83dba05847da2da \
  --repository-root /ABSOLUTE/UMI_DIRECTORY \
  --state-dir /ABSOLUTE/HOLD_STATE \
  --python /usr/bin/python3 \
  --script /ABSOLUTE/UMI_DIRECTORY/tools/legacy_validator_hold.py \
  --output /ABSOLUTE/HOME/.config/systemd/user/umi-sn78-validator-hold.service
```

Review the unit locally. Its `ExecStart` must use `/usr/bin/env -i`, the selected
Python interpreter, the detached hold source and repository, the public UID and
hotkey, the exact UMI revision, the source hash, and the private state directory.
It must contain `RestrictAddressFamilies=AF_UNIX` and must not contain a wallet
argument or path. The generated command starts from an empty environment and runs
Python in isolated mode.

Start and enable it:

```bash
set -euo pipefail
systemctl --user daemon-reload
systemctl --user enable --now umi-sn78-validator-hold.service
systemctl --user is-active --quiet umi-sn78-validator-hold.service
```

Restart the user manager's hold target once and verify that only the hold returns:

```bash
set -euo pipefail
systemctl --user restart umi-sn78-validator-hold.service
systemctl --user is-active --quiet umi-sn78-validator-hold.service
```

If the user manager does not persist after logout, the operator may enable linger
for this account. Persistence is useful operational evidence, but the disabled old
target and finalized chain observations remain more important than hold uptime.

## 3. Create the public receipt

Use the exact same public identity, revision, source hash, and state directory:

```bash
set -euo pipefail
python3 -I -S /ABSOLUTE/UMI_DIRECTORY/tools/legacy_validator_hold.py receipt \
  --uid UID \
  --hotkey HOTKEY \
  --umi-revision UMI_REVISION \
  --expected-source-sha256 1f88ff10a1385439efc3e3c0a8d8c87a543e03e04865f910a83dba05847da2da \
  --repository-root /ABSOLUTE/UMI_DIRECTORY \
  --state-dir /ABSOLUTE/HOLD_STATE \
  > umi-sn78-hold-receipt.json
```

The command fails if the hold lock is not active, if the marker does not match the
arguments, or if the source hash differs. The public receipt contains only its
schema, UID, public hotkey, UMI revision, source and marker hashes, timestamps,
status, and narrow observation scope. Post only `umi-sn78-hold-receipt.json`.
It does not name or verify the retired supervisor target. A same-user process can
reproduce a local lock and marker, so the receipt is coordination evidence only.

## 4. Wait for the chain gate

UMI independently monitors every affected hotkey at coherent finalized blocks.
Operator receipts support coordination but cannot clear the gate. A clean cutover
requires both of these conditions in one finalized SN78 MechId 0 observation:

```text
total_pending_commit_count = 0
active legacy MechId 0 row hotkeys = []
```

Any new `TimelockedWeightsCommitted` event from a legacy writer resets the wait.
Do not submit a corrective row, deregister the hotkey, or start the UMI bootstrap
writer. UMI will issue a separate start instruction after it publishes the clean
cutover checkpoint.

## Recovery

If the hold does not start, inspect only its local unit status and private journal.
Do not paste that output into a public issue because it may include local paths or
supervisor metadata. Fix the named hold target, rerun the local checks, and create
a new receipt.

Stopping the hold does not restore the legacy writer. Restoration requires an
explicit later UMI operator instruction and a separately pinned release.
