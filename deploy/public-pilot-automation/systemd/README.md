# Public-pilot automation services

> [!CAUTION]
> The public endpoint campaign closed on 2026-09-11. Do not install, enable, or
> restart the controller for this campaign, announce enrollment, add the
> `public-miner-pilot` label, or accept another readiness proof. The install and
> update sections remain below as a historical deployment record. Follow the
> retirement procedure before taking down the automation host.
>
> Keep the observer pilot-feed configuration, published bundles, R2 objects,
> controller state, spool receipts, and retained archives. The frozen bootstrap
> feed still verifies its signed eligibility row against completed public-pilot
> evidence.

These units keep the GitHub and wallet trust boundaries separate:

- GitHub Actions validates issue state, emits authenticated authorization markers,
  and posts sanitized result comments.
- `umi-public-pilot-controller` has the coordinator hotkey and read-only GitHub
  access. The default unit uses GitHub's unauthenticated public API at a reduced
  poll rate. An optional repository-scoped read token can raise that limit. The
  controller never receives a GitHub write token.
- `umi-public-pilot-spool` imports only canonical evidence signed by the pinned
  coordinator. It runs as the observer user and is the only writer to the pilot
  feed.
- The R2 upload Worker receives only the upload HMAC. It has no wallet or GitHub
  credential.

The coordinator and spool use different users. Their only shared writable path is
the setgid incoming spool. A durable attempt-started record is written before any
miner contact; recovery publishes the preserved non-feed journal and never repeats
that request.

Keep `incoming` and the observer-owned `consumer` subtree beneath the single
`/var/spool/umi-public-pilot` writable mount used by the spool service. Separate
systemd writable-path mounts can make an otherwise same-disk rename non-atomic, so
the spool fails closed if its claim or retention move crosses a mount boundary.

The campaign treats the coordinator hotkey and public R2 origin as immutable.
Drain every pending authorization and start a new declared campaign before either
value changes; historical results are deliberately checked against those bindings.

## Campaign retirement and evidence drain

Retire the GitHub boundary first. Disable
`.github/workflows/public-pilot-bot.yml`, cancel any queued or running instance,
post one closure notice, and close every issue carrying `public-miner-pilot`.
Closing the issues makes outstanding authorization markers fail the controller's
pre-contact issue-state verification. Confirm that no open enrollment remains:

```sh
gh workflow disable public-pilot-bot.yml --repo Umi-BitSign/umi
gh run list --repo Umi-BitSign/umi --workflow public-pilot-bot.yml \
  --status in_progress
gh run list --repo Umi-BitSign/umi --workflow public-pilot-bot.yml \
  --status queued
gh issue list --repo Umi-BitSign/umi --label public-miner-pilot \
  --state open --limit 200
```

Cancel every run returned by the first two `gh run list` commands with
`gh run cancel RUN_ID --repo Umi-BitSign/umi`. Close the issues returned by the
last command, then repeat it and require an empty result before continuing.

Wait for any request that already crossed the durable contact boundary. A record
in `attempt_started` may already have contacted a miner and must reach a terminal
or preserved incomplete result. Treat `processing` as busy until its state and
local journal have been reviewed. An active `case_ready` record is pre-contact and
may be left in place as cancelled history. Read the database without modifying it:

```sh
busy_count=$(/opt/umi-public-pilot/.venv/bin/python - <<'PY'
import sqlite3

connection = sqlite3.connect(
    "file:/var/lib/umi-public-pilot-controller/automation.sqlite3?mode=ro",
    uri=True,
)
print(
    connection.execute(
        "SELECT count(*) FROM authorizations "
        "WHERE state IN ('processing', 'attempt_started')"
    ).fetchone()[0]
)
PY
)
test "$busy_count" = 0
sudo systemctl disable --now umi-public-pilot-controller.service
test "$(systemctl is-active umi-public-pilot-controller.service)" = inactive
test "$(systemctl is-enabled umi-public-pilot-controller.service)" = disabled
```

The spool is the publication boundary for completed evidence. Verify its exact
installed entry point as the service user, clear any prior start-limit failure,
and run one final pass after the controller has stopped:

```sh
test -x /opt/umi-public-pilot/.venv/bin/umi-public-pilot-spool
sudo -u umi-observer \
  /opt/umi-public-pilot/.venv/bin/umi-public-pilot-spool --help >/dev/null
sudo systemd-analyze verify \
  /etc/systemd/system/umi-public-pilot-spool.service \
  /etc/systemd/system/umi-public-pilot-spool.path
sudo systemctl reset-failed \
  umi-public-pilot-spool.service umi-public-pilot-spool.path
sudo systemctl start umi-public-pilot-spool.service
test "$(systemctl show umi-public-pilot-spool.service -p Result --value)" = success
test -z "$(sudo find \
  /var/spool/umi-public-pilot/incoming \
  /var/spool/umi-public-pilot/consumer/processing \
  -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
sudo systemctl disable --now \
  umi-public-pilot-spool.path umi-public-pilot-spool.service
```

Leave the observer and its public-pilot drop-in running. Verify both retained
evidence namespaces after the final spool pass:

```sh
systemctl is-active --quiet umi-observer.service
curl --fail --silent --show-error --max-time 30 \
  'https://api.umi.vision/api/v1/pilots?limit=256' >/dev/null
curl --fail --silent --show-error --max-time 30 \
  https://api.umi.vision/api/v1/bootstrap-service >/dev/null
```

Do not delete `/var/lib/umi-public-pilot-controller`,
`/var/spool/umi-public-pilot`, `/var/lib/umi-observer/pilots`,
`/var/lib/umi-observer/pilot-feed`, or any published object. Preserve the
campaign configuration according to the evidence-retention policy. Revoke its
runtime credentials only after the final result and archive checks pass.

## Install

Use a root-owned checkout at the exact automation revision configured in GitHub as
`PUBLIC_PILOT_AUTOMATION_REVISION`. Keep the campaign revision separately pinned
as `PUBLIC_PILOT_UMI_REVISION` in GitHub and as `umi_revision` in
`public-pilot-automation.json`. The campaign revision is carried by signed
authorizations and public results. An automation revision may advance within an
active campaign only for a reviewed, campaign-compatible fix to the GitHub or
controller boundary. A change to a campaign object, request, response, timelock,
score, or public evidence format requires a new campaign revision instead. Do not
run a moving branch from systemd.
Four GiB of RAM is the recommended production size. The serialized pilot campaign
can run on the current 1 GiB Linode with swap enabled, provided no model, test, or
build workload runs on the host. Stop the controller and resize before continuing
if available memory remains below 150 MiB, swap use exceeds 256 MiB, full memory
PSI `avg10` exceeds `0.10`, an OOM event occurs, or either observer endpoint fails.

Connect with agent forwarding enabled because the deployment checkout uses the
GitHub SSH remote:

```sh
ssh -A sam@172.239.57.201
ssh -T git@github.com
```

Set both exact 40-character revisions, then clone the automation revision as
`sam`. They are normally equal for a new campaign. Do not run the clone through
`sudo`: root does not have the forwarded agent's GitHub host-key state.

```sh
automation_revision=REPLACE_WITH_40_CHARACTER_AUTOMATION_REVISION
campaign_umi_revision=REPLACE_WITH_40_CHARACTER_CAMPAIGN_REVISION
release_checkout="/home/sam/umi-public-pilot-source-$automation_revision"
git clone --no-checkout git@github.com:Umi-BitSign/umi.git "$release_checkout"
git -C "$release_checkout" checkout --detach "$automation_revision"
test "$(git -C "$release_checkout" rev-parse HEAD)" = "$automation_revision"
sudo install -d -o root -g root -m 0755 /opt/umi-public-pilot
sudo mv "$release_checkout" /opt/umi-public-pilot/source
sudo chown -R root:root /opt/umi-public-pilot/source
```

The service environment is locked with uv 0.12.9, the same version used by CI.
Ubuntu does not install uv, pip, or `python3-venv` on this host by default. Bootstrap
the pinned uv release in a dedicated virtual environment and copy only its executable
into the root-owned service path:

```sh
sudo apt-get update
sudo apt-get install --yes jq python3-venv
python3 -m venv /home/sam/umi-uv-bootstrap
/home/sam/umi-uv-bootstrap/bin/pip install 'uv==0.12.9'
test "$(/home/sam/umi-uv-bootstrap/bin/uv --version)" = 'uv 0.12.9'
sudo install -o root -g root -m 0755 \
  /home/sam/umi-uv-bootstrap/bin/uv /usr/local/bin/uv
observer_python=/opt/umi-observer/.venv/bin/python
test -x "$observer_python"
observer_base_python="$($observer_python -c \
  'import sys; print(sys._base_executable)')"
test -x "$observer_base_python"
sudo env UV_PROJECT_ENVIRONMENT=/opt/umi-public-pilot/.venv \
  /usr/local/bin/uv sync --project /opt/umi-public-pilot/source \
  --python "$observer_base_python" --locked --no-dev
observer_environment="$($observer_python -c \
  'import json; from umi.scoring import scoring_environment; print(json.dumps(scoring_environment(), sort_keys=True, separators=(",", ":")))')"
automation_environment="$(/opt/umi-public-pilot/.venv/bin/python -c \
  'import json; from umi.scoring import scoring_environment; print(json.dumps(scoring_environment(), sort_keys=True, separators=(",", ":")))')"
test "$observer_environment" = "$automation_environment"
rm -rf /home/sam/umi-uv-bootstrap
```

The observer replays every imported bundle and requires the bundle's complete
scoring-environment fingerprint. Reusing its exact Python interpreter prevents a
patch-version mismatch from passing the spool and then taking the public observer
offline.

Install the group and directories before starting either unit:

```sh
sudo install -m 0644 /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-public-pilot.sysusers \
  /usr/lib/sysusers.d/umi-public-pilot.conf
sudo systemd-sysusers /usr/lib/sysusers.d/umi-public-pilot.conf
sudo install -m 0644 /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-public-pilot.tmpfiles \
  /usr/lib/tmpfiles.d/umi-public-pilot.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/umi-public-pilot.conf
```

Materialize `/etc/umi/public-pilot-automation.json` from the example. Replace the
revision and Worker origin if the deployed Worker uses another origin. `jq -j`
omits the usual trailing newline; the coordinator refuses noncanonical
configuration. The configured wallet must resolve to the published coordinator
hotkey.

```sh
campaign_umi_revision=REPLACE_WITH_40_CHARACTER_CAMPAIGN_REVISION
pilot_config_candidate=$(mktemp)
jq -cSj --arg revision "$campaign_umi_revision" \
  '.umi_revision = $revision' \
  /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/public-pilot-automation.json.example \
  >"$pilot_config_candidate"
sudo install -d -o root -g root -m 0755 /etc/umi
sudo install -o root -g root -m 0644 "$pilot_config_candidate" \
  /etc/umi/public-pilot-automation.json
```

The observer feed is mutable append-only state, so keep it under the private
observer state directory rather than `/etc`. Before starting the spool, copy the
existing feed byte-for-byte to
`/var/lib/umi-observer/pilot-feed/observer-pilot-feed.json`, make it owned by
`umi-observer:umi-observer` with mode `0600`, and update
`UMI_OBSERVER_PILOT_FEED_CONFIG` in `/etc/umi/umi-observer.env` to that path. The
spool refuses a config whose parent is not private and owned by its service user.
Install `umi-observer-public-pilot.conf` as an observer service drop-in. The
observer can read the feed and published bundles, while only the spool service has
writable mounts for those paths.

```sh
sudo install -d -o umi-observer -g umi-observer -m 0700 \
  /var/lib/umi-observer/pilot-feed
sudo install -o umi-observer -g umi-observer -m 0600 \
  /etc/umi/observer-pilot-feed.json \
  /var/lib/umi-observer/pilot-feed/observer-pilot-feed.json
sudo sed -i \
  's#^UMI_OBSERVER_PILOT_FEED_CONFIG=.*#UMI_OBSERVER_PILOT_FEED_CONFIG=/var/lib/umi-observer/pilot-feed/observer-pilot-feed.json#' \
  /etc/umi/umi-observer.env
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/umi-observer.service.d
sudo install -o root -g root -m 0644 \
  /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-observer-public-pilot.conf \
  /etc/systemd/system/umi-observer.service.d/20-public-pilot-read-only.conf
```

Create `/etc/umi/umi-public-pilot-spool.env` from the example. Obtain the numeric
group ID with `getent group umi-pilot`; do not guess it. The producer UID is the
numeric UID of `sam`.

```sh
pilot_producer_uid=$(id -u sam)
pilot_producer_gid=$(getent group umi-pilot | cut -d: -f3)
test -n "$pilot_producer_gid"
pilot_spool_env=$(mktemp)
sed \
  -e "s/^UMI_PILOT_PRODUCER_UID=.*/UMI_PILOT_PRODUCER_UID=$pilot_producer_uid/" \
  -e "s/^UMI_PILOT_PRODUCER_GID=.*/UMI_PILOT_PRODUCER_GID=$pilot_producer_gid/" \
  /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-public-pilot-spool.env.example \
  >"$pilot_spool_env"
sudo install -o root -g root -m 0600 "$pilot_spool_env" \
  /etc/umi/umi-public-pilot-spool.env
```

Create three distinct 32-byte secrets under
`/etc/umi/public-pilot-secrets`, encoded as 64 lowercase hexadecimal characters
with mode `0600` and owned by root:

- `github-auth-hmac.hex`, shared only with the matching GitHub Actions secret;
- `result-hmac.hex`, shared only with the matching GitHub Actions secret; and
- `upload-hmac.hex`, shared only with the R2 upload Worker secret.

The GitHub copies of the HMAC keys use standard base64, not hexadecimal. Never
print the keys in a terminal transcript or place them in an environment file.

The checked-in unit deliberately has no GitHub API token. Keep `poll_seconds` at
300 or greater in this mode; the controller refuses a faster unauthenticated
configuration. It honors GitHub's reset and retry headers and backs off
exponentially when GitHub reports a secondary limit.

If a suitably least-privilege credential becomes available, install
`github-api-token` in that directory with mode `0600` and root ownership, then
install the supplied `umi-public-pilot-controller-token.conf.example` as a systemd
drop-in. Use a fine-grained token restricted to `Umi-BitSign/umi` with repository
metadata and Issues read access only. It must have no write permission. The file
contains only the token, optionally followed by one newline; do not put its value in
the JSON config, an environment variable, a command line, or a terminal transcript.
Do not copy a broad token from the local `gh` credential store. Authenticated mode
may use `poll_seconds: 60`. Rotate the token before expiry and restart the
controller after replacing its source credential file.

```sh
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/umi-public-pilot-controller.service.d
sudo install -o root -g root -m 0644 \
  /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-public-pilot-controller-token.conf.example \
  /etc/systemd/system/umi-public-pilot-controller.service.d/github-token.conf
```

Install and verify the units:

```sh
sudo install -m 0644 /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-public-pilot-controller.service /etc/systemd/system/
sudo install -m 0644 /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-public-pilot-spool.service /etc/systemd/system/
sudo install -m 0644 /opt/umi-public-pilot/source/deploy/public-pilot-automation/systemd/umi-public-pilot-spool.path /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/umi-public-pilot-controller.service \
  /etc/systemd/system/umi-public-pilot-spool.service \
  /etc/systemd/system/umi-public-pilot-spool.path \
  /etc/systemd/system/umi-observer.service
sudo systemctl daemon-reload
sudo systemctl enable --now umi-public-pilot-spool.service umi-public-pilot-spool.path
sudo systemctl enable --now umi-public-pilot-controller.service
observer_pid="$(systemctl show umi-observer.service -p MainPID --value)"
test "$observer_pid" -gt 1
sudo grep -Fzxq -- '--pilot-feed-config' "/proc/$observer_pid/cmdline"
sudo grep -Fzxq -- \
  '/var/lib/umi-observer/pilot-feed/observer-pilot-feed.json' \
  "/proc/$observer_pid/cmdline"
systemctl show umi-observer.service -p ReadOnlyPaths --value | \
  grep -Fq '/var/lib/umi-observer/pilot-feed /var/lib/umi-observer/pilots'
curl --fail --silent --show-error --max-time 30 \
  https://api.umi.vision/api/v1/network >/dev/null
curl --fail --silent --show-error --max-time 30 \
  'https://api.umi.vision/api/v1/pilots?limit=256' >/dev/null
```

Start these services before adding the pilot label to any existing issue. Confirm
from the controller log and state database that it is idle and has not prepared a
case or contacted a miner. Then check the R2 Worker,
`https://api.umi.vision/api/v1/network`, and the immutable public result origin
before announcing enrollment or adding the pilot label to existing issues.

Stopping the controller stops new case preparation and request issuance. Stopping
the spool does not lose an archive: files remain in `incoming` or `processing` and
are recovered before the next item. Never delete a state database, attempt journal,
processed archive, receipt, or quarantine item during the campaign.

## Automation-only update

A boundary or controller fix may use a later automation commit without changing
the active campaign revision. Publish and test the commit first. Set
`PUBLIC_PILOT_AUTOMATION_REVISION` to that exact commit for the GitHub workflow,
but leave `PUBLIC_PILOT_UMI_REVISION` and the canonical JSON config's
`umi_revision` unchanged. Record both revisions in the incident or deployment
note.

The service environment imports the editable package from
`/opt/umi-public-pilot/source`. Replace that checkout as a unit; do not copy
individual files into it. The dependency lock must remain unchanged for this
short update path. If it changed, use a separately reviewed full deployment.
Preserve the old source checkout as the rollback target.

Before the swap, stop if the durable database contains `processing` or
`attempt_started` work. An active `case_ready` record is safe because no request is
in flight. Stop the controller, repeat that check, swap the checkout, verify the
unchanged campaign config, and restart:

```sh
set -eu
automation_revision=REPLACE_WITH_40_CHARACTER_AUTOMATION_REVISION
release_checkout="/home/sam/umi-public-pilot-source-$automation_revision"
git clone --no-checkout git@github.com:Umi-BitSign/umi.git "$release_checkout"
git -C "$release_checkout" checkout --detach "$automation_revision"
test "$(git -C "$release_checkout" rev-parse HEAD)" = "$automation_revision"
test -z "$(git -C "$release_checkout" status --porcelain)"
cmp /opt/umi-public-pilot/source/uv.lock "$release_checkout/uv.lock"

busy_count=$(/opt/umi-public-pilot/.venv/bin/python - <<'PY'
import sqlite3

connection = sqlite3.connect(
    "file:/var/lib/umi-public-pilot-controller/automation.sqlite3?mode=ro",
    uri=True,
)
print(
    connection.execute(
        "SELECT count(*) FROM authorizations "
        "WHERE state IN ('processing', 'attempt_started')"
    ).fetchone()[0]
)
PY
)
test "$busy_count" = 0

campaign_config_sha256=$(sudo sha256sum /etc/umi/public-pilot-automation.json)
campaign_umi_revision=$(sudo jq -r .umi_revision /etc/umi/public-pilot-automation.json)
old_automation_revision=$(sudo git -C /opt/umi-public-pilot/source rev-parse HEAD)
source_backup="/opt/umi-public-pilot/source-$old_automation_revision"
test ! -e "$source_backup"

sudo systemctl stop umi-public-pilot-controller.service
busy_count=$(/opt/umi-public-pilot/.venv/bin/python - <<'PY'
import sqlite3

connection = sqlite3.connect(
    "file:/var/lib/umi-public-pilot-controller/automation.sqlite3?mode=ro",
    uri=True,
)
print(
    connection.execute(
        "SELECT count(*) FROM authorizations "
        "WHERE state IN ('processing', 'attempt_started')"
    ).fetchone()[0]
)
PY
)
test "$busy_count" = 0
sudo mv /opt/umi-public-pilot/source "$source_backup"
sudo mv "$release_checkout" /opt/umi-public-pilot/source
sudo chown -R root:root /opt/umi-public-pilot/source
test "$(sudo git -C /opt/umi-public-pilot/source rev-parse HEAD)" = "$automation_revision"
/opt/umi-public-pilot/.venv/bin/python -B -c \
  'import umi.public_pilot_authorization, umi.public_pilot_controller'
test "$(sudo jq -r .umi_revision /etc/umi/public-pilot-automation.json)" = \
  "$campaign_umi_revision"
test "$(sudo sha256sum /etc/umi/public-pilot-automation.json)" = \
  "$campaign_config_sha256"
sudo systemctl start umi-public-pilot-controller.service
systemctl is-active --quiet umi-public-pilot-controller.service
```

If either post-swap check or service startup fails, stop the service, move the new
checkout aside, restore `source_backup` to `/opt/umi-public-pilot/source`, and
start the service from the preserved checkout. Do not modify or replace the state
database during either path.
