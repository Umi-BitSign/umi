# Public-pilot automation services

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

The campaign treats the coordinator hotkey and public R2 origin as immutable.
Drain every pending authorization and start a new declared campaign before either
value changes; historical results are deliberately checked against those bindings.

## Install

Use a root-owned checkout at the exact Git revision configured in GitHub and in
`public-pilot-automation.json`. Do not run a moving branch from systemd.
The coordinator host needs at least 4 GiB of RAM. Check `free -h` before installing;
the current 1 GiB Linode size is too small to run the observer, coordinator, and
bounded spool consumer together.

Connect with agent forwarding enabled because the deployment checkout uses the
GitHub SSH remote:

```sh
ssh -A sam@172.239.57.201
ssh -T git@github.com
```

Set the exact 40-character release revision, then clone as `sam`. Do not run the
clone through `sudo`: root does not have the forwarded agent's GitHub host-key
state.

```sh
umi_revision=REPLACE_WITH_40_CHARACTER_RELEASE_REVISION
release_checkout="/home/sam/umi-public-pilot-source-$umi_revision"
git clone --no-checkout git@github.com:Umi-BitSign/umi.git "$release_checkout"
git -C "$release_checkout" checkout --detach "$umi_revision"
test "$(git -C "$release_checkout" rev-parse HEAD)" = "$umi_revision"
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
sudo env UV_PROJECT_ENVIRONMENT=/opt/umi-public-pilot/.venv \
  /usr/local/bin/uv sync --project /opt/umi-public-pilot/source --locked --no-dev
rm -rf /home/sam/umi-uv-bootstrap
```

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
umi_revision=REPLACE_WITH_40_CHARACTER_RELEASE_REVISION
pilot_config_candidate=$(mktemp)
jq -cSj --arg revision "$umi_revision" \
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
