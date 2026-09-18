# Public intake monitor and audit archive

`umi-public-intake-monitor` reads only public HTTPS routes. It has no wallet,
RPC, validator state, coordinator state, or chain-write configuration. Run it
on a host that is independent of the intake coordinator and validators.

Each successful poll fences the admission head, downloads the status and
readiness documents, every submission-list page, every full signed submission
and receipt, and every observer participant page. It verifies the policy and
deployment identity, replays admission signatures, rebuilds the external
checkpoint, checks append-only state, and inspects validator UIDs 0 and 54. A
successful capture is committed as one fsynced archive snapshot.

The validator last-update thresholds are fixed at 200 blocks for warning, 240
for investigation, 300 for critical, and 360 for stale. Exit status is `0` for
healthy, `1` for warning or investigation, `2` for critical or stale, and `3`
when the result is unknown or validation fails.

## Archive root contract

The archive root must:

- be an absolute, dedicated, pre-existing directory;
- be owned by the monitor service account with mode `0700`;
- reside on one local filesystem, because snapshot commits use atomic rename
  and full-record deduplication uses hard links;
- have enough capacity for immutable snapshot metadata and one
  content-addressed copy of each distinct full record.

The root contains `objects/`, `snapshots/`, `rejected/`, `.staging/`,
`monitor.lock`, and `latest.json`. Every accepted snapshot includes the exact
monitor config, pre-crawl and post-crawl status/readiness documents, all list
pages, all participant pages, all full records, monitor state, and a digest
manifest. Files are mode `0400` and committed snapshots are mode `0500`. Each
manifest binds its predecessor snapshot and manifest digest. `verify` walks
that chain from the reviewed bootstrap and replays every transition, including
monotonic ledger checks.

A complete crawl that fails semantic validation is committed atomically under
`rejected/` with its failure reason, prior accepted state, config, public route
documents, and every full record. It does not advance `latest.json`. This keeps
incident evidence without treating an invalid view as accepted monitor state.

Back up the whole root, not only `latest.json`. Use a filesystem snapshot or a
backup tool that copies `objects/`, `snapshots/`, `rejected/`, and
`latest.json` as one generation and preserves hard links when possible.
Restoring only the newest snapshot is not sufficient: predecessor snapshots
are required to authenticate the manifest chain and replay every transition.

Authenticate and reproduce the recorded reason for rejected evidence with:

```sh
sudo -u umi-intake-audit \
  /opt/umi-public-intake-monitor/venv/bin/umi-public-intake-monitor \
  verify-rejected \
  --archive-root /var/lib/umi-public-intake-monitor \
  --rejected-capture REJECTED_DIRECTORY_NAME
```

Do not mount wallets, validator journals, coordinator state, or private model
data on this host. The config and archive contain public data only.

## First installation

The checked-in `config.json.example` is an observed example, not a reusable
bootstrap credential. Intake is live, so its exact count and head become stale
when another admission lands. A stale bootstrap fails closed by design.

Install an audited repository revision and create the service account before
enabling a timer. The following paths match the supplied units:

```sh
sudo useradd --system --home-dir /var/lib/umi-public-intake-monitor \
  --shell /usr/sbin/nologin umi-intake-audit
sudo install -d -o root -g root -m 0755 /opt/umi-public-intake-monitor
sudo python3 -m venv /opt/umi-public-intake-monitor/venv
sudo /opt/umi-public-intake-monitor/venv/bin/pip install /path/to/reviewed/umi
sudo install -d -o root -g umi-intake-audit -m 0750 /etc/umi-public-intake-monitor
sudo install -d -o umi-intake-audit -g umi-intake-audit -m 0700 \
  /var/lib/umi-public-intake-monitor
sudo install -o root -g umi-intake-audit -m 0640 \
  deploy/public-intake-monitor/config.json.example \
  /etc/umi-public-intake-monitor/config.json
```

Before the first poll, obtain a fenced candidate:

```sh
sudo -u umi-intake-audit \
  /opt/umi-public-intake-monitor/venv/bin/umi-public-intake-monitor \
  observe-identity --config /etc/umi-public-intake-monitor/config.json
```

Review the policy document, raw deployment document, retained baseline
promotion digest, accepted count and head, required-set IDs and digest, and
checked block in the fenced output. Update both the matching
`expected_identities` entry and `reviewed_bootstrap` in one root-owned config
edit. `observe-identity` validates and includes the complete policy and
deployment bodies; it deliberately emits a non-copyable
`acceptance_not_before_block` placeholder. For the first identity, replace it
with the actual block at which that deployment began admitting records. The
current first-round deployment opened admission at block `9,085,463`. Set
`not_before_checked_block` to the exact checked block you reviewed; it is an
observation fence, not a record-admission floor. The count floor and bootstrap
count should equal the reviewed live count. Run the first full crawl
immediately:

```sh
sudo -u umi-intake-audit \
  /opt/umi-public-intake-monitor/venv/bin/umi-public-intake-monitor poll \
  --config /etc/umi-public-intake-monitor/config.json \
  --archive-root /var/lib/umi-public-intake-monitor
sudo -u umi-intake-audit \
  /opt/umi-public-intake-monitor/venv/bin/umi-public-intake-monitor verify \
  --config /etc/umi-public-intake-monitor/config.json \
  --archive-root /var/lib/umi-public-intake-monitor --snapshot latest
```

If intake advances between observation and the first poll, the exact bootstrap
check rejects it. Observe again, review the changed head, and update the two
bootstrap fields. Never weaken the check to a minimum-only first poll.

## Policy or deployment rollover

Identity history is append-only. For a v2 policy or any deployment change:

1. Keep every existing identity entry byte-for-byte unchanged.
2. Before rollout, obtain and independently review the prospective signed
   policy, raw deployment document, retained baseline promotion digest, writer
   generation, retained set, and exact activation block through the published
   change procedure.
3. Append exactly one identity. Set `not_before_checked_block` to the reviewed
   rollout checkpoint. Set `acceptance_not_before_block` to the exact block at
   which the successor deployment becomes eligible to admit records, even if
   its published round schedule has an earlier opening. Both floors must be
   greater than the prior entry, the count floor cannot decrease, and the
   required-set count and digest must match the reviewed retained set.
4. Install the updated config before the public identity changes.
5. When the route changes, run `observe-identity` and compare every reported
   digest and checkpoint with the appended entry before the first new poll.
6. Keep the existing archive root. The retained policy and deployment bodies
   let the monitor replay records first observed on either side of the change.

The monitor rejects an unconfigured identity, a skipped entry, a predecessor
mismatch, history edits, and rollback to an earlier identity. Do not start with
an empty archive after rollover. Restore the complete archive root first.
After the first accepted snapshot, every non-identity config setting is also
frozen. Changing origins, alert thresholds, HTTP limits, retry settings, or
other bounds requires a separately reviewed archive migration; it cannot be
smuggled into an identity rollover.

## Linux systemd

Install the supplied service and timer after the one-shot poll succeeds:

```sh
sudo install -o root -g root -m 0644 \
  deploy/public-intake-monitor/systemd/umi-public-intake-monitor.service \
  /etc/systemd/system/umi-public-intake-monitor.service
sudo install -o root -g root -m 0644 \
  deploy/public-intake-monitor/systemd/umi-public-intake-monitor.timer \
  /etc/systemd/system/umi-public-intake-monitor.timer
sudo systemctl daemon-reload
sudo systemctl enable --now umi-public-intake-monitor.timer
sudo systemctl start umi-public-intake-monitor.service
sudo systemctl status umi-public-intake-monitor.service
```

An alert exit makes the oneshot unit fail so the host's service monitoring can
page on it. The timer continues to invoke later polls.

## macOS launchd

The plist uses fixed paths and the dedicated `_umi_intake` account. Create that
non-admin local account using the site's managed-account procedure, then:

```sh
sudo install -d -o root -g wheel -m 0755 /opt/umi-public-intake-monitor
sudo python3 -m venv /opt/umi-public-intake-monitor/venv
sudo /opt/umi-public-intake-monitor/venv/bin/pip install /path/to/reviewed/umi
sudo install -d -o root -g wheel -m 0755 /usr/local/etc/umi-public-intake-monitor
sudo install -d -o _umi_intake -g staff -m 0700 /var/db/umi-public-intake-monitor
sudo install -d -o _umi_intake -g staff -m 0700 /var/log/umi-public-intake-monitor
sudo install -o root -g staff -m 0640 \
  deploy/public-intake-monitor/config.json.example \
  /usr/local/etc/umi-public-intake-monitor/config.json
```

Edit and review the root-owned config, then run the manual bootstrap before
installing the daemon:

```sh
sudo -u _umi_intake \
  /opt/umi-public-intake-monitor/venv/bin/umi-public-intake-monitor \
  observe-identity \
  --config /usr/local/etc/umi-public-intake-monitor/config.json
sudo -u _umi_intake \
  /opt/umi-public-intake-monitor/venv/bin/umi-public-intake-monitor poll \
  --config /usr/local/etc/umi-public-intake-monitor/config.json \
  --archive-root /var/db/umi-public-intake-monitor
sudo -u _umi_intake \
  /opt/umi-public-intake-monitor/venv/bin/umi-public-intake-monitor verify \
  --config /usr/local/etc/umi-public-intake-monitor/config.json \
  --archive-root /var/db/umi-public-intake-monitor --snapshot latest
```

Only after those commands succeed, install and start the daemon:

```sh
sudo install -o root -g wheel -m 0644 \
  deploy/public-intake-monitor/launchd/vision.umi.public-intake-monitor.plist \
  /Library/LaunchDaemons/vision.umi.public-intake-monitor.plist
sudo plutil -lint /Library/LaunchDaemons/vision.umi.public-intake-monitor.plist
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/vision.umi.public-intake-monitor.plist
sudo launchctl kickstart -k system/vision.umi.public-intake-monitor
sudo launchctl print system/vision.umi.public-intake-monitor
```
