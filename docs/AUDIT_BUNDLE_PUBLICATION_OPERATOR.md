# Public validator audit bundles

`umi-validator-audit-publish` publishes terminal inactive-validator bundles from
the live validator's private state directory to a static HTTPS site. Run one
publisher for each validator. The command cannot load a wallet, sign data, call a
chain RPC, or submit an extrinsic.

The worker accepts the two terminal namespaces written by `umi-validator-live`:

- `calibration-bundles/<window_id>` for `calibration_no_weight`; and
- `incident-bundles/<window_id>` for `skipped`, `void`, or `failed` windows.

It ignores `.locks`, `.staging`, and every other non-window child. Raw video is not
part of either bundle and is never copied. A 64-character window directory does
not become a publication candidate until its `manifest.json` exists. The bundle
writers install that manifest last.

## Publication order

For each terminal directory, the worker:

1. copies `manifest.json` and the exact declared object set into a private
   same-filesystem staging directory;
2. runs the production seven-stage bundle replay verifier against that snapshot,
   including the validator signature, inactive policy, finality evidence, storage
   proofs, raw no-weight scan, and reached stage receipts;
3. checks the snapshot against the validator account, policy hash, source
   namespace, window ID, and terminal classification;
4. renames the complete tree into the static document root and makes its files
   read-only;
5. fetches every manifest and object through the configured public HTTPS origin,
   without redirects or content encoding, and reproduces its byte length and
   SHA-256;
6. appends one route to the validator's canonical index; and
7. fetches that exact index through HTTPS before recording completion.

A route is not added when public readback fails. A crash after the local index
replace is also recoverable: the next process accepts only the exact next entry,
checks the public tree again, and finishes the remote index check. A conflicting
tree, route, policy, validator, or classification is terminal and needs operator
investigation.

## Filesystem layout

Prepare three separate locations on the same filesystem as the service user:

```text
/srv/www/umi-audits                 mode 0755, static public document root
/var/lib/umi-audit-publisher        mode 0700, private state parent
/var/lib/umi-audit-publisher/staging mode 0700, private staging root
```

The state database and staging root must be outside both the public document root
and the validator state root. The public document root and staging root must have
the same filesystem device so a completed directory can be installed with one
rename. None of these paths may be symlinks or group- or other-writable.

The public layout for one validator is:

```text
validators/<validator_account_id32>/index.json
validators/<validator_account_id32>/windows/<window_id>/<classification>/manifest.json
validators/<validator_account_id32>/windows/<window_id>/<classification>/objects/<sha256>
```

`index.json` uses schema `umi-validator-public-bundle-index/1`. Its entries have a
contiguous append sequence and include the window index, terminal classification,
reason codes, audit-release block, manifest digest, exact bundle byte count, tree
digest, and relative route. Dashboard consumers should read this index and then
verify the validator-signed bundle. The index is a discovery aid, not a replacement
for bundle replay.

Do not edit or delete published trees or the index in place. Back up the private
SQLite database with the public tree. The database contains a hash-chained event
record for discovery, local install, remote verification, index install,
completion, and failure. Losing either half intentionally blocks automatic adoption
of an existing index.

## Canonical configuration

Start from
[the schema-valid shape reference](examples/audit-publication-config.json). Replace
every path, origin, and hotkey. The authority hotkey must come from a channel the
operator already trusts; a value read from the release being verified is not a
trust root.

The referenced `validator_config_path` must be the exact mode-`0600` file produced
by `umi-shadow-release-materialize-operator`. At startup, the publisher verifies
the complete signed release and reconstructs that validator config from its signed
release-relative template. Only the machine-local validator state root is allowed
to vary. It then reruns the packaged conformance suite and constructs the same
production bundle replay ports used by the validator.

Keep these fields fixed:

```json
{
  "translation_weights_active": false,
  "wallet_loading_capability": false,
  "chain_write_capability": false,
  "weight_submission_capability": false
}
```

The config must be canonical RFC 8785 JSON in a regular file that is not group- or
other-writable. The example is not a deployment config.

After editing a copy, validate its schema and write the canonical bytes without a
trailing newline:

```bash
python -c 'from pathlib import Path; from umi.audit_publication import AuditPublicationConfig; from umi.protocol import canonical_json_bytes; p=Path("/etc/umi/audit-publication.json"); p.write_bytes(canonical_json_bytes(AuditPublicationConfig.model_validate_json(p.read_bytes())))'
chmod 0600 /etc/umi/audit-publication.json
```

## Static HTTPS origin

Configure a static server or CDN origin whose URL root maps exactly to
`public_docroot`. It must:

- serve only `GET` and `HEAD` from this document root;
- return the exact stored bytes for query-bearing requests;
- honor `Accept-Encoding: identity` and avoid compression or transformation;
- return no redirect, directory-generated index, or fallback document;
- set the correct `Content-Length`; and
- prevent writes from the public-facing service account.

The verifier resolves the hostname once per readback pass, rejects the complete DNS
answer if any address is not globally routable, pins one verified address for the
connections, and preserves the original Host and TLS SNI values. It adds a digest
query parameter and no-cache request headers to avoid accepting an older CDN copy.

The static server can cache immutable window trees indefinitely. Give the mutable
validator `index.json` a revalidation policy. Do not enable automatic JSON
minification, object compression, edge rewrites, or an HTML 200 fallback.

## Check and run

The offline check authenticates the release, signed validator template, policy,
runtime binaries, and conformance report. It also checks the document root and
staging device. It performs no public HTTP request and creates no publication
state:

```text
umi-validator-audit-publish \
  --config /etc/umi/audit-publication.json \
  --check
```

Test the first terminal bundle with one scan:

```text
umi-validator-audit-publish \
  --config /etc/umi/audit-publication.json \
  --once
```

Exit status `0` means every discovered candidate either completed during this scan
or was already complete. Status `1` means at least one candidate has a durable
failure record. Status `2` means startup or state validation failed.

For normal operation, omit `--once` and supervise the process beside the live
validator:

```text
umi-validator-audit-publish \
  --config /etc/umi/audit-publication.json
```

Start it before the first window. The worker scans at `poll_seconds`, so use a value
that leaves enough time for replay and full HTTPS readback inside the one-tempo
publication deadline. Size network capacity for the policy's full 384 MiB bundle
ceiling rather than an average bundle.

The process writes one canonical JSON status line per scan and handles `SIGINT` and
`SIGTERM`. It does not print config contents, local paths, or bundle objects.

## Service supervision

Run the watcher under a dedicated service account when the source bundle
permissions permit it. If it must share the validator's operating-system account,
deny the service access to every wallet directory in its service sandbox. The
program has no wallet option or chain-write code path, but filesystem isolation is
still the preferred defense if the process is compromised.

This `systemd` template assumes the config, signed release, validator state, public
document root, and private publisher state are outside the home directory. Replace
every placeholder and verify each path before enabling it:

```ini
[Unit]
Description=UMI public validator audit-bundle publisher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=umi-validator
Group=umi-validator
UMask=0077
ExecStart=/opt/umi/.venv/bin/umi-validator-audit-publish --config /etc/umi/audit-publication.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadOnlyPaths=/etc/umi/audit-publication.json /opt/umi/releases/RELEASE /var/lib/umi-validator
ReadWritePaths=/srv/www/umi-audits /var/lib/umi-audit-publisher
InaccessiblePaths=/ABSOLUTE/WALLET/DIRECTORY

[Install]
WantedBy=multi-user.target
```

Run the signed-input check as the configured service user before starting the
unit. Then run `systemd-analyze security` against the installed unit and confirm
that the reverse proxy can read the document root but cannot write it. The
publisher needs outbound TCP only for HTTPS readback. It does not need an inbound
socket.

## Failure handling

HTTP status, timeout, DNS, cache-staleness, length, and digest failures are durable
and retryable. The next scan reuses the already verified local tree, checks the
unchanged source manifest, and repeats public readback. It never appends another
entry for the same window.

Source mutation, replay failure, an unexpected object, namespace/schema mismatch,
an immutable destination conflict, or an index/state conflict is terminal. Stop
the worker, preserve the source tree, public tree, database, and logs, and publish
an operator incident. Do not delete the database, rewrite `index.json`, or copy a
peer validator's bundle to make the check pass.

After any deployment or CDN change, run a one-shot scan against a new test bundle
before relying on the service for a scheduled calibration window.
