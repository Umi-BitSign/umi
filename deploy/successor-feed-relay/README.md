# Successor feed relay

This scheduled Worker copies the wallet-free successor feed to the R2 address
already installed in validator configurations. It needs an R2 binding and a
fixed HTTPS source origin. It has no wallet, signing key, public upload route,
HTTP trigger or access to private holdout files. It does not activate validators.

The checked-in configuration is disabled and has no cron trigger. The channel,
platform and initial v3 cursor shown are the amd64 bridge's sequence 19 anchor.
Verify these against the retained production authority before enabling it.
Use a separate Worker configuration for a different channel/platform.

## Copy order and recovery

Each tick copies at most one new directive. It reads the existing `after/`
route and the directive's immutable `page.json`. The package manifest and
authorization supply exact SHA-256 and byte sizes. All eight package payloads
are streamed into conditional R2 creates with exact lengths and SHA-256 checks.
Existing objects must already match; they are never overwritten.

After the dependencies and immutable directive page are present, the relay
installs an empty page at the new tail cursor. It then links the previous cursor
to that directive with `more: true`, and saves its checkpoint last. These cursor
envelopes use the existing v4 page schema and RFC8785 canonical JSON. The signed
directive objects and immutable files retain their original canonical bytes.
An initial-history reader follows the links until the explicit empty tail;
it must not stop at an old directive merely because its one-hop page ended.

Each object's destination is constructed from the configured channel prefix,
parsed hashes and fixed filenames. The source cannot select another bucket key,
origin or release archive URL. Redirects and compressed responses are rejected.
Controls are bounded to 1 MiB; manifests, authorizations and package payloads
retain the protocol's separate limits. Release archives and host bundles are
still uploaded through the release process, not this relay.

The checkpoint binds the source origin, destination prefix and initial cursor.
Its conditional ETag update prevents an older overlapping tick from moving it
backwards. Cursor pages also use monotonic heads and conditional writes. A failed
copy leaves the previous published links available; retry checks already copied
objects and continues. There is no automatic deletion or conflict override.

The relay checks directive content hashes, predecessor linkage, canonical JSON
and referenced object hashes. It relies on the configured HTTPS source feed to
verify authority signatures. Validators still perform their own signature,
policy, release, replay and activation checks. R2 delivery is not authority to
change a weight row, extend a signed deadline or replace an expired package.

## Deployment

1. Run `npm ci` and `npm run check`.
2. Route the configured source origin's channel `/successor/` path to the
   loopback wallet-free feed. Do not expose its config, wallets or journals.
3. Verify the source's retained predecessor chain and all required release
   artifacts. Qualify initial-history fetch and restart against the actual
   destination before any validator handoff.
4. Set `ENABLED` to `true` and `triggers.crons` to `["* * * * *"]` in the reviewed
   deployment configuration, then deploy with Wrangler. No API token is copied
   to the coordinator; the Worker uses its R2 binding.
5. Observe `successor_feed_relay` status logs and destination checkpoint age.
   A caught-up tick checks the upstream tail again on the next invocation.

The catch-up rate is one directive per scheduled tick. Size the schedule and
authorization headroom for that delay, artifact transfers and validator replay.
Do not activate from an old checkpoint or claim that this relay supplies fresh
evaluation data. Missing/expired rounds remain the publisher's responsibility.

To pause copying, disable the Worker or remove its trigger. Retain the checkpoint
and immutable objects. Disabling copying does not stop validators; their signed
validity rules continue to apply.

## Tests

`npm run check` uses local Workers/R2 bindings. It covers interrupted copies,
checkpoint-write failure, concurrent and delayed ticks, bounded/truncated bodies,
checksum mismatches, redirects, changed source configuration, ordered publication,
and hold/replay modes. Synthetic signatures in these transport tests are not
production signatures. The Python feed regression separately verifies initial
history catch-up with real fixture signatures across linked one-hop pages and
an empty tail. Neither test suite submits chain transactions.
