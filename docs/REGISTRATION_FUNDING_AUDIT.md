# Temporary registration-funding audit

This read-only worker checks Taostats transfer histories for shared-funder
candidates during the registration bridge. It does not change weights, ban UIDs,
or identify people. The active reward policy still groups passing miners by
coldkey or HTTPS endpoint IP until the new
[signed funding-cap policy](REGISTRATION_BRIDGE_FUNDING_CAP.md) is deployed.
Publishing this checker alone does not activate funding-based reward grouping.

The audit is temporary. Its watcher stops querying at finalized block
`9,075,171`. Stop it earlier if the open competition replaces the bridge. It is
not a requirement of the planned 70% endpoint / 30% model-contribution mechanism.

## API key and cost

An operator running this audit worker needs a Taostats API key. Existing UMI
weight-writing validators do not need a key for their current release. Running
one audit worker on the coordinator avoids duplicating requests across validators.

Taostats lists a free allowance of five requests per minute and 10,000 requests
per month. The client spaces requests by at least 12.5 seconds and the watcher
defaults to a persistent total budget of 1,000 requests. Check your account's
remaining quota; usage by other applications also counts. No wallet funding or
validator-fund transfer is needed for the authenticated free-tier queries tested.
See [API plans](https://taostats.io/pro/api-keys) and
[transfer documentation](https://docs.taostats.io/reference/get-transfers).

Do not paste API keys into chat, shell commands or Git. Rotate any key already
shared in chat. Use the hidden terminal prompt below, `TAOSTATS_API_KEY` from a
secret manager, or `--api-key-file` with a regular, owner-private credential file.
Only run one worker per API key. The local lock cannot coordinate separate hosts.

## Run the cached watcher

From a checkout with the project's dependencies installed:

```sh
python -m umi.registration_funding_watch \
  --state-root /ABSOLUTE/PRIVATE/PATH/funding-audit \
  --prompt-api-key
```

The parent directory must exist. The worker creates the state directory with
mode `0700`, keeps the cache and report private, and refuses unsafe existing
paths. Use a dedicated account with no wallet access. Do not run the watcher as
root or inside a weight writer. Stop it with Ctrl-C; restarting with the same
state directory retains the cache, API-call budget and rate-limit timestamp.

The initial scan queues all current registrations. Each cycle processes up to
five uncached coldkey histories, then waits 30 seconds before reading finalized
chain state again. Completed histories are cached; new registration identities
are detected using UID, hotkey, coldkey and registration block. Histories for a
shared coldkey are queried once before its earliest current registration.
Requests for an already cached coldkey and cutoff reuse that result.

Failed or incomplete lookups stay unknown and retry after a cooldown. Each
history has a ten-page bound. Budget exhaustion holds the worker without
changing rewards. Do not delete its cache to reset the API budget.

`report.json` records the finalized roster, transfer references, page hashes and
candidate groups. `collecting` means work remains queued;
`scan_complete_with_unknowns` means some histories could not be verified.
`scan_complete` describes completion of the indexer scan, not proof of ownership.

For a one-time report limited to selected registrations:

```sh
python -m umi.registration_funding_audit \
  --uid 71 --uid 72 \
  --prompt-api-key \
  --output /ABSOLUTE/PRIVATE/PATH/new-funding-report.json
```

The output file must not already exist. Do not run this alongside a watcher
using the same API key.

## Interpretation

A candidate requires exactly one recorded non-self sender across the complete
pre-registration transfer history returned by the indexer. Only direct shared
senders are grouped; there is no recursive wallet clustering. Known exchange or
shared-service addresses can be excluded with repeated `--shared-funder SS58`
arguments.

Transfers can predate registration by months. They do not prove who paid the
registration fee or who operates the miner. Shared withdrawal wallets, changed
coldkey ownership, same-block funding and non-transfer balance changes can make
the inference wrong or incomplete. Indexer completeness is not independently
proved. A reviewed, separately authorized reward-policy update would be required
before these candidates could affect payouts.
