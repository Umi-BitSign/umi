# Coordinator and validator alerts

This monitor sends service-availability alerts from Cloudflare even when the
coordinator is offline. It observes selected long-running systemd services and,
when configured, the standing validator's native finalized-chain observations.
It detects missing observations and stalled block height or weight updates even
when systemd still reports a running process. These host observations do not
independently certify correct reward allocation or received payments. Intake,
evaluation and settlement progress require additional monitoring.

A coordinator timer sends a bounded heartbeat once per minute. The Worker
requires a private bearer token and exactly the configured service names. A
Durable Object retains the server-side receipt time and notification state.
After the first heartbeat, its independent alarm checks every minute. Five
minutes without a heartbeat raises an incident. Failed services also raise an
incident. Unresolved incidents repeat hourly; recovery and new incidents have
a five-minute notification cooldown to limit flapping. Failed email sends do
not record success and leave another check scheduled. Delivery is at least once:
a crash after email acceptance but before recording its receipt can duplicate
an alert. Cloudflare or email-provider failure can delay notifications.

## Configure and install

1. Onboard a dedicated sending subdomain in Cloudflare Email Service and verify
   the operator's destination address. Preserve the existing inbound mail setup.
2. Copy `wrangler.jsonc` into a private deployment configuration. Set its absolute
   `main` path, account, sender and recipient bindings, and the exact comma-separated
   `EXPECTED_SERVICES`. Restrict the email binding to that recipient and sender.
3. Generate a random token, save it privately, and set `HEARTBEAT_TOKEN` with
   `wrangler secret put --config /absolute/private/wrangler.jsonc HEARTBEAT_TOKEN`.
   Deploy using that configuration. Tokens and addresses are deployment inputs,
   not committed source defaults.
4. Install `heartbeat.py` as root-owned `/opt/umi-cohort-alerts/heartbeat.py`.
   Create root-owned `/etc/umi-cohort-alerts/heartbeat.json`, mode `0600`:

   ```json
   {
     "url": "https://YOUR-WORKER.workers.dev/heartbeat",
     "token": "PRIVATE_TOKEN",
     "services": ["umi-validator@0.service", "umi-validator@54.service"]
   }
   ```

5. Create the system account `umi-cohort-monitor`, with no home directory or login
   shell. Install the supplied service and timer in `/etc/systemd/system/`, reload
   systemd and enable `umi-cohort-heartbeat.timer`. The unprivileged service user reads
   its secret through systemd's credential facility; it has no validator state
   or wallet access. Select only services whose healthy substate is `running`.
   A systemd query failure aborts the poll; it does not report every service as
   failed. The external missing-heartbeat alarm still detects that loss of monitoring.
6. Check authenticated `GET /status` for a fresh heartbeat and future alarm.
   Test a missing heartbeat by stopping only this new timer, then restart it
   and check incident/recovery notification receipts. Confirm inbox delivery
   separately. Never stop validators to test the monitor.

## Successor validator health

For validator units managed by the successor supervisor, add
`successor_services` to the private heartbeat configuration, listing a subset
of `services`. Give the monitor user read access to systemd journals with a
service override containing `SupplementaryGroups=systemd-journal`. The sender
then requires the latest bounded `umi-successor-host-status/1` report from each
selected unit to use the current `started` / `successor_worker_started` or
`healthy` / `successor_worker_healthy` status/reason pair. It also accepts the
retained legacy `worker_started` and `worker_healthy` status values. A running
process with a held, failed, malformed, missing or older-than-45-minutes report
is exported as a failed service. Reports from an earlier systemd invocation
cannot satisfy a restarted service. The sender never exports the report text or
reason.

The window allows a healthy successor to verify retained history. This check
detects a supervisor that is alive but cannot reconcile or launch its worker;
it does not prove that a finalized weight update occurred. Use standing
validator progress below once the standing reward executor is active.

## Standing validator progress

Enable this only for units running the standing reward executor, which emits
`umi-standing-chain-observation/1` after native chain proof collection. Old
bootstrap validators do not emit it. Add `standing_services` to the private
heartbeat configuration, listing a subset of `services`. Give the monitor user
read access to systemd journals with a service override containing
`SupplementaryGroups=systemd-journal`. This group can read other journal entries;
the sender exports only the two integer counters, never journal text, wallet
data or transaction bytes. A denied, missing, malformed or oversized journal
read reports missing progress.

Configure the same metrics in the Worker's `PROGRESS_LIMITS` variable, as a JSON
string. For example, for a validator expected to refresh weights within thirty
minutes:

```json
{
  "umi-validator@54.service/finalized_block": 300000,
  "umi-validator@54.service/weight_update_block": 1800000
}
```

Values are alert thresholds in milliseconds, bounded between five minutes and
one day. Choose the weight threshold above the chain's permitted submission
interval and expected verification time. They are notification thresholds;
they do not expire work or cause restarts, transactions or reward changes.
Configure both counters for each monitored validator. Deploy the sender and
Worker configuration together; the Worker rejects a heartbeat that omits any
required metric, including an older availability-only heartbeat.

The external monitor retains each counter's highest observation and the server
time when it advanced. Repeated logs, lower counters, service restarts and fresh
heartbeats do not reset that time. Recovered missing data must still advance if
its previous observation is stale. Initial observations start the timer when
first received; missing data is an immediate incident. The native weight-update
counter advances only when chain storage does, never on a successful send or
an unresolved transaction. During slow replay an alert can be expected; it is
an instruction to investigate progress, not to erase state or interrupt replay.

The Worker exposes no unauthenticated status or configuration endpoint. Rotating
the token requires updating both the Worker secret and the coordinator's private
credential file. Disable both the timer and the Worker when deliberately retiring
the monitor; stopping only the coordinator timer raises an alert.

Run `npm ci && npm test` for storage/retry/cooldown and Workers runtime checks and
`wrangler deploy --dry-run --outdir /TASK-SCRATCH/build` before deployment.
Installed delivery and timer persistence require separate qualification.
