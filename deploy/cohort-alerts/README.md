# Coordinator availability alerts

This monitor sends service-availability alerts from Cloudflare even when the
coordinator is offline. It observes selected long-running systemd services; it
does not prove cohort progress, chain finality or payments. Add those native
observations before treating it as complete cohort monitoring.

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

The Worker exposes no unauthenticated status or configuration endpoint. Rotating
the token requires updating both the Worker secret and the coordinator's private
credential file. Disable both the timer and the Worker when deliberately retiring
the monitor; stopping only the coordinator timer raises an alert.

Run `npm ci && npm test` for storage/retry/cooldown and Workers runtime checks and
`wrangler deploy --dry-run --outdir /TASK-SCRATCH/build` before deployment.
Installed delivery and timer persistence require separate qualification.
