# Studio private-service gateway

Public miner origin: https://studio-miner.sam-sn78.workers.dev

Public assignment-feed route:
https://api.umi.vision/v1/competition/assignments/query

The Worker forwards `GET /healthz` and `POST /v1/translate` on the miner host
to a fixed Workers VPC service for Studio's `127.0.0.1:8787`. A route on
`api.umi.vision` forwards only `POST /v1/competition/assignments/query` to a
separate fixed VPC service for `127.0.0.1:8129`. Host and path checks prevent
either public origin from reaching the other service. Studio needs outbound
connectivity, with no static public IP or inbound router port.

## Request boundaries

- Separate fixed VPC bindings, origins and ports; clients cannot choose an
  upstream.
- Exact public host, path and method combinations. The assignment path is
  intercepted on `api.umi.vision`; all other API paths continue to the API
  origin.
- Exact routes and methods, no query strings, redirects or protocol upgrades.
- Request and response bodies limited to 64 KiB. These are JSON envelopes;
  video is not uploaded through this route. Headers are limited to 16 KiB.
- 180-second proxy deadline and cancellation on client disconnect. Validator
  deadlines can be shorter; the 130-second probe is a transport check only.
- Request body bytes and authentication headers are preserved. The actual
  miner must authenticate each translation request before running inference.
- Responses are not cached. Proxy logs exclude bodies and credentials.
- The Cloudflare Worker has no wallet or tunnel-token binding. The token stays
  in a mode-0600 file under a mode-0700 directory on Studio.

The VPC services are `studio-miner-http`, ID
`01a0a172-c22f-7230-82f2-3bdb5f8c9e93`, and
`studio-competition-feed-http`, ID
`01a0ae0a-9ebc-7462-8ad7-14d7cfa55810`. Both use dedicated tunnel
`4407a5b4-06b1-4b1b-935a-c3966a6281d1`. Its public ingress is a catch-all 404.

Workers VPC is currently beta. See [Cloudflare's VPC limits](https://developers.cloudflare.com/workers-vpc/reference/limits/).
The `workers.dev` address depends on keeping the Worker and account subdomain
names unchanged. It is not a dedicated public IP.

## Studio startup

The connector currently runs in `user/502/com.umi.studio-miner-tunnel`, a
background launchd job that restarts the connector if it exits. This does not
establish startup before login after a reboot.

The files in `macos/` are staged in
`/Users/sam/umi-miner-setup/cloudflare/` on Studio. To enable boot startup,
run this in your own terminal and enter Studio's sudo password:

```sh
ssh -t sam@matthews-mac-studio.local '/bin/bash /Users/sam/umi-miner-setup/cloudflare/enable-tunnel-at-boot.sh'
```

The script installs only `com.umi.studio-miner-tunnel` as a LaunchDaemon,
running as `sam`. It starts a second connector and checks readiness on loopback
port 20247 before unloading the existing background connector on port 20246.
It refuses to overwrite a different daemon configuration. Neither validator
service is changed. Enabling the tunnel does not start the model server.

## Update the Worker

Use a Cloudflare login with access to the configured account and VPC service.
No API credential belongs in the repository.

```sh
cd deploy/studio-miner-proxy
npm ci
npm test
npm run types
npm run check
npx wrangler deploy --dry-run
npm run deploy
```

Before announcing a release, test both public routes with their real signed
protocols. A working gateway alone does not establish miner eligibility,
assignment eligibility or incentive.
