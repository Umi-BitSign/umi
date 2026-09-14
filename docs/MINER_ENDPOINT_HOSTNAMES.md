# Miner endpoint IPs and hostnames

The open-competition endpoint path accepts either of these HTTPS origins:

- A public literal IP, such as `https://8.8.8.8:8443`.
- A DNS hostname, such as `https://miner.example.org`.

These are format examples, not UMI endpoints. Use your own origin and a valid
certificate for its IP or hostname. This support does not activate open
competition or change the live registration bridge's literal-IP discovery and
signed grouping rules.

## Registration and verification

The miner signs its exact endpoint URL with its registered hotkey. For DNS names,
use lowercase ASCII labels (IDNs use their canonical `xn--` spelling), without a
trailing dot. Origins have no credentials, path other than `/`, query or fragment.
Omitting the port means 443. Private addresses and local names are rejected.

The finalized chain Axon still records a numeric IP and port. A hostname must
resolve to public addresses that include that announced IP, and its HTTPS port
must equal the announced port. Validators reject the entire DNS answer set if
any address is private, reserved, multicast or an unsupported transition address.
DNS failure, an oversized answer set or a mismatching Axon holds dispatch before
the evaluator signs or claims a request.

The validator connects only to the validated Axon IP. It sends the signed
hostname in TLS/SNI and the HTTP Host header, verifies the certificate, and
checks the miner's hotkey-authenticated response. It does not resolve DNS again
between validation and connection, and does not follow redirects.

DNS evidence is a local resolver observation, separate from the finalized chain
proof. IP evidence retains schema `/1`; hostname evidence uses
`umi-competition-endpoint-origin-evidence/2`, including the DNS answers and
connection origin. If answers change during repeated checks at the same
finalized block, the original evidence is retained and that check holds. A later
finalized block can record the new answers. Do not clear evidence to force a retry.

## Dynamic home IPs and Cloudflare Tunnel

A Cloudflare Tunnel connects outward from the miner host, so the home connection
does not need a static IP or inbound port forwarding. Use a stable hostname and
a persistent tunnel, with the local miner bound to loopback. Keep UMI request
authentication enabled. See Cloudflare's
[Tunnel documentation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/).

For this endpoint profile, announce a current public IP returned by the proxy
hostname's DNS and its public HTTPS port, not the home's private or changing IP.
If that announced proxy IP disappears from the validator's DNS answers, update
the Axon and wait for finalization. Geo-dependent DNS answers can cause holds;
test from the evaluator's network before announcing service as available.

Configure the proxy to preserve request bodies and UMI authentication headers,
disable response caching, and avoid browser login or challenge pages on miner
API routes. Check its upload and request-time limits against the signed workload
limits. Expose only the miner routes, never model-worker sockets, wallets or
administrative endpoints.

A shared CDN IP does not establish a shared operator. The current bridge's IP
grouping can combine miners behind the same proxy IP; hostname support here does
not silently exempt those miners from the bridge's signed reward policy. An
external health response alone also does not establish model-serving readiness.
