[Documentation](../README.md) / Apple Silicon miner

# Apple Silicon miner

Use the [current connection guide](connection.md) for the miner release, policies,
feed profile, durable state paths and health checks. Apple Silicon is supported
as the miner target `aarch64-apple-darwin`. Keep model identity and protocol
configuration separate: changing the coordinator's platform does not require
moving your model to Linux.

## Model runtime

For the S1 reference model, the [model repository's macOS build and probe instructions](https://github.com/Umi-BitSign/umi-reference-model/blob/main/docs/RUN_MINER_MACOS.md#3-verify-build-and-bind-the-extractor)
cover the local extractor and inference identity. Extraction runs in its pinned
Linux/AMD64 Docker worker; PyTorch runs natively with MPS or CPU. Use those
instructions for the model artifacts. Use this repository's connection guide
for the active competition profile, transport allowance and service arguments.

A custom model can use the [in-process or isolated sidecar interface](model.md).
The sidecar must advertise the same model revision and transport digest as the
protocol miner, with capacity that fits the signed inference allowance. Verify
that agreement before restarting the protocol service. Preserve the model assets,
wallet and durable state specified by the connection guide.

## Finality and service operation

Use the Darwin observer from the
[competition miner bundle](https://github.com/Umi-BitSign/umi/releases/tag/umi-competition-miner-bundle-v1),
verified against the active transport policy's `aarch64-apple-darwin` digest and
published checksums. A locally rebuilt binary is not guaranteed to match that pin.
Keep the observer path consistent with the miner and chain configuration.

Keep the model runtime and protocol service available after reboot. If the model
uses Docker Desktop, verify that its required login session and Docker daemon
are running. Prevent system sleep while serving. Test restart recovery with the
actual service account and durable state, including a reboot; a successful
foreground shell run does not establish boot operation.

Check the miner's own `/healthz`, model capacity and finality freshness. A static
TLS-edge health response cannot show protocol readiness. Serve translation
requests through the [HTTPS endpoint configuration](model.md#miner-endpoint-ips-and-hostnames).

Measure the selected model under concurrent requests within the active signed
bounds. Test interrupted fetches, exact request retries, model timeouts and
restarts without losing durable response or nonce state. Keep capability URLs,
private video and hypotheses out of shared logs.

## Validators on a Mac

Provision a supported Linux VM and follow the
[validator supervisor guide](../PERMANENT_VALIDATOR_SUPERVISOR.md). Native Darwin
is not a validator-supervisor target. Miner support does not qualify a host-native
validator or an alternative container deployment.
