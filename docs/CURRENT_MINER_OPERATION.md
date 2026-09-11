# What SN78 miners should run now

The current validator release runs the temporary `bootstrap_service_binary`
mechanism. It replays completed pilot evidence, checks the frozen participants'
announced HTTPS endpoints, and submits or renews the signed service-weight row.
It does not issue new translation challenges or score a miner's current model.
Installing more validators does not by itself start translation traffic.

Check [public bootstrap status](https://api.umi.vision/api/v1/bootstrap-service)
for the current row, eligible miners, and economic effect. At finalized block
`9044963` on 2026-09-11, the frozen manifest contained UIDs 6 and 247. UID 54's
matching row was active, but both eligible miners still had zero consensus and
incentive, and active conflicting rows remained. Use the live endpoint for newer
observations.

## If your hotkey is in the frozen bootstrap manifest

Keep the same registered hotkey and chain-announced HTTPS IP and port recorded
in the manifest. Before each submission or renewal, the validator requires a
fresh `GET /healthz` response with HTTP 200, valid TLS, no redirect, and a small
response body. A failed check prevents submission of the frozen row; the worker
does not silently remove a miner and redistribute its share.

A lightweight HTTPS keepalive can satisfy this current endpoint health check.
You do not need to load a GPU model or switch to the full translation runtime
solely because another bootstrap validator starts. The check establishes endpoint
availability only; it does not establish that a model can translate.

The pilot closure notice retires timed case requests and readiness challenges.
It does not retire the health endpoint needed by an already enrolled bootstrap
participant. Do not reset that axon or shut down its HTTPS health service while
participating in the remaining bootstrap interval.

## If your hotkey is not in that manifest

The pilot campaign is closed and the initial manifest is frozen. Starting a
keepalive, completing an old challenge, or running a model cannot add your hotkey
to this bootstrap row. No pilot compute or new pilot issue is needed. Model
development can continue locally while the live translation release is prepared.
Prior pilot participation is not a prerequisite for the planned live translation
mechanism.

## When translation traffic starts

UMI will publish the matching miner instructions and signed policy before asking
miners to serve translation requests. That phase needs the UMI protocol miner
connected to a working model, using an in-process translator or a model sidecar
as described in [miner model integration](MINER_MODEL_INTEGRATION.md). A health-only
keepalive cannot answer those authenticated translation requests.

A change to the checkpoint, preprocessing, decoder, or other inference-affecting
artifact needs a new serving model revision. Follow the model integration guide
to bind that revision to the backend; do not change it during an active request.

## Interpreting displayed payouts

Chain emissions can be enabled while UMI translation weights are inactive and
the bootstrap row has no economic effect. An amount shown as a dividend or
emission does not identify the row that produced it or prove translation scoring
has started. Check the UID, finalized block, and exact field before attributing
a displayed payment to UMI.

The `subnet_emission_enabled` flag does not guarantee positive TAO inflow. The
chain scales TAO emission shares by miner burn and applies an emission gate;
participant-side alpha issuance is a separate value. At finalized block `9045044`
on 2026-09-11, the flag was true, `SubnetTaoInEmission` and
`SubnetAlphaInEmission` were zero, `MinerBurned` was about 99.61%, and
`SubnetAlphaOutEmission` was 1 alpha per block. Zero TAO inflow alone does not
establish that the switch was disabled or that every alpha payout stopped.
See the [Bittensor emissions documentation](https://www.bittensor.com/docs/concepts/emissions#subnet-emission-shares)
for these separate accounting paths.

The public API reports `service_weights_active` separately from
`service_weights_economically_effective`; `translation_weights_active` identifies
the translation mechanism. See the
[shared-validator bootstrap explanation](SHARED_VALIDATOR_BOOTSTRAP_SUPERSESSION.md)
for the current validator behavior.
