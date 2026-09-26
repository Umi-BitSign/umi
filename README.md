# UMI

UMI develops ASL-to-English translation through endpoint competition and
reproducible public model contributions. Endpoint miners may keep their models
private; contributors can submit runnable, licensed artifacts for promotion
into successive public baselines.

## Miners: start here

- **New to SN78?** Follow the official [Bittensor registration guide](https://www.bittensor.com/docs/guides/mining) using subnet **78**, then read [what UMI miners should run now](docs/CURRENT_MINER_OPERATION.md).
- **Already running an endpoint?** Apply the [current C4 / policy-8 update](docs/miners/connection.md). An accepted receipt can remain valid while your service still needs this update.
- **Set up and submit an endpoint:** [connect your model](docs/miners/model.md), [Apple Silicon setup](docs/miners/macos.md), and [competition intake instructions](docs/reference/commands.md#live-first-round-intake). On-chain registration and competition intake are separate steps.

## Validators: start here

- **Install:** [validator supervisor setup](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#install).
- **Already installed?** [Check the service](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#check-the-service), [understand automatic updates](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#what-is-automatic), or [troubleshoot a hold or failed update](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#troubleshooting).
- **Check weights and eligibility:** [current bridge rules](docs/operators/bridge.md) and [finalized-row diagnostics](docs/operators/bridge.md#check-current-rows).

## Documentation

- [All documentation](docs/README.md)
- [Competition and the 70/30 allocation](docs/OPEN_COMPETITION.md)
- [Public results API and pending round discovery](docs/reference/competition-results-api.md)
- [Model contributions](docs/contributors/models.md)
- [Whitepaper](whitepaper/README.md) and [PDF](whitepaper/UMI-Whitepaper.pdf)

## Network phase

The temporary registration bridge uses live HTTPS health checks and shared
coldkey/IP/funding groups. It does not score translations. The ongoing bridge policy has no scheduled calendar sunset;
historical finite policies retain their original expiry.

Public competition intake is live for endpoint submissions only. Use the
[current connection guide](docs/miners/connection.md) for the exact miner
release, policy files, binary downloads and service configuration. Check the
public status for the next intake schedule. Accepted submissions can carry
forward when their terms, registration and validity interval remain eligible.
Open-competition rewards have not replaced the bridge. An
`accepted_no_weight` receipt records an admitted submission; it does not prove
evaluation, settlement or payment. Model-artifact intake remains closed. See the
[live competition status](https://api.umi.vision/v1/competition/status) and the
[launch configuration](docs/competition/launch.md) for the exact policy and
cutoffs. The status also publishes an operator-declared repository revision and
the UMI source-tree digest. Intake startup recomputes and enforces the source-tree
digest. Release verification must separately confirm that the declared revision
is the commit from which that exact tree was deployed.

The `main` branch is reviewed source, not an activation signal. Launch-facing
documentation on `main` must describe deployed behavior; incomplete features
must be gated and labeled. Live behavior is defined by the exact signed policy,
release and finalized chain row reported through the public status and release
channels. Code, tests, a running process and staged artifacts do not activate
rewards.

## Development

Python 3.10 through 3.14 are supported. Install FFmpeg and FFprobe with your
operating-system package manager, then:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install uv==0.12.9
uv sync --locked --extra dev
make check
```

The dependency lock uses Bittensor 11.1.0. Miners use its HTTP protocol, not the
removed Axon/Dendrite/Synapse Python classes. Model execution belongs on an
appropriately provisioned host, separate from private evaluator labels.

See the [model adapter](docs/miners/model.md),
[CLI recipes](docs/reference/commands.md),
[owned-finality verifier](rust/grandpa-finality-observer/README.md) and
[observer API](docs/reference/dashboard-api.md) for component details.
The public model lives in
[umi-reference-model](https://github.com/Umi-BitSign/umi-reference-model).
Product planning lives under [bitsign MVP](roadmap/bitsign-mvp/README.md).

## License

UMI-authored code is [Apache-2.0](LICENSE). See
[third-party notices](THIRD_PARTY_NOTICES.md) for inherited terms.
