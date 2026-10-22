# UMI

UMI develops ASL-to-English translation through reproducible public model
contributions and evaluation. Contributors submit runnable, licensed artifacts
for promotion into successive public baselines.

## Miners: start here

- **Submit a public model for C6:** follow the [model submission steps](docs/miners/model.md#model-files-for-recoverable-cohorts), including the separate admission-status check. Install the [published model client](docs/miners/connection.md#install-or-update-the-model-submission-client), even if you already run an endpoint miner.
- **Check what is required now:** [current miner operation](docs/CURRENT_MINER_OPERATION.md) distinguishes live C5 rewards, C6 intake and successor preparation.
- **Register a hotkey:** use the official [Bittensor registration guide](https://www.bittensor.com/docs/guides/mining) for subnet **78**. Registration alone does not submit a model or earn a competition reward.
- **Maintain an existing endpoint:** use the [connection guide](docs/miners/connection.md) and [model integration guide](docs/miners/model.md). Endpoint enrollment is not a public-model submission for C6.

## Validators: start here

- **Install:** [validator supervisor setup](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#install).
- **Already installed?** [Check the service](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#check-the-service), [understand automatic updates](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#what-is-automatic), or [troubleshoot a hold or failed update](docs/PERMANENT_VALIDATOR_SUPERVISOR.md#troubleshooting).
- **Check results and reward state:** [public results API](docs/reference/competition-results-api.md) and the finalized chain allocation. Admission, scoring and active rewards are separate states.

## Documentation

- [All documentation](docs/README.md)
- [Competition and reward allocation](docs/OPEN_COMPETITION.md)
- [Public results API and pending round discovery](docs/reference/competition-results-api.md)
- [Model contributions](docs/contributors/models.md)
- [Whitepaper](whitepaper/README.md) and [PDF](whitepaper/UMI-Whitepaper.pdf)

## Network phase

C5 certification is complete and C5 competition rewards are live. C6 remains in
public-model intake while its release preparation completes. Its evaluation and
cohort certification have not started. The intake cutoff will be announced
separately; an expired nominal block target is not a new cutoff announcement.

C6 uses direct R2 model delivery. Prepare public-model contributions for C6 and
later cohorts; do not start an endpoint enrollment as a substitute. Later cohorts
still require their authenticated successor plans before opening. Read the
[current miner operation guide](docs/CURRENT_MINER_OPERATION.md), the
[cohort catalog](https://api.umi.vision/v1/competition/cohorts) and the selected
cohort's signed history/readiness before submitting.

The original submission receipt always says `pending_attestation`. It does not
change when a certificate is issued. Run `query-cohort-admission` with the original
signed request to read the current `admission_certified` status. Neither status
means the model has been scored or has active rewards. The
[submission guide](docs/miners/model.md#check-admission-after-upload) provides the
exact command and explains each stage.

The [current upgrade manifest](deploy/miner-upgrade/current.json) selects the
published client and its authenticated policy/runtime bindings. The `main` branch
is reviewed source, not an activation signal. Live behavior is defined by the
signed deployment, cohort history and finalized chain state. Historical bridge
instructions do not describe current C5 competition payouts.

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
