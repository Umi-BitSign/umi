# UMI

UMI develops ASL-to-English translation through endpoint competition and
reproducible public model contributions. Endpoint miners may keep their models
private; contributors can submit runnable, licensed artifacts for promotion
into successive public baselines.

Start with the [documentation](docs/README.md).

- [Miners: what to run now](docs/CURRENT_MINER_OPERATION.md)
- [Validators: installation, updates and troubleshooting](docs/PERMANENT_VALIDATOR_SUPERVISOR.md)
- [Competition and the 70/30 allocation](docs/OPEN_COMPETITION.md)
- [Model contributions](docs/contributors/models.md)
- [Whitepaper](whitepaper/README.md) and [PDF](whitepaper/UMI-Whitepaper.pdf)

## Network phase

The temporary registration bridge uses live HTTPS health checks and shared
coldkey/IP/funding groups. It does not score translations. The public-endpoint
pilot is closed. The ongoing bridge policy has no scheduled calendar sunset;
historical finite policies retain their original expiry.

Open-competition rewards have not been activated. Code, tests, a running miner
and staged release artifacts are not a finalized competition row. The
[launch checklist](docs/competition/launch.md) defines the remaining activation
evidence. Check current chain state before making payout claims.

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

## Historical material and license

[Retired runbooks and dated deployment reports](docs/reference/legacy.md) are
available at their preserved Git revision. They are not current installation
instructions. The [version 0.1 specification](whitepaper/LEGACY_V0_1.md) remains
available for interpreting old signed evidence.

UMI-authored code is [Apache-2.0](LICENSE). See
[third-party notices](THIRD_PARTY_NOTICES.md) for inherited terms.
