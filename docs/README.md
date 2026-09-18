# UMI documentation

Start with the guide for your role. Public first-round competition intake is
live for endpoint submissions only, while the registration bridge remains the
current reward mechanism. Open-competition rewards have not been activated. The
public-endpoint pilot and calibration enrollment are closed. The
[public status](https://api.umi.vision/v1/competition/status) exposes the exact
live intake policy. Assignment delivery and model-artifact intake are not yet
open.

| I want to... | Start here |
| --- | --- |
| Run a miner now | [Miner requirements](CURRENT_MINER_OPERATION.md) |
| Connect my translation model | [Model integration and HTTPS endpoints](miners/model.md) |
| Run a miner on Apple Silicon | [Mac miner setup](miners/macos.md) |
| Install or troubleshoot a validator | [Validator supervisor](PERMANENT_VALIDATOR_SUPERVISOR.md) |
| Upgrade an existing validator host | [State-preserving upgrade](validators/successor-upgrade.md) |
| Understand the competition and rewards | [Competition overview](OPEN_COMPETITION.md) |
| Prepare a reproducible model for a future contribution round | [Contributor checklist](contributors/models.md) and [terms](MODEL_CONTRIBUTION_TERMS.md) |

## Service operators

Ordinary miners and weight-writing validators do not need to deploy these services.

1. [Launch configuration and acceptance checklist](competition/launch.md)
2. [Private evaluation data](operators/private-holdout.md)
3. [Round scheduling and work authorization](operators/rounds.md)
4. [Endpoint dispatch](operators/dispatch.md) and [model evaluation](operators/evaluation.md)
5. [Evaluator exchange and retained history](operators/exchange.md)
6. [Settlement and signed weight publication](operators/settlement.md)
7. [Model review and promotion](operators/promotion.md)

The temporary mechanism has its own [bridge rules and diagnostics](operators/bridge.md)
and optional [funding audit](operators/funding-audit.md).

## Reference

- [Competition CLI recipes](reference/commands.md)
- [Observer API](reference/dashboard-api.md) and [example configurations](examples/)
- [Whitepaper](../whitepaper/README.md), [PDF](../whitepaper/UMI-Whitepaper.pdf)
- [Retired workflows and dated deployment evidence](reference/legacy.md)

Keep current instructions here. Put implementation history in commits and PRs,
not another dated operator guide. The `main` branch may be ahead of production;
merging code does not activate it. Deployment status needs a checked block,
signed policy or release, and finalized chain evidence. A running process or an
old report does not prove current rewards.
