# UMI documentation

Start with the guide for your role. Public competition intake is live for endpoint
submissions. The registration bridge supplies current rewards; competition reward
activation requires certified settlement and verified native weight effects.
Model-artifact intake remains closed. Check [public status](https://api.umi.vision/v1/competition/status)
for the active policy and next intake schedule.

| I want to... | Start here |
| --- | --- |
| Register a new SN78 hotkey | [Official Bittensor mining guide](https://www.bittensor.com/docs/guides/mining), using subnet **78** |
| Run a miner now | [Miner requirements](CURRENT_MINER_OPERATION.md) |
| Configure or update an endpoint | [Current connection guide](miners/connection.md) |
| Connect my translation model | [Model integration and HTTPS endpoints](miners/model.md) |
| Run a miner on Apple Silicon | [Mac miner setup](miners/macos.md) |
| Install or troubleshoot a validator | [Validator supervisor](PERMANENT_VALIDATOR_SUPERVISOR.md) |
| Upgrade an existing validator host | [State-preserving upgrade](validators/successor-upgrade.md) |
| Understand the competition and rewards | [Competition overview](OPEN_COMPETITION.md) |
| Prepare a reproducible model for a future contribution round | [Contributor checklist](contributors/models.md), [staged terms](MODEL_CONTRIBUTION_TERMS_V2.md), [dependence-gate terms draft](competition/TERMS_V3_DRAFT.md), and [historical version 1 terms](MODEL_CONTRIBUTION_TERMS.md) |

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
- [Public results API and pending round discovery](reference/competition-results-api.md)
- [Observer API](reference/dashboard-api.md) and [example configurations](examples/)
- [Whitepaper](../whitepaper/README.md), [PDF](../whitepaper/UMI-Whitepaper.pdf)

Keep current instructions here. Put implementation history in commits and PRs,
not another dated operator guide. The `main` branch may be ahead of production;
merging code does not activate it. Deployment status needs a checked block,
signed policy or release, and finalized chain evidence. A running process or an
old report does not prove current rewards.

Update the authoritative guide in place. Keep release downloads, policy hashes
and connection commands in the connection guide; link to it from role pages.
Remove expired instructions and completed deployment narratives. Retain migration
steps only while deployed consumers need them, with a clear removal condition.
Exact signed terms and evidence remain available for verification. Implementation
history belongs in commits and PRs; community replies belong outside public setup
documentation.
