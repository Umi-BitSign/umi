[Documentation](README.md) / Open competition

# Open competition

The successor mechanism has two tracks. Qualifying translation endpoints share
70% of the miner allocation, proportional to quality. A qualifying promoted
model's contributor receives 30%. Until the first promotion, that 30% is burned.
The imported baseline has no contributor award or founding-model exception.

Public intake is live at `https://api.umi.vision`. The first roster is scheduled
to close between blocks `9,135,843` and `9,135,903`; its evaluation closes at
block `9,156,243`. A submission intended for this round must remain valid through
at least `9,156,243`. The exact policy digest is
`81c118c5b45527650d7f304a6574d04223de30fbad76c69df09e7f2ae4897fa0`.

Competition rewards have not yet replaced the registration bridge. Until the
signed transition is verified on chain, miners should keep following the
[current bridge instructions](CURRENT_MINER_OPERATION.md) as well. A healthy
endpoint or `accepted_no_weight` receipt proves neither evaluation nor payment.

## Endpoint miners

Run the [protocol miner with a working model](miners/model.md). The endpoint
track supports a public HTTPS IP or a hotkey-signed hostname bound to its
chain-announced IP. A keepalive alone cannot answer translation requests.

Sign your submission with the registered hotkey. It binds your endpoint, model
revision, policy and accepted terms. No seed phrase, coldkey or personal API key
is submitted. The live origin and complete procedure are in the
[submission commands](reference/commands.md#live-first-round-intake). A valid
receipt has status `accepted_no_weight`; keep it and keep the submitted model and
endpoint unchanged and online through evaluation.

## Model contributors

Contribution is optional. Submit a complete, reproducible artifact with weights
or base-plus-adapter files, configuration, tokenizer, inference code, dependency
inventory, hashes and notices. UMI preserves qualifying promoted models so
future miners and products can use them independently of an endpoint.

Read the [preparation and rights checklist](contributors/models.md) and
[accepted version 1 terms](MODEL_CONTRIBUTION_TERMS.md) before spending compute.
Ownership stays with contributors; licenses and upstream obligations still apply.
Uploading an archive or winning an endpoint benchmark does not grant the model
share. Promotion requires reconstruction, paired improvement, preservation and
rights review.

The first contribution round targets seven days, with exact signed cutoffs
published before intake. Endpoint scoring may run during collection. If nothing
qualifies, the 30% remains burned; rewards do not accrue retroactively.

## Evaluation and trust

The initial policy uses UID 0 as one evaluator group. UID 54 shares its
administration and is not an independent vote. This is a disclosed
single-operator launch, not independent evaluator consensus.

Automatic scoring compares one authentic reference per clip: fingerspelling
CER weighted 3/13 and continuous-signing WER weighted 10/13. The inference limit
is 120 seconds. Candidates and the preserved incumbent use the same committed
suite and runtime profile. Labels stay out of execution until reveal; exposed
cases are retired. Text error rates do not establish human interpreter
equivalence, clinical safety or unseen-training performance.

## Operations and release checks

The [launch configuration](competition/launch.md) is the single acceptance
checklist and policy reference. It covers the burn proof, exact intake windows,
real workload qualification, signed artifacts, state-preserving handoff and
finalized competition-row verification.

Service operators should follow the [round](operators/rounds.md),
[dispatch](operators/dispatch.md), [evaluation](operators/evaluation.md),
[settlement](operators/settlement.md) and [promotion](operators/promotion.md)
guides. Ordinary weight validators consume certified results; installing one
does not grant access to private labels.

Renewal uses fresh chain checks and bounded reuse of an existing settlement.
New reviewed rounds and protected suites remain necessary. The
[whitepaper](../whitepaper/README.md) describes the mechanism; the
[CLI reference](reference/commands.md) retains component and rehearsal recipes.
