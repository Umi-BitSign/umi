[Documentation](../README.md) / Transport cadence

# Align transport windows with recurring cohorts

A public cohort schedule and the request transport have separate clocks. A
2,880-block cohort cadence can drift through a 2,160-block transport cadence:
one cohort may fit while the next has too little time left to issue its requests.
Moving the transport activation block can align one cohort, but does not remove
that recurring mismatch.

`ScoringPolicy.competition_transport` accepts an explicit `window_stride_blocks`.
For a 2,880-block public cadence and a six-hour issue allowance:

```python
transport = ScoringPolicy.competition_transport(
    activation_block=reviewed_activation_block,
    implementation_pins=reviewed_pins,
    validator=reviewed_evaluator,
    issue_allowance_seconds=21600,
    window_stride_blocks=2880,
)
```

The stride must be a whole multiple of the 360-block launch window, at least
the minimum stride needed for the configured challenge lifecycle. Omitting it
preserves the previous minimum-stride calculation and canonical policy bytes.
Legacy scoring policies retain their fixed launch clock.

Changing only the stride preserves request deadlines, response and reveal
allowances, authentication freshness, retry limits and reward settings. Extending
the issue allowance instead would also extend the request's block deadline,
which can exceed the cohort's already frozen evaluation close.

This produces a different transport digest. It requires a reviewed deployment,
compatible miner and replay releases, signed connection inputs, and new state
namespaces wherever journals bind the old transport. Older releases reject a
stride that differs from their minimum-stride calculation. Preserve previous
assignments, responses, receipts and nonce history during migration; changing a
policy does not alter any outstanding assignment.

Align the activation phase as well as the stride. Qualify capacity against each
cohort's actual cutoff, the full pending workload, measured costs and fresh owned
finality. Regression tests using prior timing bounds are not a fresh deployment
or inference qualification. Published policies and running cohorts do not change
when this source support is installed.
