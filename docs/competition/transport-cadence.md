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

For a future cohort, the issue allowance can be between 300 and 86,400 seconds.
Extend the public signing and evaluation phases along with the transport clock;
choose a cadence long enough for response, reveal and evidence collection.
Authentication freshness remains unchanged: dispatch signs a fresh nonce when it
claims each request. Longer queues do not make old authentication reusable.

Future competition transports can also set `response_window_seconds` between
300 and 3600. The default remains 300, preserving existing policy bytes. An
18-hour issue allowance with `response_window_seconds=900` and
`window_stride_blocks=7200` leaves 15 minutes after issue close for the last
request to finish. The minimum stride calculation includes this response time.
Compared with the default response window, 900 seconds moves response and reveal
600 seconds later and increases the request's block deadline by 50 blocks.
Recheck the public evaluation close and capacity with those deadlines. Legacy
scoring policies retain their 300-second response window.

Dispatch HTTP timeouts accept up to 900 seconds; their default remains 180. A
615-second timeout for a 600-second inference allowance fits within the explicit
900-second response window. Capacity admission charges the full configured HTTP
timeout and checks the response and block deadlines before signing new work.

A version-2 launch amendment with reason `extend_future_cohort_windows` names
the first old cycle being replaced. It requires the evaluator quorum, preserves
the original intake opening and eligible tracks, and cannot shorten any phase
or the cadence. Apply it after the preceding cycle's validity ends and before
the original next roster cutoff. The store rejects an extension of any already
prepared or active cohort and retains prior rounds, receipts, checkpoint history
and evidence. A quiesced migration fences stale writers. Version-1 amendments
retain their existing bytes and first-cohort scope.

Before signing, project the full intended miner count with measured costs,
publication/signing delays, faster block progress, slower operations and recovery.
Require explicit reserve against issue, response and block deadlines. Then run
the actual host rehearsal with advancing clocks; a projection alone does not
qualify a deployment. Apply only to future unconsumed cohorts; existing signed
assignments keep their original deadlines.

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
