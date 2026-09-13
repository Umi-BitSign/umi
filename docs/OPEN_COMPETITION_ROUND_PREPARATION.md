# Round preparation

These are internal coordinator APIs. They produce unsigned inputs for the
existing cutoff-publication contract. They do not schedule protected data,
collect quorum signatures, publish evaluator orders or authorize weights.

## One finalized snapshot

`FinalizedRegistrationProvider.collect_at(height)` rechecks complete SN78
membership at a recent exact height. A coordinator and an independent evaluator
can therefore compare the same snapshot even when their latest heads differ.

The historical header must already be in the caller's owned finality verifier.
The method verifies its header/evidence binding, pinned runtime, storage proofs
and inverse UID mapping. Both the current head and the requested snapshot must
pass the existing wall-clock freshness checks; the requested height must also
fit the policy's snapshot-age limit. It never accepts a header supplied by the
coordinator as finality evidence.

Historical reads retain their own evidence without replacing the latest intake
snapshot or lowering the persistent head guard. Exact-block reads reprove
membership even if that height was captured earlier. Existing caches remain
usable, and their highest captured block still prevents rollback.

## Atomic roster and cutoff

`CompetitionStore.prepare_round(...)` takes that registration snapshot, the
private evaluation suite, explicit evaluation/reveal/cutoff/expiry blocks and
publication byte limits. In one SQLite transaction it:

- Selects the latest accepted submission for each current hotkey and track.
  A submission must remain valid through evaluation close. An expired
  replacement never revives an older submission.
- Excludes hotkeys no longer registered at the supplied snapshot. Their earlier
  admission records remain intact.
- Reads the preserved, unconflicted incumbent and assigns the next round sequence.
- Fixes the evidence cutoff and freezes the complete selected roster at the
  snapshot block, then retains the unsigned cutoff publication and signed
  submission bodies.

The caller must obtain the snapshot from its owned provider. The store itself
cannot verify finality. Its output remains `chain_submission_authorized: false`
and contains no protected references or evaluator signatures.

A submission racing the freeze is either included in that round or explicitly
rejected at the closed admission boundary. It can be submitted in a later block
for a later round. Concurrent preparations cannot freeze different rosters at
the same boundary.

The suite digest identifies an exact retry. Restarting or retrying later returns
the original preparation, including its original deadlines. Changing those
deadlines for the same suite is rejected. The eventual publisher must check
that sufficient time remains before signing or dispatching; an old preparation
does not become timely because it was retrieved again.

`RoundPreparationCapacity` bounds retained preparations (default 1,024 records
and 1 GiB of preparation bodies). Publication byte limits are checked before
reading a large roster into memory. A storage or byte-limit failure rolls back
the cutoff, round and suite reservation together. It does not remove earlier
preparations. Ordinary admission and existing proof-cache limits still apply.

## Remaining integration

The [continuous coordinator](OPEN_COMPETITION_ROUND_COORDINATOR.md) now consumes
private plans, calls these APIs and obtains independent cutoff signatures.
Operators still supply fresh protected suites and reviewed round windows.
Automatic evaluation-order signing and delivery to the exchange remain work.
Completed rounds then need signed settlement publication and successor input
materialization. None of these internal methods changes the live bridge policy
or extends its sunset.
