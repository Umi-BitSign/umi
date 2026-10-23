# Maintenance

- Carry each change through affected miner and validator implementations,
  published release selections and supported automatic update paths. Verify
  actual published/installed behavior before claiming rollout, including older
  supported layouts. Source-only fixes do not establish update delivery.
- Treat Bittensor runtime upgrades as routine. Discover the runtime from native
  finalized code/metadata proofs; do not gate new operation on fixed runtime
  versions or an expanding release allowlist. Preserve historical signed bytes
  and their original bindings for recovery, and require explicit supported state
  semantics and proofs rather than silently trusting RPC assertions.

- For C6 and later cohorts, retain the entire finalized block range and complete
  native replay proofs throughout intake, work and certification. Verify
  independent blocks in bounded spawned workers, persist each completed result,
  and apply history effects in block order under one owner. Workers must use
  immutable inputs without RPC, signing keys or live owner database handles.
  Expose captured, verified, replicated and applied progress separately. Qualify
  serial equivalence, gaps, out-of-order completion, restart, repair and upgrades.

- Carry every permanent fix through C6 and subsequent cohorts, including the
  selected miner/client, coordinator, reviewer, writer and upgrade paths that
  consume it. Qualify older supported installations, retained artifacts, restart,
  repair and reward replay before claiming successor readiness. Preserve each
  already signed plan and its clocks; transport or policy changes need their
  supported authenticated adoption or a separately signed successor. A C5-only
  recovery helper or source test is not proof of a future cohort deployment.

- Prefer one consolidated PR for a coherent body of work. Include related fixes,
  integration, tests and documentation, and batch validation before pushing to
  avoid running slow CI for each small change. Split only when an independent
  release or urgent fix needs to land separately.

- Maintain existing public setup guides in place. Keep one authoritative page
  for current miner release, policy and download details, linked from the README
  and role index. Test changed commands and download hashes, and check internal
  links before publishing. Do not add dated incident reports or community replies
  to the public repository. Write from the current operator's perspective. Remove
  superseded guides, expired block schedules and completed deployment narratives;
  Git history holds the chronology. Keep migration instructions only while a
  deployed consumer needs them, and state the condition for removing them.
- Preserve exact signed terms, artifacts and evidence. Link an older specification
  at its fixed Git revision only where verification or recovery still needs it;
  do not maintain a general catalogue of retired workflows.
- Check each change for unused code and duplicated documentation. Before removing
  code, check imports, command entry points, deployed services and recovery/replay
  consumers. An elapsed block boundary alone does not make a decoder unused.

- Keep command entry points separate from policy, pure calculations, and I/O.
  Use explicit imports and typed boundaries; do not add runtime import tricks to
  preserve an oversized module.
- Refactors must preserve signed bytes, published schemas, command arguments,
  and durable journal semantics. Test historical inputs and failure paths.
- Schema or encoding changes must include the compatibility reader, migration or
  repair needed by supported installations and retained evidence. Qualify the
  original signed artifacts through every consuming publication, certification,
  reward and restart/replay stage; preserve their bytes and state bindings.
- Every preparation, validation, migration, recovery and execution stage must
  expose counted progress, elapsed time, ETA basis and stalled/retrying status.
  Before enough samples exist, report a labeled planning range with assumptions.
  Keep substage estimates separate from overall completion, revise stale ranges,
  and qualify telemetry without adding execution watchdogs.
- Successful expensive verification is durable owner state. Reuse it across
  stages and restart for unchanged evidence and validation context. Bind reuse to
  actual immutable local/R2 identities, policy, lineage, owner and signed clocks;
  never accept a caller-supplied digest as proof. Preserve exact collector coverage
  and resource accounting without rereading/rehashing trusted unchanged payloads.
  Initial semantic verification remains required. Version native/shape rules when
  accepted validation semantics change; unrelated releases preserve verdicts.
  Ship atomic checkpointing, interruption recovery, invalidation/repair telemetry
  and actual consuming-stage tests with every reuse or retained-format change.
- Existing validators and miners must not be stopped or replaced for a cleanup.
  Test changes in an isolated workspace before any separately qualified deployment.
- Clean up task-created remote build/test/rehearsal directories after use. Check
  process, service, configuration, symlink, and environment dependencies first.
  Preserve wallets, private data, model assets, and recovery state. Never delete
  by a broad home-directory glob. Report retained dependencies and cleanup results.
