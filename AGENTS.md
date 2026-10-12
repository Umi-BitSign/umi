# Maintenance

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
- Existing validators and miners must not be stopped or replaced for a cleanup.
  Test changes in an isolated workspace before any separately qualified deployment.
- Clean up task-created remote build/test/rehearsal directories after use. Check
  process, service, configuration, symlink, and environment dependencies first.
  Preserve wallets, private data, model assets, and recovery state. Never delete
  by a broad home-directory glob. Report retained dependencies and cleanup results.
