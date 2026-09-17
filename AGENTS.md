# Maintenance

- Keep command entry points separate from policy, pure calculations, and I/O.
  Use explicit imports and typed boundaries; do not add runtime import tricks to
  preserve an oversized module.
- Refactors must preserve signed bytes, published schemas, command arguments,
  and durable journal semantics. Test historical inputs and failure paths.
- Existing validators and miners must not be stopped or replaced for a cleanup.
  Test changes in an isolated workspace before any separately qualified deployment.
- Clean up task-created remote build/test/rehearsal directories after use. Check
  process, service, configuration, symlink, and environment dependencies first.
  Preserve wallets, private data, model assets, and recovery state. Never delete
  by a broad home-directory glob. Report retained dependencies and cleanup results.
