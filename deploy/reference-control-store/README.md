# Reference control storage

This Worker gives the reference publication owner bounded, authenticated access
to public R2 control objects. `CONTROL` binds `umi-public-evidence`;
`PUBLICATION_TOKEN` is a separate private transport credential. It never loads a
chain signer, interprets certification, or deletes objects. Only the two common
platform cursor namespaces and immutable reference approvals are allowed.
Every PUT requires an R2 atomic condition. Approval writes also require the exact
body SHA256, and only conditional creation is supported.

The Python publisher selects this transport with configuration version2. Keep
operator setup in [the upgrade guide](../../docs/validators/successor-upgrade.md).
Deploying this Worker does not select a directive or activate validator weights.
Run `npm test` under Node22 or later. Local tests use synthetic storage; qualify
actual public R2 conditions, competing writers, independent readback and cleanup
before selection.
