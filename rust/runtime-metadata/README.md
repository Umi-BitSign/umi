# Proof-backed runtime metadata

This read-only helper executes `Metadata_metadata` from runtime Wasm. The Python
adapter requires a verified `:code` membership proof at the requested snapshot,
hash-checks and privately stages the helper, then checks its output before
constructing a Bittensor codec. RPC metadata is not an input.

The helper uses the existing vendored smoldot interpreter. It services no
storage, network, clock, offchain or signature host requests. Unresolved imports
may exist but trap if called. Output must be one canonical SCALE byte vector
with the metadata magic prefix. Runtime versions come from the Wasm.

Bounds: 8 MiB input, 16 MiB metadata, 2 GiB address space, 40 CPU seconds,
32 file descriptors, no core dumps. The Python adapter additionally enforces a
15-second wall timeout by default (maximum 45). Failure to install the OS limits
is fatal. Linux is the deployment target; macOS can reject its address-space
limit and is not a supported execution environment for this helper.

Build and test:

```sh
cargo test --locked --manifest-path rust/runtime-metadata/Cargo.toml
cargo build --release --locked --manifest-path rust/runtime-metadata/Cargo.toml
```

This does not activate runtime-independent signing. The resulting context has
mode `executed_runtime/1`; the existing weight transport rejects it. Integration
still needs a signed executor pin, proof-backed collection at the current owned
header, retained execution evidence, release packaging and transaction replay
tests. No current policy or validator service changes when this helper is built.
