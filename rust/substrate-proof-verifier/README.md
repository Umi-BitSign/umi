# UMI Substrate proof verifier

This helper verifies Substrate state proof membership and non-membership against an
explicit finalized header state root. It is intentionally separate from Python so
the consensus-critical trie implementation is the same `sp-trie` revision used by
the pinned Subtensor runtime.

Build and fingerprint it before configuring a validator:

```sh
cargo build --locked --release --manifest-path rust/substrate-proof-verifier/Cargo.toml
shasum -a 256 rust/substrate-proof-verifier/target/release/umi-substrate-proof-verifier
```

The binary accepts newline-delimited JSON on stdin and emits exactly one compact
JSON response per line. A single request followed by EOF is the one-shot mode.

Request schema:

```json
{"schema":"umi-substrate-proof/1","request_id":"opaque","state_version":1,"state_root":"0x...","items":[{"key":"0x...","value":"0x..."}],"proof":["0x..."]}
```

The same binary verifies the ordered extrinsics trie root from a finalized
header. This request is independent of storage-proof verification:

```json
{"schema":"umi-substrate-extrinsics-root/1","request_id":"opaque","state_version":1,"expected_root":"0x...","extrinsics":["0x..."]}
```

Use `null` for `value` to prove non-membership. Items must be unique and ordered by
their decoded key bytes. Hex is lowercase and `0x`-prefixed. The verifier rejects
unknown JSON fields, duplicate proof nodes, state versions other than 1, oversized
inputs, invalid proofs, and mismatched ordered extrinsics roots. It writes no
diagnostic material to stdout.

The `proof` array is the raw node list returned by Substrate
`state_getReadProof`, not the compact path-proof encoding produced by
`sp_trie::generate_trie_proof`. The checked-in `finney-state-v1.json` fixture is a
public state-version-1 proof for the Aura authority set at Finney's official
GRANDPA warp checkpoint. Tests verify the original proof and reject changed
values, missing nodes, and modified nodes.

The Python adapter requires an absolute binary path and its expected SHA-256. Keep
the release binary and `Cargo.lock` together as activation artifacts.

The `sp-core` and `sp-trie` sources are pinned to Polkadot SDK revision
`cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a`, the revision selected by Subtensor
`da06f033663896ef2fdbbfc3ecc68ca908fba0f5` (runtime spec 452 at implementation
time). `Cargo.lock` fixes every remaining dependency.
