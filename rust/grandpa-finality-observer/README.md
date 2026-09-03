# UMI GRANDPA finality observer

This sidecar runs an embedded smoldot light client against the bootnodes in a
hash-pinned Substrate chain specification. It accepts no RPC URL. The client
checks the governed checkpoint, warp-sync proofs, GRANDPA finality, headers, and
proof-backed runtime reads before the sidecar emits a record.

The output is a `verifier_attested_finality` record. It is not a portable
offline proof: the public smoldot light-client API reports verified finalized
headers but does not expose the GRANDPA commit or warp proof that established
them. Reproduction therefore requires the pinned sidecar binary and a live peer
path. Audit consumers must not relabel these records as self-contained GRANDPA
proofs.

Attestations and the supervisor's acceptance receipts are unsigned. Their hash
chains detect changes relative to a retained run, but anyone can fabricate a new
offline chain. They are replay artifacts, not an independent finality root of
trust. Activation evidence must be captured directly from an invocation of the
exact hash-pinned sidecar over its peer-to-peer path; signing the same output with
a sidecar-local key would add no independent authority.

The process reads one canonical JSON configuration from standard input, closes
the input protocol after that object, and writes RFC 8785 JSON records one per
line to standard output. Bounded diagnostics go only to standard error. It exits
on rollback, a post-baseline ancestry gap, a chain-spec, checkpoint, or genesis
mismatch, a timestamp failure, or any configured limit.

## Security model and bootstrap

Version 0.1 accepts exactly one bootstrap class:
`grandpa_warp_sync_checkpoint`. It rejects genesis fallback, legacy
`lightSyncState`, an ambiguous specification containing both profiles, and a
minimum requested height that does not advance beyond the checkpoint.

The governed Finney input is the official raw specification from subtensor
revision `da06f033663896ef2fdbbfc3ecc68ca908fba0f5`:

- source: [`chainspecs/raw_spec_finney.json`](https://github.com/opentensor/subtensor/blob/da06f033663896ef2fdbbfc3ecc68ca908fba0f5/chainspecs/raw_spec_finney.json);

- chain-spec SHA-256:
  `f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105`;
- genesis hash:
  `0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03`;
- checkpoint block: `8,867,448`;
- checkpoint hash:
  `0x511948e96e1d479d0a92d89bb976638780f2c65a93a5d5be710f22ee15c60200`;
- signing GRANDPA set: set ID 5 with 20 nonzero, unique authorities;
- generated smoldot database SHA-256:
  `44f1db866965c849184a1bb2b625f03958311a8a65a18a7b0a94587c97766763`.

The observer decodes the checkpoint header and authority bytes, requires the
exact number and hash, applies the header's immediate Aura and GRANDPA authority
changes, and generates the database deterministically. Patched smoldot returns a
typed receipt proving that this exact database checkpoint was selected. Every
attestation binds `bootstrap_source: "grandpa_checkpoint"`,
`bootstrap_selected: true`, and the exact first verified finalized head. The
first emitted block and startup head must be above the checkpoint.

Trust in this policy-selected checkpoint and its authority set is an explicit
weak-subjectivity assumption. An operator cannot substitute another checkpoint
without a new scoring-policy hash. From that point forward, smoldot verifies the
peer-supplied warp and GRANDPA data; no remote RPC's `finalized` label is used.
RPC storage values are separate inputs and become authoritative only after a
LayoutV1 trie proof binds them to an observer-attested state root.

## Production pins

The version 0.1 build uses Rust 1.98.0 and these reviewed upstream revisions:

- `subxt-lightclient` 0.50.3 at
  `49ea25dcf81a6c764ed6d341679211a396191cc8`;
- `smoldot-light` 1.3.2 at
  `5fe9121f81a58454542ac69a44c4d73f00f30283`;
- `smoldot` 2.2.0 at
  `90e94869a7fbd617d28990da3005eaa906bc3862`.

The vendored `smoldot-light` manifest pins `lru` 0.18.4 instead of its upstream
0.16 line, removing RUSTSEC-2026-0253 from the locked graph.

The narrow local patches, upstream archive checksums, and redistribution terms
are recorded in `vendor/PATCHES.md`. The complete vendored tree, including
license files and provenance, has build-time SHA-256
`6ebb7bb6f4c5bbf559fe09e27996382eb44ff81e0b68105cb7755a5ca56d37be`.
The root Apache-2.0 license does not relicense the vendored smoldot code.

Current artifact pins are:

- `Cargo.lock` SHA-256:
  `9d6ba175a232ddb051c0ce795dc500562b05b48f57bb29a33344aad1eef87f8c`;
- `fixtures/finality-v1.json` SHA-256:
  `b5522352dc04cbd88eb7916ba95e65330c89915619e292f3512ed3acebd11655`;
- `fixtures/finney-grandpa-checkpoint-v1.json` SHA-256:
  `b3f2191587a21b57fbe9f56e3a8245e852c06cdebb0a4dd0b878a5242d9a8311`;
- source-tree SHA-256:
  `3bd630238cdc042572999b5058fadc63f6ca51ea7835b0f42023793a7abc0002`;
- `aarch64-apple-darwin` release binary SHA-256:
  `7ab05980889a64657365dda53a3288be90ef720c914dc0f786a020f174b0270e`.

The source-tree digest starts with
`umi-grandpa-finality-observer-source-v1\0`. It then covers, in bytewise sorted
relative-path order, `Cargo.toml`, `build.rs`, `rust-toolchain.toml`, every file
below `src/` and `vendor/`, and every file below `.cargo/` when that directory
exists. Each entry is
`U32BE(path_length) || UTF8(path) || SHA256(file_bytes)`. `Cargo.lock`, the
fixture set, chain specification, and release binaries have separate policy
pins. The build script independently refuses any change to the complete vendor
tree or the checkpoint fixture.

The profile-specific `FinalityVerifierPin` has this shape:

```json
{
  "profile": "smoldot-verifier-attested-finality/1",
  "evidence_class": "verifier_attested_finality",
  "offline_finality_proof": false,
  "source_revision": "pinned-upstream-revisions-and-local-patches",
  "source_tree_sha256": "hex-encoded-sha256",
  "cargo_lock_sha256": "hex-encoded-sha256",
  "finality_fixture_set_sha256": "hex-encoded-sha256",
  "release_sha256_by_target": {"target-triple": "hex-encoded-sha256"},
  "chain_spec_source_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
  "chain_spec_sha256": "f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105",
  "expected_genesis_hash": "2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
  "bootstrap_kind": "grandpa_warp_sync_checkpoint",
  "bootstrap_block_number": 8867448,
  "bootstrap_block_hash": "511948e96e1d479d0a92d89bb976638780f2c65a93a5d5be710f22ee15c60200"
}
```
