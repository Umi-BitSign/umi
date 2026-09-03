# Vendored finality dependencies

These crates are vendored because the UMI finality observer needs two narrowly
scoped bootstrap interfaces that are not available in the published releases.
Their source remains governed by the upstream licenses copied into each crate
directory. The repository's root Apache-2.0 license does **not** relicense these
vendored files.

## `smoldot` 2.2.0

- Upstream: <https://github.com/paritytech/smoldot>
- Upstream revision: `90e94869a7fbd617d28990da3005eaa906bc3862`
- crates.io archive SHA-256:
  `7998fa4206a99d310bd288df99300724da1d7800f06b64387e431d9cd0d870f1`
- License: `GPL-3.0-or-later WITH Classpath-exception-2.0`; exact upstream
  `LICENSE` copied into `smoldot-2.2.0/`.
- Changed file: `src/chain/chain_information/build.rs`.
- Patch: when a proof-verified non-genesis finalized header is available and a
  runtime advertises both Aura and Babe APIs, select an engine only when the
  header contains exactly one corresponding pre-runtime digest. Ambiguous or
  unrecognized headers retain upstream's fail-closed behavior. This is required
  by Finney, whose current runtime advertises both APIs while finalized headers
  use Aura.

## `smoldot-light` 1.3.2

- Upstream: <https://github.com/paritytech/smoldot>
- Upstream revision: `5fe9121f81a58454542ac69a44c4d73f00f30283`
- crates.io archive SHA-256:
  `f5ae693a7dec686bb80f97a78e42bf96aec196776dba8b2ab11b16445c7268f1`
- License: `GPL-3.0-or-later WITH Classpath-exception-2.0`; exact upstream
  `LICENSE` copied into `smoldot-light-1.3.2/`.
- Changed files: `src/lib.rs`, `Cargo.toml`, and `Cargo.toml.orig`.
- Bootstrap patch: allow a genesis-matched serialized database to provide initial chain
  information when the chain specification has no legacy `lightSyncState`, and
  return typed evidence stating whether the database was selected plus the exact
  initial finalized number and hash.
- Dependency patch: pin `lru` 0.18.4 in place of the upstream 0.16 line. This
  removes RUSTSEC-2026-0253 from the locked dependency graph. The affected
  upstream code did not call the vulnerable `LruCache::pop` method, but the
  observer does not rely on that reachability argument for its release audit.

## `subxt-lightclient` 0.50.3

- Upstream: <https://github.com/paritytech/subxt>
- Upstream revision: `49ea25dcf81a6c764ed6d341679211a396191cc8`
- crates.io archive SHA-256:
  `8154466fec781c4466fc4489bbab172859af689a99a2ccfd2ac5a55c8fbdfb8b`
- License: upstream's `Apache-2.0 OR GPL-3.0`; exact upstream `LICENSE`
  copied into `subxt-lightclient-0.50.3/`. UMI consumes it under Apache-2.0.
- Changed file: `src/lib.rs`.
- Patch: accept an explicit serialized database and expected checkpoint, require
  smoldot to report that the database was selected at that exact number and hash,
  and return a typed `VerifiedDatabaseBootstrap` receipt.

The observer's build script hashes every file below this directory, including
this record and the license files, and refuses to build if the reviewed vendor
tree changes. The release policy separately hashes all root build inputs and the
same complete vendor tree.
