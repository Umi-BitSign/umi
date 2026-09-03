# Third-party notices

Most UMI-authored source is licensed under Apache License 2.0 as stated in the
root `LICENSE` file. The vendored finality dependencies below retain their
upstream licenses. The root license does not relicense those directories.

## smoldot 2.2.0

UMI includes a modified copy of `smoldot` 2.2.0 from Parity Technologies at
upstream revision `90e94869a7fbd617d28990da3005eaa906bc3862`. It is licensed
under GPL-3.0-or-later WITH Classpath-exception-2.0. The source, local patch
description, provenance, and exact license are retained under
`rust/grandpa-finality-observer/vendor/smoldot-2.2.0/`.

## smoldot-light 1.3.2

UMI includes a modified copy of `smoldot-light` 1.3.2 from Parity Technologies
at upstream revision `5fe9121f81a58454542ac69a44c4d73f00f30283`. It is licensed
under GPL-3.0-or-later WITH Classpath-exception-2.0. The source, local patch
description, provenance, and exact license are retained under
`rust/grandpa-finality-observer/vendor/smoldot-light-1.3.2/`.

## subxt-lightclient 0.50.3

UMI includes a modified copy of `subxt-lightclient` 0.50.3 from Parity
Technologies at upstream revision
`49ea25dcf81a6c764ed6d341679211a396191cc8`. Upstream offers it under
Apache-2.0 OR GPL-3.0; UMI uses the Apache-2.0 option. The source, local patch
description, provenance, and exact license are retained under
`rust/grandpa-finality-observer/vendor/subxt-lightclient-0.50.3/`.

The complete patch record and upstream archive hashes are in
`rust/grandpa-finality-observer/vendor/PATCHES.md`. Anyone distributing a built
finality-observer binary must distribute the applicable notices and source in
the form required by those licenses.

## Generated Rust binary license closures

Each signed inactive release carries `storage_proof_license_closure` and
`finality_license_closure` artifacts generated from the target-resolved locked
Cargo graphs. These archives enumerate every resolved package and retain the
license and notice material collected for binary distribution. Release generation
fails when a package has no license declaration, uses an unreviewed expression, or
lacks material for a declared license ID.

The proof verifier uses packages from the RaoFoundation `polkadot-sdk` fork at
commit `cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a`. Its license closure includes
the fork's `substrate/LICENSE-APACHE2`. The release source archive contains the UMI
proof-verifier source and `Cargo.lock`; the pinned SDK and crates.io dependency
sources are fetched from their recorded Git revision and lockfile checksums when a
rebuild is required.
