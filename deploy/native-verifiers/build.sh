#!/bin/sh
# Shared by the bridge and competition images. Sources retain their repo layout.
set -eu

test "$#" -gt 0
for crate in "$@"; do
  case "$crate" in
    grandpa-finality-observer|substrate-proof-verifier|runtime-metadata) ;;
    *) echo "unknown native verifier: $crate" >&2; exit 2 ;;
  esac
done

export CARGO_TARGET_DIR=/build/target
for crate in "$@"; do
  manifest="/build/rust/$crate/Cargo.toml"
  if test "$crate" != grandpa-finality-observer; then
    cargo +1.98.0 test --locked --release --manifest-path "$manifest"
  fi
  cargo +1.98.0 build --locked --release --manifest-path "$manifest"
  install -Dm0555 "/build/target/release/umi-$crate" "/build/bin/umi-$crate"
  if test "$crate" = grandpa-finality-observer; then
    /build/bin/umi-grandpa-finality-observer --conformance-self-test
  fi
done
