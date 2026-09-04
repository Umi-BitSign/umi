# Build an inactive live-shadow release

`umi-shadow-release` stages a target-bound public release for SN78 calibration.
Every output fixes `translation_weights_active` to `false`. The command has no
wallet, signature-generation, extrinsic, broadcast, or weight-submission
capability.

The public directory contains every UMI executable and configuration byte selected
for one primary validator `target_triple`. Its wheel, repository-exact lockfile, pinned `uv`
binary and provenance, FFmpeg and FFprobe binaries, Rust verifier binaries, Finney
chain spec, runtime metadata, fixture sets, validator-capacity set, cost schedule,
mirror rule, and control disclosures are copied under
`artifacts/sha256/<digest>/`. The same tree includes deterministic source archives
for both Rust binaries, target-resolved Rust license closures, the media-runtime
license and corresponding-source bundles, the vendored finality patches and license
files, the root `LICENSE`, and `THIRD_PARTY_NOTICES.md`. An operator does not need
the builder's source paths after emission. Python and locked Python packages are
installed from their signed metadata and are not claimed to be bundled for offline
installation. An optional `aarch64-apple-darwin` miner target adds only a native
finality observer, its build report and license closure, and a signed miner
template. It does not add a Darwin validator or media runtime.

Operator documentation is deliberately outside the wheel and signed runtime
artifact tree. The manifest records both the exact 40-character UMI Git commit
and the source-tree digest. Release preparation refuses a dirty repository,
untracked source or documentation files, and a source tree whose repository root
does not match the running builder. Publish the Git tag or commit named by
`umi_git_revision` alongside the release so operators can obtain these instructions
from that revision. A working-tree copy is not evidence for the recorded release
revision.

The production media profile is deliberately narrower than “whatever FFmpeg is on
the build host.” A release accepts only an explicitly supported Linux target and
static ELF FFmpeg/FFprobe files with no `PT_INTERP` or `PT_DYNAMIC` segment. A
canonical `umi-media-runtime-closure/1` manifest binds their target, hashes,
version, complete configure flags, license expression, reviewed redistribution
status, license bundle, and corresponding-source bundle. Homebrew, apt, and other
host-shared FFmpeg installations are useful for development but are rejected as
release inputs. Each target release must pass verification and conformance on a
clean machine or image of that exact target before publication.

The fixture files are inputs, not claims of success. Release construction executes
all 34 required cases across normalization, media, timelock, chain, live-chain,
storage-proof, and finality fixtures. It writes the canonical execution report into
the signed release and pins that report's SHA-256 in the scoring policy. The
installed-release verifier and live validator startup each execute the same cases
again from the exact packaged fixtures and binaries and require byte-for-byte report
reproduction.

The workflow uses two live observations:

1. A capacity-signing observation fixes the block and block hash in the three
   publisher capacity statements.
2. A fresh release observation is captured while staging the final public
   release.

Both observations are collected in the command invocation that uses them. The
command starts the exact hash-pinned smoldot sidecar over its Finney peer-to-peer
path, then verifies node-supplied storage values against that finalized header's
state root with the pinned trie-proof helper. Saved attestations and proofs are
replay artifacts only; supplying their bytes does not authorize a release.

A dedicated release authority signs twice. It first signs the static release
intent after all three publisher capacity signatures are present. That intent
covers the policy and every static public file by path, byte length, and SHA-256.
After the fresh release observation is captured, the authority signs a second,
domain-separated digest of the exact unsigned manifest. That signature binds the
live observation and every packaged byte. Operators must obtain the expected
release-authority hotkey through a channel they already trust. The hotkey copied
into the release manifest is not a trust root by itself.

## Prerequisites

Install the locked environment and build the two Rust release binaries for the
host named by `target_triple`. Gather all absolute artifact paths required by
`LiveShadowReleaseInput` in `src/umi/shadow_release.py`, including:

- a wheel whose `umi/*.py` bytes exactly match the current source tree;
- the repository's exact `uv.lock` bytes, the pinned target-specific `uv` binary,
  its upstream license file, and canonical `umi-uv-tool-provenance/1` record;
- the target-specific static FFmpeg and FFprobe pair, canonical
  `umi-media-runtime-closure/1` record, license bundle, corresponding-source
  bundle, runtime metadata, all fixture sets, and the Finney chain spec;
- the validator-capacity set, common cost schedule, mirror-discovery rule, and
  three control-disclosure documents;
- four secret-free validator template entries;
- exactly three registered publishers in three control groups, with the claimed
  owners and collateral already present on chain; and
- a dedicated release-authority hotkey whose private key is available to an
  external signing tool, never to `umi-shadow-release`.

To include an Apple Silicon miner, first create the native artifact on that host
with `umi-miner-finality-artifact`, then transfer its three immutable files to the
release builder. Record the three emitted SHA-256 values and confirm them through a
separate trusted channel. Add the files and those expected digests through the
top-level `miner_finality_targets` input before any publisher or release-authority
signature is collected. The exact workflow and schema are in [the macOS miner
operator guide](MACOS_MINER_OPERATOR.md).

Release preparation runs `cargo +1.98.0 metadata --locked --offline` for the target
triple and derives one deterministic license archive for each Rust binary. Every
resolved package must match its `Cargo.lock` identity, source, and crates.io
checksum. Each package must declare one reviewed license expression. Missing and
unrecognized expressions stop the release. The archive contains package-to-license
mappings, every license or notice file shipped beside a resolved package, and one
identified text for every license ID in the graph.

The RaoFoundation `polkadot-sdk` packages are accepted only from commit
`cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a` with a clean tracked checkout. Their
shared `substrate/LICENSE-APACHE2` is included in the proof-verifier license
closure. The proof-verifier source archive contains the UMI crate source and lock,
while its transitive crates.io and RaoFoundation sources remain reproducible from
the recorded checksums and pinned Git commit over the network. It is not an offline
vendor archive of the full SDK.

The builder rejects a copied or regenerated lockfile unless its bytes exactly equal
the repository `uv.lock`, every non-project package comes from the canonical PyPI
registry with hashed `files.pythonhosted.org` artifacts, and the packaged `uv`
binary reports version `0.12.9` and passes `uv lock --check --offline`. It invokes
that packaged binary directly; no ambient `uv` or pip-installed bootstrap tool
participates in release validation.

### Prepare the pinned uv artifacts

Release targets are deliberately limited to `aarch64-unknown-linux-musl` and
`x86_64-unknown-linux-musl`. Build and stage a release on a clean Linux host of the
same architecture; do not use Rosetta, QEMU user emulation, or a macOS target for
the signed conformance run. The official uv 0.12.9 archive hashes are:

| Target | Archive SHA-256 | Extracted `uv` SHA-256 |
|---|---|---|
| `aarch64-unknown-linux-musl` | `7eb9bf48516448c9db6a9e436d8e747ac9c8a9cac74717160a29918249b080a6` | `8353b259b2486ab011aae51f8815f88b41648e2ee8fe68494a8379b9f59377c8` |
| `x86_64-unknown-linux-musl` | `aa4b1f8770910f7c7c543c7acc980e4270e52e70750c996acef813ea1c7c2912` | `308d3841102bffca4acfe799e726db08846ee35f7408762a02349c42d1ba0a09` |

The common `source.tar.gz` SHA-256 is
`2523396a64a6a1ea358aff5b3d23acd5e371ee6b38013750d9de5648491fbd4a`.
The SHA-256 of the combined `uv-LICENSE` bytes produced by the command below is
`01b9a628dce02323aaa1e263192edc7368c19572471b7c035c673ec6205f724f`.
Select exactly one row, then fetch and extract it as follows. `INPUTS` must already
be an empty private directory retained with the release work papers:

```bash
INPUTS=/absolute/path/to/release-inputs
TARGET=x86_64-unknown-linux-musl
UV_ARCHIVE_SHA256=aa4b1f8770910f7c7c543c7acc980e4270e52e70750c996acef813ea1c7c2912
UV_SOURCE_SHA256=2523396a64a6a1ea358aff5b3d23acd5e371ee6b38013750d9de5648491fbd4a
UV_LICENSE_SHA256=01b9a628dce02323aaa1e263192edc7368c19572471b7c035c673ec6205f724f
UV_BASE=https://github.com/astral-sh/uv/releases/download/0.12.9

mkdir -m 0700 "$INPUTS/uv-extract" "$INPUTS/uv-source"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$INPUTS/uv-$TARGET.tar.gz" "$UV_BASE/uv-$TARGET.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$INPUTS/uv-source.tar.gz" "$UV_BASE/source.tar.gz"
printf '%s  %s\n' "$UV_ARCHIVE_SHA256" "$INPUTS/uv-$TARGET.tar.gz" | sha256sum --check
printf '%s  %s\n' "$UV_SOURCE_SHA256" "$INPUTS/uv-source.tar.gz" | sha256sum --check
tar --extract --gzip --file "$INPUTS/uv-$TARGET.tar.gz" \
  --strip-components=1 --directory "$INPUTS/uv-extract"
tar --extract --gzip --file "$INPUTS/uv-source.tar.gz" \
  --strip-components=1 --directory "$INPUTS/uv-source"
install -m 0500 "$INPUTS/uv-extract/uv" "$INPUTS/uv"
{
  printf '%s\n' '===== LICENSE-APACHE ====='
  sed -n '1,$p' "$INPUTS/uv-source/LICENSE-APACHE"
  printf '%s\n' '===== LICENSE-MIT ====='
  sed -n '1,$p' "$INPUTS/uv-source/LICENSE-MIT"
} > "$INPUTS/uv-LICENSE"
chmod 0400 "$INPUTS/uv-LICENSE"
printf '%s  %s\n' "$UV_LICENSE_SHA256" "$INPUTS/uv-LICENSE" | sha256sum --check
"$INPUTS/uv" --version
sha256sum "$INPUTS/uv"
```

The version command must identify `uv 0.12.9`; the official detailed form also
names the commit date and selected target triple. The builder rejects another
semantic version, a detailed form naming another target, or an extracted binary,
binary archive, or source archive whose hash differs from the hard-coded reviewed
values above. Generate the canonical provenance record from the bytes just verified:

```bash
python - "$INPUTS" "$TARGET" "$UV_ARCHIVE_SHA256" "$UV_SOURCE_SHA256" <<'PY'
import hashlib
import sys
from pathlib import Path

from umi.protocol import canonical_json_bytes

root = Path(sys.argv[1])
target, binary_archive_sha256, source_archive_sha256 = sys.argv[2:]
base = "https://github.com/astral-sh/uv/releases/download/0.12.9"
record = {
    "binary_archive_sha256": binary_archive_sha256,
    "binary_archive_url": f"{base}/uv-{target}.tar.gz",
    "binary_sha256": hashlib.sha256((root / "uv").read_bytes()).hexdigest(),
    "license_expression": "Apache-2.0 OR MIT",
    "license_sha256": hashlib.sha256((root / "uv-LICENSE").read_bytes()).hexdigest(),
    "schema": "umi-uv-tool-provenance/1",
    "source_archive_sha256": source_archive_sha256,
    "source_archive_url": f"{base}/source.tar.gz",
    "target_triple": target,
    "tool": "uv",
    "version": "0.12.9",
}
path = root / "uv-provenance.json"
path.write_bytes(canonical_json_bytes(record))
path.chmod(0o400)
PY
```

Name those three output paths as `artifacts.uv_binary`, `artifacts.uv_license`,
and `artifacts.uv_provenance` in the release descriptor. Retain the downloaded
archives and the independently obtained release checksum list for authority review;
they are provenance work papers, not installed runtime files.

Build both Rust sidecars for the same musl target with the repository-pinned
toolchain and locks, then use those target paths in the descriptor:

```bash
rustup toolchain install 1.98.0 --profile minimal
rustup target add --toolchain 1.98.0 "$TARGET"
cargo +1.98.0 build --locked --release --target "$TARGET" \
  --manifest-path rust/substrate-proof-verifier/Cargo.toml
cargo +1.98.0 build --locked --release --target "$TARGET" \
  --manifest-path rust/grandpa-finality-observer/Cargo.toml
```

The target's musl C compiler/linker must be present. Copy the resulting binaries
from each crate's `target/$TARGET/release/` directory and verify they execute on the
clean target host before starting release preparation.

### Prepare the static media-runtime closure

The initial reviewed recipe uses unmodified FFmpeg 8.0.1 source from
`https://ffmpeg.org/releases/ffmpeg-8.0.1.tar.xz`, whose SHA-256 is
`05ee0b03119b45c0bdb4df654b96802e909e0a752f72e4fe3794f487229e5a41`.
Run this on the same native-target clean musl Linux builder used for release
staging. Install a C toolchain, `make`, `pkgconf`, `perl`, `xz`, and `binutils` from
that builder's locked image before starting, and record the image digest and exact
package versions in `BUILD.md`.

```bash
FFMPEG_VERSION=8.0.1
FFMPEG_SOURCE_SHA256=05ee0b03119b45c0bdb4df654b96802e909e0a752f72e4fe3794f487229e5a41
FFMPEG_CONFIG='--disable-shared --enable-static --disable-autodetect --disable-doc --disable-debug --disable-network --disable-everything --enable-ffmpeg --enable-ffprobe --enable-avcodec --enable-avformat --enable-avutil --enable-avfilter --enable-swscale --enable-decoder=h264 --enable-encoder=rawvideo --enable-demuxer=mov --enable-muxer=rawvideo --enable-parser=h264 --enable-filter=format --enable-filter=scale --enable-protocol=file --enable-protocol=pipe --extra-cflags=-static --extra-ldflags=-static'

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$INPUTS/ffmpeg-$FFMPEG_VERSION.tar.xz" \
  "https://ffmpeg.org/releases/ffmpeg-$FFMPEG_VERSION.tar.xz"
printf '%s  %s\n' "$FFMPEG_SOURCE_SHA256" \
  "$INPUTS/ffmpeg-$FFMPEG_VERSION.tar.xz" | sha256sum --check
mkdir -m 0700 "$INPUTS/ffmpeg-source"
tar --extract --xz --file "$INPUTS/ffmpeg-$FFMPEG_VERSION.tar.xz" \
  --strip-components=1 --directory "$INPUTS/ffmpeg-source"
cd "$INPUTS/ffmpeg-source"
./configure $FFMPEG_CONFIG
make -j1 ffmpeg ffprobe
install -m 0500 ffmpeg ffprobe "$INPUTS/"
readelf --program-headers --wide "$INPUTS/ffmpeg" | \
  awk '/INTERP|DYNAMIC/ { bad=1 } END { exit bad }'
readelf --program-headers --wide "$INPUTS/ffprobe" | \
  awk '/INTERP|DYNAMIC/ { bad=1 } END { exit bad }'
```

Do not add `--enable-gpl`, `--enable-nonfree`, an external codec, or any other
configure flag without a new license review and a complete source/license update.
Create a nonempty `BUILD.md` containing the target, clean builder image digest,
package versions, source URL and hash, the exact configure string above, compiler
and linker versions, and commands. Create `DEPENDENCIES.md` identifying every
statically linked component and its license. The release authority must review
those records and the actual obligations before setting `redistribution_reviewed`
to true; this flag is an attestation, not an automated legal conclusion.

Build two deterministic ZIP files with no directory or symlink entries:

- `media-runtime-source.zip` contains `BUILD.md`,
  `SOURCES/ffmpeg-8.0.1.tar.xz`, any other corresponding source under `SOURCES/`,
  and `SOURCE-MANIFEST.sha256`. The manifest is the lexically sorted set of every
  `SOURCES/` member as `<sha256><two spaces><path><newline>`.
- `media-runtime-licenses.zip` contains nonempty `LICENSES/FFmpeg.txt` (FFmpeg's
  `LICENSE.md` and applicable license text), `LICENSES/DEPENDENCIES.md`, and the
  applicable license text for every listed static dependency.

Generate `umi-media-runtime-closure/1` with RFC 8785 canonical JSON. It has exactly
these fields: `schema`, `profile` (`target-bound-static-elf-media-runtime/1`),
`target_triple`, `ffmpeg_binary_sha256`, `ffprobe_binary_sha256`,
`ffmpeg_version`, `ffmpeg_configuration`, `linkage`
(`static-elf-without-pt-interp-or-pt-dynamic`), `runtime_dependencies` (the empty
array), `license_expression`, `license_bundle_sha256`,
`corresponding_source_bundle_sha256`, and `redistribution_reviewed` (`true` only
after review). Name the five paths as `artifacts.ffmpeg_binary`,
`artifacts.ffprobe_binary`, `artifacts.media_runtime_manifest`,
`artifacts.media_runtime_license_bundle`, and
`artifacts.media_runtime_source_bundle`. The release builder independently checks
the target ELF machine, absence of dynamic/interpreter segments, all hashes,
required ZIP members, and the complete source manifest before executing media
conformance.

The following bounded packager produces all three files after the work papers and
license review exist. Put the FFmpeg archive and every additional corresponding
source archive in `$INPUTS/corresponding-sources`; put each additional license text
in `$INPUTS/dependency-licenses`. Neither directory may contain symlinks or nested
directories. Set the aggregate SPDX expression determined by the review, not an
optimistic placeholder:

```bash
mkdir -m 0700 "$INPUTS/corresponding-sources" "$INPUTS/dependency-licenses"
cp "$INPUTS/ffmpeg-8.0.1.tar.xz" "$INPUTS/corresponding-sources/"
MEDIA_LICENSE_EXPRESSION='reviewed SPDX expression for the complete static binary'

python - "$INPUTS" "$TARGET" "$FFMPEG_CONFIG" "$MEDIA_LICENSE_EXPRESSION" <<'PY'
import hashlib
import io
import sys
import zipfile
from pathlib import Path

from umi.protocol import canonical_json_bytes

root = Path(sys.argv[1]).resolve(strict=True)
target, configuration, license_expression = sys.argv[2:]
source_root = (root / "corresponding-sources").resolve(strict=True)
license_root = (root / "dependency-licenses").resolve(strict=True)


def flat_files(directory: Path) -> list[Path]:
    files = sorted(directory.iterdir(), key=lambda item: item.name)
    if not files or any(not item.is_file() or item.is_symlink() for item in files):
        raise SystemExit(f"{directory} must contain only nonempty regular files")
    if any(not item.read_bytes() for item in files):
        raise SystemExit(f"{directory} contains an empty file")
    return files


def deterministic_zip(path: Path, members: dict[str, bytes]) -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in sorted(members.items()):
            if not payload:
                raise SystemExit(f"empty archive member: {name}")
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100444 << 16
            archive.writestr(info, payload)
    path.write_bytes(stream.getvalue())
    path.chmod(0o400)


build = (root / "BUILD.md").read_bytes()
dependencies = (root / "DEPENDENCIES.md").read_bytes()
if not build or not dependencies:
    raise SystemExit("BUILD.md and DEPENDENCIES.md must be nonempty")

source_members = {
    f"SOURCES/{item.name}": item.read_bytes() for item in flat_files(source_root)
}
source_manifest = "".join(
    f"{hashlib.sha256(source_members[name]).hexdigest()}  {name}\n"
    for name in sorted(source_members)
).encode("ascii")
source_members.update({"BUILD.md": build, "SOURCE-MANIFEST.sha256": source_manifest})
source_bundle = root / "media-runtime-source.zip"
deterministic_zip(source_bundle, source_members)

ffmpeg_license = b"\n".join(
    [
        (root / "ffmpeg-source" / "LICENSE.md").read_bytes(),
        (root / "ffmpeg-source" / "COPYING.LGPLv2.1").read_bytes(),
    ]
)
license_members = {
    "LICENSES/FFmpeg.txt": ffmpeg_license,
    "LICENSES/DEPENDENCIES.md": dependencies,
    **{
        f"LICENSES/{item.name}": item.read_bytes()
        for item in flat_files(license_root)
    },
}
license_bundle = root / "media-runtime-licenses.zip"
deterministic_zip(license_bundle, license_members)

ffmpeg = (root / "ffmpeg").read_bytes()
ffprobe = (root / "ffprobe").read_bytes()
record = {
    "corresponding_source_bundle_sha256": hashlib.sha256(
        source_bundle.read_bytes()
    ).hexdigest(),
    "ffmpeg_binary_sha256": hashlib.sha256(ffmpeg).hexdigest(),
    "ffmpeg_configuration": configuration,
    "ffmpeg_version": "8.0.1",
    "ffprobe_binary_sha256": hashlib.sha256(ffprobe).hexdigest(),
    "license_bundle_sha256": hashlib.sha256(license_bundle.read_bytes()).hexdigest(),
    "license_expression": license_expression,
    "linkage": "static-elf-without-pt-interp-or-pt-dynamic",
    "profile": "target-bound-static-elf-media-runtime/1",
    "redistribution_reviewed": True,
    "runtime_dependencies": [],
    "schema": "umi-media-runtime-closure/1",
    "target_triple": target,
}
manifest = root / "media-runtime-closure.json"
manifest.write_bytes(canonical_json_bytes(record))
manifest.chmod(0o400)
PY
```

The helper deliberately fails when either review directory is empty. For the
minimal musl build, include the musl license (and any compiler-runtime license
identified by `DEPENDENCIES.md`) in `dependency-licenses`; do not delete that
guard just because FFmpeg itself configured as LGPL.

Every input file must be owned by the invoking user and must not be group- or
world-writable. The final public release directory, capacity-signing work
directory, and release signing-stage directory must be distinct absolute paths
and must not exist before their respective writes. The capacity-signing directory
contains builder-local paths and is created as a private `0700` tree with `0600`
files. The public stage
contains only distributable artifacts and secret-free operator templates.

Fetch the Finney chain specification only from the policy-pinned Subtensor
revision, then verify its exact digest before naming it in the descriptor. Do not
download from the moving `main` branch:

```bash
FINNEY_SPEC=/absolute/path/to/raw_spec_finney.json
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$FINNEY_SPEC" \
  'https://raw.githubusercontent.com/opentensor/subtensor/da06f033663896ef2fdbbfc3ecc68ca908fba0f5/chainspecs/raw_spec_finney.json'
python - "$FINNEY_SPEC" <<'PY'
import hashlib
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected = "f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105"
observed = hashlib.sha256(path.read_bytes()).hexdigest()
if observed != expected:
    raise SystemExit(f"Finney chain-spec digest mismatch: {observed}")
print(observed)
PY
chmod 0444 "$FINNEY_SPEC"
```

The `LiveShadowReleaseInput` descriptor contains no wallet name, wallet path,
state directory, or private mirror-header path. Those values exist only in the
local bindings created in step 11.

Set `maximum_finalized_head_age_ms` to the schema-fixed value `120000`. A live
capture older than two minutes is rejected at collection, staging verification,
and finalization. The authority must return the final-manifest signature quickly
enough for finalization to finish inside that interval. If it does not, discard
the stage and collect another live observation. The static intent remains valid
as long as no signed static input changes.

Choose a future numeric `activation_block`. Its hash cannot be known in advance
and is not a release input. The schema requires at least one full 360-block window
between a release observation and activation. In practice, schedule activation
days ahead so all three administrators can sign, four validators can install the
release, and publishers can prepare window zero. A later final observation that
leaves fewer than `minimum_release_lead_blocks` makes the command fail closed; use
a later activation block and repeat the capacity-signing pass.

## 1. Prepare a canonical draft

Create an RFC 8785 `umi-live-shadow-release-input/1` document. The complete schema
is the `LiveShadowReleaseInput` model. Keep these invariants:

- `network` is `finney`, `mode` is `live_shadow_calibration`, netuid is 78, and
  translation weights are false;
- the clock, limits, and thresholds equal the version 0.1 launch profile;
- publisher capacity entries cover the three control groups in raw-ID order;
- operator entries cover the validator registry in decoded-account order;
- operator entries contain only the validator hotkey, signature scheme, and
  public transport timing settings;
- each capacity `valid_from_block` equals the future `activation_block`; and
- `release_authority.signature` is `null` until the intent-signing pass.

On the first pass, `observation` is a provisional lower bound and expected runtime
pin. Its runtime metadata digest, runtime versions, genesis hash, and source
revision must be the intended Finney values. Its finalized block number and
timestamp must not be ahead of the live observation. Set each provisional capacity
`issued_block` and `issued_block_hash` to that provisional observation. The two
artifact paths below may reserve not-yet-created absolute paths during this pass:

- `artifacts.finality_attestation`
- `artifacts.release_observation_chain_evidence`

Those provisional header fields and absent files do not become authority. The
capacity-signing command replaces them with bytes obtained from its direct live
run. All other release artifacts must already exist. Operator-local bindings are
created only after the finalized release is installed.

Serialize through the model instead of relying on editor formatting:

```bash
python - draft.json release-input.canonical.json <<'PY'
import json
import sys
from pathlib import Path

from umi.protocol import canonical_json_bytes
from umi.shadow_release import LiveShadowReleaseInput

source, destination = map(Path, sys.argv[1:])
value = LiveShadowReleaseInput.model_validate(json.loads(source.read_bytes()))
destination.write_bytes(canonical_json_bytes(value))
PY
```

## 2. Capture the signing baseline

Run:

```bash
umi-shadow-release release-input.canonical.json \
  --capacity-signing-dir /absolute/path/to/capacity-signing
```

This action uses the network. It directly runs the pinned finality sidecar and
performs read-only RPC and storage-proof collection. It does not load a wallet or
write to the chain. Success creates:

- `release-input.baselined.json`, the canonical unsigned descriptor to continue
  from;
- `release-baseline-patch.json`, the exact replacements and content digest;
- `release-observation/finality-attestation.json` and `chain-evidence.json`;
- `scoring-policy.json`; and
- one exact request per group under `publisher-capacity-signing/`.

Retain this private directory unchanged. The baselined descriptor contains absolute paths
to its replay artifacts, replaces every capacity issuance block/hash, and clears
all capacity signatures and the release-authority signature.

## 3. Obtain all three capacity signatures

For each request, independently check the administrator, policy hash, activation-
equivalence digest, future validity interval, cadence, runway totals, and control-
disclosure digest. The declared administrator signs the raw 32 bytes decoded from
the request's lowercase hexadecimal `digest`, using the request's declared
`sr25519` or `ed25519` scheme. Return the signature as `0x` followed by 128
lowercase hexadecimal characters.

Copy `release-input.baselined.json` to a working file and insert each signature in
the matching `publisher_capacities` entry. Revalidate and canonicalize it. For
example, with `signatures.json` as a JSON object mapping control-group IDs to
signature strings:

```bash
python - /absolute/path/to/capacity-signing/release-input.baselined.json \
  signatures.json release-input.publisher-signed.json <<'PY'
import json
import sys
from pathlib import Path

from umi.protocol import canonical_json_bytes
from umi.shadow_release import LiveShadowReleaseInput

source, signatures_path, destination = map(Path, sys.argv[1:])
document = json.loads(source.read_bytes())
signatures = json.loads(signatures_path.read_bytes())
for capacity in document["publisher_capacities"]:
    capacity["signature"] = signatures[capacity["control_group_id"]]
value = LiveShadowReleaseInput.model_validate(document)
destination.write_bytes(canonical_json_bytes(value))
destination.chmod(0o600)
PY
```

Signature creation happens outside this repository command. Do not place signing
keys, wallet paths, tokens, or private mirror headers in the public release tree.

## 4. Sign the static release intent

After inserting all publisher signatures, emit the exact release-authority
request:

```bash
umi-shadow-release release-input.publisher-signed.json \
  --release-authority-request /absolute/path/to/release-authority-request.json
```

The authority checks the target triple, activation block, policy hashes, disabled
weight flag, observation-authentication profile, and complete `signed_artifacts`
index. It signs the raw 32 bytes decoded from `digest` with the declared scheme.
Insert the resulting canonical 64-byte hexadecimal signature into
`release_authority.signature`, then canonicalize the descriptor again. Any static
file change invalidates this signature.

Save the returned signature as a single line in an owner-only file, then produce
the exact input used by the remaining steps:

```bash
python - release-input.publisher-signed.json \
  /absolute/private/release-authority-signature.txt \
  release-input.release-signed.json <<'PY'
import json
import sys
from pathlib import Path

from umi.protocol import canonical_json_bytes
from umi.shadow_release import LiveShadowReleaseInput

source, signature_path, destination = map(Path, sys.argv[1:])
document = json.loads(source.read_bytes())
document["release_authority"]["signature"] = signature_path.read_text().strip()
value = LiveShadowReleaseInput.model_validate(document)
destination.write_bytes(canonical_json_bytes(value))
destination.chmod(0o400)
PY
```

The static authority signature does not authorize the later observation bytes.
After capture, those bytes are checked against finalized chain state and covered
by the second authority signature in step 7.

## 5. Run the offline check

```bash
umi-shadow-release release-input.release-signed.json --check
```

`--check` performs no network access and writes nothing. It replays the saved
proofs, verifies all three capacity signatures, rebuilds the policy, and validates
the release-authority signature and pinned local files. Its output deliberately
states `"release_authority":false`: a replay-only check cannot authorize a release.

## 6. Stage the public release

Choose a temporary public staging path that is separate from the descriptor's
`release_install_root`:

```bash
umi-shadow-release release-input.release-signed.json \
  --stage-dir /absolute/path/to/public-release-signing-stage
```

This action is networked. In this invocation it obtains a fresh direct smoldot
observation, verifies the required state, and atomically creates the staging
directory. It fails if runtime or topology pins drift, any validator or publisher
registration differs, an owner or collateral fact fails, commit-reveal is not
enabled at version 4, SN78 is not started, mechanism count is not one, the
finalized head is over two minutes old, the activation lead is too short, or the
destination already exists.

Before creating the stage, it also executes all seven conformance fixture groups
against the exact selected FFmpeg, FFprobe, storage-proof, and finality binaries.
A fixture parse error, missing case, wrong expected output, executable failure, or
digest mismatch stops release construction. The command derives the canonical
`conformance-execution-report.json`; the descriptor cannot supply or override that
report.

The proof-backed `SubtokenEnabled` value may be false: that flag controls TAO-side
pool injection and is not the subnet-start signal. A nonzero past
`FirstEmissionBlockNumber` proves that SN78 was started.

The staged manifest and generated artifacts contain no wallet name, wallet path,
state directory, or private mirror-header path. Runtime metadata and transaction-
version RPC bytes are content-pinned inputs; the runtime spec version is also
storage-proof-backed. State version 1 is a pinned trie-format assumption enforced
by the proof verifier, not a separately stored chain fact. The manifest labels
these limits and does not present the unsigned attestation as a portable offline
finality proof.

The manifest's `external_artifacts` entries are installed files despite the
historical field name. Each entry gives its release-relative content-addressed
path, digest, size, and required mode. Verifier binaries, FFmpeg, and FFprobe are
installed as `0555`; other static inputs are `0444`. The
`finality_source_bundle` archive includes `Cargo.lock`, the observer source,
checkpoint fixtures, `vendor/PATCHES.md`, and each vendored dependency's source
and license. The `storage_proof_license_closure` and
`finality_license_closure` archives enumerate the complete target-resolved binary
graphs and carry their collected license and notice material. Keep the applicable
source archive, license closure, and `third_party_notices` with each distributed
Rust binary.

The stage contains `release-manifest.unsigned.json` and
`release-manifest-signing-request.json`. It is not a distributable release. It is
valid only while the recorded finalized head is at most two minutes old.

## 7. Sign the exact staged manifest

Give the external release-authority signer read-only access to the complete stage,
not just `release-manifest-signing-request.json`. From an independently trusted
UMI installation, the signer can verify the stage and obtain the exact request:

```bash
python - /absolute/path/to/public-release-signing-stage \
  5ExpectedReleaseAuthorityAddress <<'PY'
import sys
from pathlib import Path

from umi.protocol import canonical_json_bytes
from umi.shadow_release import verify_shadow_release_signing_stage

stage, authority = Path(sys.argv[1]), sys.argv[2]
_, request = verify_shadow_release_signing_stage(
    stage,
    expected_authority_hotkey=authority,
)
sys.stdout.buffer.write(canonical_json_bytes(request) + b"\n")
PY
```

This verification checks the embedded unsigned manifest, expected authority,
disabled weight flag, activation lead, every installed artifact, and current live
observation age. The signer then signs the raw 32 bytes decoded from the request's
lowercase hexadecimal `digest` with the declared scheme.

Return a canonical response with this shape. Copy the authority, scheme, unsigned
manifest hash, and digest exactly from the request; replace only the signature
placeholder:

```json
{
  "schema": "umi-live-shadow-final-manifest-authority/1",
  "authority_hotkey": "5ExpectedReleaseAuthorityAddress",
  "signature_scheme": "sr25519",
  "unsigned_manifest_sha256": "64-lowercase-hex-characters",
  "digest": "64-lowercase-hex-characters",
  "signature": "0x-followed-by-128-lowercase-hex-characters"
}
```

This second signature is distinct from the static-intent signature. It covers the
exact unsigned manifest through the domain `umi-live-shadow-final-manifest-v1\0`,
including both live-observation artifacts and every static and generated artifact
digest. Do not modify the stage while it is being reviewed or signed.

## 8. Finalize atomically

Finalize before the recorded finalized head becomes two minutes old:

```bash
umi-shadow-release-finalize \
  /absolute/path/to/public-release-signing-stage \
  --signature-response /absolute/path/to/final-manifest-signature.json \
  --emit-dir /absolute/path/to/public-release \
  --expected-authority-hotkey 5ExpectedReleaseAuthorityAddress
```

The finalizer re-verifies the entire stage, both authority signatures, the exact
full-manifest digest, the finality and state-proof evidence, the activation lead,
and current head age. It copies only indexed release files, adds the signed
`release-manifest.json`, verifies the temporary final tree, and then publishes it
with one atomic directory replacement. It refuses an existing, overlapping, or
unsafe destination. A failed or interrupted finalization leaves no partial final
release. If the stage is stale, discard it and repeat from step 6.

The final public release does not contain the unsigned manifest or signing
request. It does contain two secret-free templates per validator under
`operator-templates/`. Those templates carry only validator identity, fixed
settings, and release-relative paths; they are covered by both release-authority
signatures.

When the input includes the Apple Silicon miner target, the release also contains
`miner-templates/aarch64-apple-darwin.json`. That template is covered by both
authority signatures and carries no wallet or model path. The primary validator
templates and Linux artifact pins are unchanged.

## 9. Verify before distribution or startup

Run the verifier from an independently trusted checkout or previously verified
wheel. Pass the authority hotkey obtained outside the candidate release:

```bash
umi-shadow-release-verify /absolute/path/to/public-release \
  --expected-authority-hotkey 5ExpectedReleaseAuthorityAddress
```

The verifier rejects unknown or extra files, symlinks, digest or mode changes, an
unexpected authority, either invalid authority signature, incomplete signature
coverage, an active weight policy, a head that was stale when captured, invalid
finality evidence, invalid storage proofs, and disagreement between chain
evidence, policy, and manifest. Historical verification uses the recorded capture
time; it does not make an old release current again. Live validator startup
performs its own current-head checks. A successful result includes
`"translation_weights_active":false`.

The verifier also recomputes the UMI source-tree digest directly from the
packaged wheel's `umi/*.py` members and requires it to match the policy and source
marker. It does not rely on the builder's workspace after finalization.
It stages the signed release's exact fixture and executable bytes into a private
temporary directory, executes all 34 conformance cases, and requires the resulting
canonical report and digest to match the signed report exactly. Checking only the
stored `verified` field is insufficient.

On an Apple Silicon miner host, use the role-scoped resolver after obtaining this
same release and trusted authority hotkey:

```bash
install -d -m 0700 /absolute/private/umi-resolved-releases
umi-shadow-release-resolve-miner /absolute/path/to/public-release \
  --expected-authority-hotkey 5ExpectedReleaseAuthorityAddress \
  --target-triple aarch64-apple-darwin \
  --output-dir /absolute/private/umi-resolved-releases/release-001
```

It authenticates the complete tree and static policy bindings, then runs the
signed Darwin finality self-test from a fresh private copy. The destination must not
exist before the command; its parent must be owner-only. It does not execute the
Linux-only validator conformance or storage-proof binaries. Consume
`/absolute/private/umi-resolved-releases/release-001/resolved-miner-release.json`;
its output paths are suitable only for the miner command. Its minimum validator
transport timeout and concurrency fields are derived from the signed validator
templates for use by the miner capacity rehearsal. Follow [the macOS miner operator
guide](MACOS_MINER_OPERATOR.md) for installation and startup.

Publish these three values together through the same trusted channel used for the
authority hotkey:

- release directory or archive location;
- SHA-256 of the canonical `release-manifest.json`; and
- release-authority hotkey.

The detached manifest digest helps mirrors and humans identify the intended
release. The verifier still checks both authority signatures and the full tree.

## 10. Install the signed wheel with the signed lock

Use the verified manifest to copy the Python installation inputs into a
private local project directory. This example refuses an existing destination
and rechecks each copied digest:

```bash
RELEASE=/operator/local/path/to/public-release
INSTALL_PROJECT=/operator/private/path/to/umi-python

python - "$RELEASE" "$INSTALL_PROJECT" <<'PY'
import hashlib
import json
import os
import re
import sys
from pathlib import Path

release = Path(sys.argv[1]).resolve(strict=True)
destination = Path(sys.argv[2])
destination.mkdir(mode=0o700, parents=False, exist_ok=False)
manifest = json.loads((release / "release-manifest.json").read_bytes())
records = {item["label"]: item for item in manifest["external_artifacts"]}
outputs = {
    "pyproject": "pyproject.toml",
    "python_lockfile": "uv.lock",
    "python_wheel": "umi_subnet-0.1.0-py3-none-any.whl",
    "uv_binary": "uv",
}
for label, filename in outputs.items():
    record = records[label]
    payload = (release / record["relative_path"]).read_bytes()
    if hashlib.sha256(payload).hexdigest() != record["sha256"]:
        raise SystemExit(f"digest mismatch while copying {label}")
    target = destination / filename
    target.write_bytes(payload)
    os.chmod(target, 0o500 if label == "uv_binary" else 0o400)

policy = json.loads((release / "scoring-policy.json").read_bytes())
scoring = policy["implementation_pins"]["scoring"]
version = scoring["python_version"]
if scoring["python_implementation"] != "CPython" or re.fullmatch(
    r"[0-9]+\.[0-9]+\.[0-9]+", version
) is None:
    raise SystemExit("release carries an unsupported Python runtime pin")
version_file = destination / ".python-version"
version_file.write_text(version + "\n", encoding="ascii")
os.chmod(version_file, 0o400)
PY

IFS= read -r PINNED_PYTHON < "$INSTALL_PROJECT/.python-version"
UV="$INSTALL_PROJECT/uv"
"$UV" --version
"$UV" python install "$PINNED_PYTHON"
"$UV" lock --check --offline --python "$PINNED_PYTHON" \
  --project "$INSTALL_PROJECT"
"$UV" sync \
  --project "$INSTALL_PROJECT" \
  --python "$PINNED_PYTHON" \
  --locked \
  --no-install-project
"$UV" pip install \
  --python "$INSTALL_PROJECT/.venv/bin/python" \
  --no-deps \
  "$INSTALL_PROJECT/umi_subnet-0.1.0-py3-none-any.whl"
```

The release verifier has already required this exact `uv` binary to report
`uv 0.12.9`; the explicit version and offline lock checks above repeat those local
checks before any download. `uv sync --locked --no-install-project` installs the exact dependency graph from
the packaged lock without looking for the builder's source tree. The final
`--no-deps` wheel installation cannot re-resolve that graph. Rerun the release
verifier from the installed wheel before using any other installed command:

```bash
"$INSTALL_PROJECT/.venv/bin/umi-shadow-release-verify" "$RELEASE" \
  --expected-authority-hotkey 5ExpectedReleaseAuthorityAddress
```

## 11. Materialize private validator configuration

After copying the verified public release to the operator machine, create a
mode-`0600` canonical local-bindings file. The file uses this schema and contains
values chosen on that machine:

```json
{
  "schema": "umi-validator-operator-local-bindings/1",
  "validator_hotkey": "5ValidatorHotkey",
  "state_root": "/operator/private/umi-state",
  "wallet_name": "validator-wallet",
  "wallet_hotkey_name": "umi-validator",
  "wallet_path": "/operator/private/wallets",
  "mirror_request_headers_path": "/operator/private/mirror-headers.json"
}
```

Canonicalize the file with the same `canonical_json_bytes` procedure used in step
1, substituting `OperatorMaterializationBindings` as the model. The bindings and
private mirror headers must remain outside the public release. The headers file is
canonical `umi-mirror-request-headers/2` JSON. It must contain every retrieval
origin in the signed discovery rule exactly once, in sorted order, and a different
bearer supplied by that origin's operator:

```json
{
  "schema": "umi-mirror-request-headers/2",
  "readiness_set_path": "/operator/public/window-0-mirror-readiness-set.json",
  "origins": [
    {
      "origin": "https://mirror-a.example",
      "headers": {"Authorization": "Bearer validator-a-token-from-mirror-a"}
    },
    {
      "origin": "https://mirror-b.example",
      "headers": {"Authorization": "Bearer validator-a-token-from-mirror-b"}
    },
    {
      "origin": "https://mirror-c.example",
      "headers": {"Authorization": "Bearer validator-a-token-from-mirror-c"}
    }
  ]
}
```

Never reuse an `Authorization` value across origins. The installed operator rejects
a missing or extra origin, a shared authorization value, or the former flat v1
header map. It also canonical-parses the window-specific readiness set, verifies
every hotkey signature and embedded release/anchor digest, and makes those exact
pool-manifest hashes an eligibility condition in the live mirror adapter. A valid
chain anchor absent from that release is ignored; a valid pool whose certificate
signer set differs from the readiness signer set fails closed. Then materialize
the two startup configs at the public release's actual local path:

```bash
"$INSTALL_PROJECT/.venv/bin/umi-shadow-release-materialize-operator" \
  /operator/local/path/to/public-release \
  --expected-authority-hotkey 5ExpectedReleaseAuthorityAddress \
  --local-bindings /operator/private/path/to/local-bindings.json \
  --emit-dir /operator/private/path/to/startup-config
```

Before reading the local bindings, the command verifies the finalized release
against the independently supplied authority hotkey. It then selects the signed
template matching the local validator hotkey, resolves the release-relative
fields, and validates the policy, target-specific binary hashes, chain spec,
capacity set, mirror rule, and reproduced conformance report. It injects the
verified public release's absolute path as `conformance_release_root`; that
machine-local path never appears in the signed template. It writes a new `0700`
directory containing two `0600` files and refuses existing or overlapping
destinations. The resulting `*.validator.json` and `*.operator.json` files are
accepted by the live validator.

Credentials are window-scoped. Prepare unused service infrastructure for the next
window while the current window is retained. After the current `reveal_round` and
terminal bundle are complete, stop the validator. Start the primer before the next
announcement as described below, finish that window's qualification and mirror
readiness, distribute every new per-origin bearer over its private channel, and
atomically install the complete new header file before the full check and restart.
Do not rotate one origin in place or change a header file while a validator process
is running; the old services and credentials remain available through their
window's reveal.
Do not hand-edit the templates or materialized files.

The local bindings may name the intended v2 header path before that file exists.
Materialization verifies the release and binds the path, but it does not read the
future readiness set or header file. The full validator check below reads both and
will reject either one if it is missing or invalid.

## 12. Prime the window, then check and start the validator

Locate the two files for the selected validator under the materialized directory:

```bash
CONFIG_ROOT=/operator/private/path/to/startup-config
ACCOUNT_HEX=VALIDATOR_ACCOUNT_HEX
VALIDATOR_CONFIG="$CONFIG_ROOT/operator-templates/$ACCOUNT_HEX.validator.json"
OPERATOR_CONFIG="$CONFIG_ROOT/operator-templates/$ACCOUNT_HEX.operator.json"
```

Before the window-specific mirror readiness set exists and before its announcement
block, start the planner-only command with the validator config alone:

```bash
"$INSTALL_PROJECT/.venv/bin/umi-validator-live" \
  --config "$VALIDATOR_CONFIG" \
  --prime-next-window
```

This command runs the pinned finality observer, replays the prior terminal bundle
when there is one, waits for the exact finalized announcement header, and records
exactly one deterministic active window at
`pool_and_selection`. It exits without opening the wallet or constructing a mirror,
anchor, transcript, stage, or weight adapter. It refuses to create the window at or
after `proposal_close_block`. Repeating it before the pool stage advances returns
the same window as `already_primed`.

Use the printed window ID and the same state root for the candidate, authority,
qualification, mirror, and readiness workflow in
[PUBLISHER_AVAILABILITY_OPERATOR.md](PUBLISHER_AVAILABILITY_OPERATOR.md). Install
the resulting canonical `umi-mirror-request-headers/2` file at the path in the
local bindings. Then perform the full offline assembly check:

```bash
"$INSTALL_PROJECT/.venv/bin/umi-validator-live" \
  --config "$VALIDATOR_CONFIG" \
  --operator-config "$OPERATOR_CONFIG" \
  --check
```

After `--check` succeeds, remove that flag to start the live-shadow validator.
The signed policy and both materialized configurations fix
`translation_weights_active` to `false`; startup fails if the runtime, topology,
artifact, finality, storage-proof, capacity, or mirror bindings disagree.
Startup also reruns all conformance cases directly from the content-addressed
release root and requires byte-for-byte equality with the signed execution report.

## 13. Reconcile a certified mirror breach

If every configured mirror loses a child object after its pool receives a quorum
availability certificate, the validator terminates that window as `skipped` with
reason `certificate_breach`. It writes the pool receipt first, publishes the signed
incident bundle, and places an incident-bound hold on new-window intake. Restarting
the validator recovers that receipt and does not repeat the exhausted HTTP attempts.
The failed window is never scored or retried.

The validator cannot calculate the complete public retirement transition until the
committed bytes become available again. Recover them out of band into one private
mode-`0700` directory. Each file name must be its lowercase SHA-256 digest and each
file must be a regular, non-symlink, non-group-writable, non-world-writable file.
Supply:

- every final pool manifest marked `qualified` in the original retrieval evidence;
- every public batch manifest and ground-truth envelope referenced by those pools;
- the exact failed video when the incident target was a video; and
- the canonical Quicknet pulse JSON for the original ground-truth reveal round.

Some of these objects already exist in the incident bundle. The command reads those
copies by digest and requires recovered files only for missing objects. It verifies
the original incident signature and replay, terminal receipt, certificate, closing
proof, policy, descriptor hashes, reveal pulse, and recovered content hashes before
changing protocol state.

```bash
WINDOW_ID=64_LOWERCASE_HEX_CHARACTERS
STATE_ROOT=/operator/private/umi-state

"$INSTALL_PROJECT/.venv/bin/umi-validator-live-reconcile" \
  --config "$VALIDATOR_CONFIG" \
  --incident-bundle "$STATE_ROOT/incident-bundles/$WINDOW_ID" \
  --recovered-objects /operator/private/recovered/$WINDOW_ID \
  --reveal-pulse /operator/private/recovery-pulses/$WINDOW_ID.json
```

The reveal-pulse path must be absolute and subject to the same safe-file checks.
Do not put `reveal-pulse.json` inside the digest-only object directory; use a sibling
path if the directory is consumed by an automated recovery collector.

Success applies exactly one idempotent no-score transition. It retires the public
batch, video, frame, and successfully revealed script hashes, applies only objective
publisher reveal faults, preserves the original `skipped/certificate_breach`
terminal record, resolves that incident, and releases only its matching intake
hold. It does not issue miner requests, calculate miner scores, or submit weights.
After reconciliation, the ordinary live process accepts the next scheduled window;
there is no separate manual resume command. If the process stops during recovery,
rerun the same command with the same inputs.

## External inputs that remain required

The release command cannot supply or prove the off-chain facts below:

- three administrator capacity signatures and the truth of their future runway;
- four operators' wallet names, local paths, private mirror headers, and state
  locations;
- the accuracy, canary, metric-validity, challenge-supply, economics, and 30-day
  soak evidence required by the whitepaper; and
- human consent, reference quality, publisher independence, and control-group
  disclosures.

The resulting release is for public calibration only. It is not evidence that the
activation gates passed, and it cannot submit UMI weights.
