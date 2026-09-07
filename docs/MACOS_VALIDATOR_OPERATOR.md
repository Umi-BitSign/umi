# Run a UMI validator on an Apple Silicon Mac

Apple Silicon can operate a conforming UMI validator today by running the signed
Linux validator release inside Docker Desktop's bounded Linux VM. The supplied
deployment uses the `linux/amd64` release target by default, so a Mac can join the
same policy-bound cohort as ordinary x86_64 Linux validators.

This is not a host-native Darwin validator. The distinction matters: UMI's signed
release currently binds every validator to one target-specific Python environment,
conformance report, proof verifier, finality observer, and static FFmpeg runtime.
Linux also gives every FFmpeg child a hard address-space limit. A native Darwin
validator would need a new target-indexed release format and an equivalent hard
media-containment boundary. The existing Apple Silicon miner remains host-native.

The live entrypoint composes no weight-submission capability. It accepts only a
signed policy with `translation_weights_active: false` and can submit the three
protocol transcript commitments required for public calibration. The installed
UMI package also contains generic protocol libraries used by release tooling; the
inactive policy and live dependency graph are the enforced boundary.

## 1. Send the public intake information

Open a validator calibration enrollment issue and provide:

- SN78 UID and validator hotkey;
- confirmation that the hotkey has a live validator permit;
- Apple Silicon model, CPU count, memory, dedicated storage, and region class;
- the proposed HTTPS audit hostname; and
- confirmation that the validator is independently administered.

Do not send a seed phrase, keyfile, wallet password, private mirror bearer, or
Cloudflare credential. The release coordinator will return the exact policy-bound
capacity statement for hotkey signature, the expected release-authority hotkey
through a trusted channel, and the signed inactive release.

The validator cannot start before its hotkey and capacity statement are included in
that release. A generic Bittensor validator process is not a substitute.

## 2. Prepare Docker Desktop

Install a current Docker Desktop for Apple Silicon and enable its Apple
Virtualization Framework and x86/amd64 emulation. Give Docker's Linux VM at least
16 GiB of memory, 8 CPUs, and 100 GiB of disk. The UMI service itself defaults to a
12 GiB cgroup limit, 8 CPUs, 512 processes, a read-only root filesystem, no Linux
capabilities, and `no-new-privileges`.

This is an always-on service. Disable automatic host sleep while connected to
power, enable Docker Desktop at login, and make sure the operator account can
restore the deployment after a reboot. Before enrollment, perform one controlled
host reboot and confirm that Docker returns, the revision-bound validator and
audit services restart, and the checks in Sections 5 and 6 still pass. Do not join
a timed window until that drill and an external HTTPS audit-origin readback have
succeeded.

Verify the host and VM before handling a release:

```sh
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
docker info >/dev/null
docker compose version
docker run --rm --platform linux/amd64 \
  python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c \
  uname -m
```

The final command must print `x86_64`. Stop if Docker silently selects another
platform or cannot enforce the requested platform.

## 3. Check out the release revision and build the runner

The signed release names one 40-character `umi_git_revision`. Check out that exact
revision in a fresh public UMI clone. The build command refuses a dirty checkout
and embeds the revision in the image:

```sh
git clone https://github.com/Umi-BitSign/umi.git /absolute/path/to/umi
cd /absolute/path/to/umi
git fetch --tags origin
git checkout --detach REPLACE_WITH_RELEASE_UMI_REVISION
test -z "$(git status --porcelain)"
```

Create two private host input directories. Durable validator state, audit-publisher
state, and released evidence stay on three Linux-native Docker volumes; they are
not SQLite databases on a macOS shared mount:

```sh
install -d -m 0700 \
  /absolute/private/umi-validator-inputs \
  /absolute/private/umi-audit-publisher-inputs
```

Copy the environment template outside the repository and keep it private. Fill the
release revision, matching image tag, public hotkey, paths, and resource limits
first. Leave only `UMI_VALIDATOR_ACCOUNT_HEX` at its placeholder until the image
has decoded the hotkey below:

```sh
cp deploy/macos-validator/operator.env.example \
  /absolute/private/umi-validator-inputs/operator.env
chmod 0600 /absolute/private/umi-validator-inputs/operator.env
```

`UMI_RELEASE_ROOT` is the verified public release directory.
`UMI_OPERATOR_INPUT_ROOT` is `/absolute/private/umi-validator-inputs`.
`UMI_AUDIT_PUBLISHER_INPUT_ROOT` is
`/absolute/private/umi-audit-publisher-inputs`.
`UMI_DEPLOYMENT_ID` is a new lowercase identifier for this exact signed release;
use a value combining prefixes of the UMI revision and release-manifest SHA-256.
Use only lowercase letters, digits, and internal hyphens, with at most 48
characters. It namespaces the Compose project and all three persistent volumes.
The launcher passes that project name explicitly, so an ambient
`COMPOSE_PROJECT_NAME` cannot redirect the deployment. Never reuse the ID for a
different signed release and never change it after initialization.

`UMI_WALLET_ROOT` must be a dedicated runtime copy that contains the named
Bittensor wallet's selected hotkey file and public metadata only. It must not
contain the wallet's `coldkey`, a seed, or unrelated hotkeys. Read-only mounting
protects the files from container writes; it does not protect their contents from
the validator process. Keep the coldkey and original wallet tree offline. Startup
walks the mounted tree, rejects symlinks and non-regular files, rejects any file or
directory outside the selected hotkey plus optional `coldkeypub.txt`, and requires
the configured hotkey file.

Create that minimal copy without carrying the original wallet tree or its ACLs.
Replace the three source/name values, then point `UMI_WALLET_ROOT` at
`RUNTIME_WALLET_ROOT`:

```sh
export RUNTIME_WALLET_ROOT=/absolute/private/umi-runtime-wallets
export WALLET_NAME=validator-wallet
export HOTKEY_NAME=umi-validator
export SOURCE_WALLET_ROOT="$HOME/.bittensor/wallets"
install -d -m 0700 \
  "$RUNTIME_WALLET_ROOT" \
  "$RUNTIME_WALLET_ROOT/$WALLET_NAME" \
  "$RUNTIME_WALLET_ROOT/$WALLET_NAME/hotkeys"
install -m 0600 \
  "$SOURCE_WALLET_ROOT/$WALLET_NAME/hotkeys/$HOTKEY_NAME" \
  "$RUNTIME_WALLET_ROOT/$WALLET_NAME/hotkeys/$HOTKEY_NAME"
if test -f "$SOURCE_WALLET_ROOT/$WALLET_NAME/coldkeypub.txt"; then
  install -m 0600 "$SOURCE_WALLET_ROOT/$WALLET_NAME/coldkeypub.txt" \
    "$RUNTIME_WALLET_ROOT/$WALLET_NAME/coldkeypub.txt"
fi
chmod -RN "$RUNTIME_WALLET_ROOT"
chmod 0700 \
  "$RUNTIME_WALLET_ROOT" \
  "$RUNTIME_WALLET_ROOT/$WALLET_NAME" \
  "$RUNTIME_WALLET_ROOT/$WALLET_NAME/hotkeys"
```

Startup requires each directory to be owned by the runtime UID/GID at mode `0700`
and each allowed file to have one hard link, the same owner/group, and mode `0400`
or `0600`.
Keep `UMI_VALIDATOR_PLATFORM=linux/amd64` unless the release coordinator explicitly
publishes a different single target for the complete validator cohort.

Set `UMI_VALIDATOR_HOTKEY` first and build the image. This is the only management
command allowed to build it, and it requires the checkout to be clean:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env build
```

Then derive the 64-character AccountId32 value from that public hotkey; do not
guess it from the SS58 text:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env account-id
```

Set that output as `UMI_VALIDATOR_ACCOUNT_HEX`, then inspect the runner and
initialize its persistent volumes:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env preflight
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env initialize
```

The image is only a revision-bound launcher. The signed release remains
authoritative for every protocol binary, fixture, policy byte, and runtime pin.
The image resolves its own Debian/glibc wheels, and startup compares their exact
fingerprint with the signed policy. The release coordinator must build the x86_64
release policy in this same pinned container environment; a musl-built or otherwise
different wheel closure will fail safely at `check`. The required exact-release
Apple Silicon smoke run proves this compatibility before enrollment.
The `initialize` command creates or checks three persistent Linux volumes. It does
not overwrite validator state or remove evidence. Run it before starting either
the validator or audit services.

## 4. Create the container-local bindings

Write `/absolute/private/umi-validator-inputs/local-bindings.json` as canonical
RFC 8785 JSON. Every path in this object is a path inside the validator container:

```json
{
  "mirror_request_headers_path": "/operator-input/mirror-request-headers.json",
  "schema": "umi-validator-operator-local-bindings/1",
  "state_root": "/private/state",
  "validator_hotkey": "5VALIDATOR_HOTKEY",
  "wallet_hotkey_name": "umi-validator",
  "wallet_name": "validator-wallet",
  "wallet_path": "/wallets"
}
```

Use `OperatorMaterializationBindings` and `canonical_json_bytes` from the exact UMI
revision to encode it. Give the file mode `0600`. The mirror header file is
installed later at
`/absolute/private/umi-validator-inputs/mirror-request-headers.json`;
it holds the window-scoped bearers and must never enter Git, the environment file,
or the public release.

Verify the release and materialize the signed template selected by the validator
hotkey:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env verify
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env materialize
```

Materialization is create-once and refuses to overwrite `startup-config`. The
initial cohort tooling deliberately does not implement release rotation: validator
protocol state must carry spent and publisher-fault history forward, while the
audit publisher's database and public index are bound to the exact policy and
release manifest. If the signed release changes, stop the old deployment with its
unchanged environment file, preserve all three volumes, and wait for the release
coordinator's reviewed migration or replay procedure. Do not edit generated files,
change `UMI_DEPLOYMENT_ID`, or initialize a fresh deployment as an upgrade; that
would reset or strand protocol evidence.

## 5. Prime, check, and run one window

Before the window announcement, run the wallet-free primer:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env prime
```

Use its window ID for the qualification and mirror-readiness workflow. After the
coordinator privately supplies this validator's distinct bearer for every signed
mirror origin, install the canonical v2 mirror-header file at the path above. Then
run the complete startup check:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env check
```

Only after that command succeeds, start the validator and follow its logs:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env start
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env logs
```

The `account-id`, release verification, materialization, and primer commands use a
wallet-free bootstrap service. The live validator mounts the wallet read-only only
for `check` and `start`; the audit publisher and Caddy never receive that mount.
Do not pass a wallet password through Compose, an environment variable, or a
command line. If the selected hotkey requires interactive decryption, stop and
arrange a reviewed local secret input method before launch.

Before UMI adds this host to the public validator registry, the operator and
release coordinator must capture one real Apple Silicon run of `preflight`,
`initialize`, `verify`, `materialize`, `prime`, `check`, `audit-check`, and an
external audit-origin readback from the exact signed release. The repository's
Linux CI verifies the container construction, but it does not replace this
Docker Desktop emulation and reboot smoke test.

## 6. Publish replayable evidence

Create the canonical audit-publication config at
`/absolute/private/umi-audit-publisher-inputs/audit-publication.json`. Use container
paths:

- validator state and materialized config under `/private`;
- publisher state under `/publisher-private`;
- private same-filesystem staging under `/publication/staging`; and
- the released public docroot under `/publication/public`.

The local path fields therefore have this shape; replace the hotkey and public
origin and retain the capability fields exactly:

```json
{
  "chain_write_capability": false,
  "expected_release_authority_hotkey": "5RELEASE_AUTHORITY",
  "maximum_remote_concurrency": 4,
  "mode": "live_shadow_calibration",
  "poll_seconds": 5,
  "private_staging_root": "/publication/staging",
  "protocol": "umi-asl/0.1",
  "public_docroot": "/publication/public",
  "public_origin": "https://audit-validator-name.umi.vision",
  "remote_timeout_seconds": 30,
  "schema": "umi-validator-audit-publication-config/1",
  "state_database_path": "/publisher-private/publication.sqlite3",
  "translation_weights_active": false,
  "validator_config_path": "/private/startup-config/operator-templates/VALIDATOR_ACCOUNT_HEX.validator.json",
  "wallet_loading_capability": false,
  "weight_submission_capability": false
}
```

Encode the object as canonical RFC 8785 JSON without a trailing newline and set
its mode to `0600`.

Follow [AUDIT_BUNDLE_PUBLICATION_OPERATOR.md](AUDIT_BUNDLE_PUBLICATION_OPERATOR.md)
for the exact schema and HTTPS readback requirements. The audit service has no
wallet mount and sees validator private state read-only.

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env audit-check
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env audit-start
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env audit-logs
```

The publisher stages and installs bundles atomically within one Linux-native
volume. Caddy receives only that volume's `public` subtree, read-only, on
`127.0.0.1:8093`. The coordinator must provision a dedicated remotely managed
Cloudflare Tunnel whose public hostname and loopback service match the signed
publication config. Install and supervise it with the concrete
[macOS audit-tunnel runbook](../deploy/macos-validator/launchd/README.md), then
repeat its local readiness and external HTTPS probes after the reboot drill.
Raw video, mirror credentials, wallets, and local state are never public artifacts.

## 7. Reconcile a certified mirror breach

A terminal `certificate_breach` creates an incident-bound intake hold. After the
incident bundle is public and the originally committed bytes are available again,
place the recovery inputs under the private operator input root:

```text
certificate-breach-recovery/WINDOW_ID/
├── objects/
│   └── LOWERCASE_SHA256
└── reveal-pulse.json
```

The `objects` directory must be mode `0700`. Every object must be a regular,
non-symlink file named by its lowercase SHA-256 digest and must not be group- or
world-writable. `reveal-pulse.json` is the canonical Quicknet pulse for the
original reveal round and must be mode `0600`. Follow Section 13 of
[SHADOW_CALIBRATION_OPERATOR.md](SHADOW_CALIBRATION_OPERATOR.md) for the exact
required object set, then stop the ordinary validator and run:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env \
  reconcile 64_LOWERCASE_HEX_WINDOW_ID
```

The launcher refuses recovery while either the validator or audit publisher is
running. The recovery then runs through the wallet-free bootstrap service. It verifies the
published incident and committed object graph, applies only the idempotent
no-score retirement/fault transition, and releases only the matching intake hold.
It never retries the window, scores a miner, or submits weights. On success, run
`check` again before restarting the validator. If recovery is interrupted, rerun
the same command with the same inputs.

## 8. Stop without deleting evidence

The management script never deletes volumes or host files:

```sh
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env stop
deploy/macos-validator/manage.sh \
  --env-file /absolute/private/umi-validator-inputs/operator.env audit-stop
```

Retain the signed release, state tree, terminal bundles, audit publication state,
public evidence volume, and logs for the policy retention period. The persistent
Compose volumes are prefixed with
`umi-macos-validator-UMI_DEPLOYMENT_ID_`; inspect their exact names with
`docker volume ls` and the deployment ID before backup.
Back them up as one retention unit. Never use `docker compose down -v` or delete a
volume to repair a failed window; use the protocol's reconciliation procedure.
Container stdout uses Docker's local `json-file` driver with five 10 MiB files per
service; durable protocol evidence remains in the named volumes rather than logs.
