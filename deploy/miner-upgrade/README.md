# Miner cohort updater

`upgrade.py` is the stable updater for standard Linux miners managed by systemd.
The operator supplies one policy choice: whether the miner intends to enter the
public-model track. The current canonical manifest supplies the cohort, runtime,
policies, eligible tracks, authority bindings and new state namespace.

Run the current updater as one shell command:

```sh
curl -fsSLo /tmp/umi-miner-upgrade.py \
  https://raw.githubusercontent.com/Umi-BitSign/umi/main/deploy/miner-upgrade/upgrade.py \
  && sudo python3 /tmp/umi-miner-upgrade.py --public-model-track no
```

Use `yes` instead of `no` to record public-model participation intent. The intent
does not assert contribution rights or upload model bytes. A public-model
submission still needs its ordinary signed consent, rights decision and bundle.

The updater discovers exactly one running `umi.miner` systemd service. It derives
the hotkey, model revision and serving origin from the retained deployment,
downloads hash-bound current inputs, installs the pinned UMI runtime beside the
old one, and creates a fresh policy state root. If the miner uses the standard
Unix-socket model sidecar, the updater clones its configuration with the new
transport binding and socket.

The downloaded bootstrap runs with Python 3.8 or newer and locates the existing
miner's CPython 3.12 interpreter. It builds an isolated dependency-complete
runtime, verifies the exact Git revision and imports, then makes that runtime
root-owned before a service can execute it.

The live transaction stops the miner, switches systemd to hash-bound command
files, starts the updated sidecar when present, and verifies exact sidecar and
miner health. A failure restores the previous systemd overrides and starts the
old services. Prior cohort databases and configuration remain intact.

The script installs itself at `/usr/local/libexec/umi-miner-upgrade`. For later
cohorts, run the same installed updater:

```sh
sudo /usr/local/libexec/umi-miner-upgrade --public-model-track yes
```

The current manifest determines the allowed answer; the updater never infers a
track from the cohort number. The selected C6-C10 profile has no endpoint
pathway. A manifest that publishes that profile rejects `no`, records public-model
intent, and leaves the previous endpoint service unchanged as a recoverable prior
deployment. The operator then signs the ordinary rights declaration and submits
the selected bundle. A future successor manifest may replace any unopened
cohort's selected profile. Once a cohort opens, the accepted manifest remains
fixed for that cohort. An endpoint-only manifest rejects `yes`.

The automatic path deliberately refuses ambiguous or custom deployments before
stopping anything: multiple miner services, a root-run miner, a non-systemd
sidecar, an unrecognized entry point, mismatched sidecar config, or an existing
incomplete runtime. Operators of custom containers should use the same manifest
and health contract in their deployment tooling.
