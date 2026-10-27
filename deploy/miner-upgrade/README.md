# Miner cohort updater

Operator commands, supported installations, status meanings and future-cohort
upgrades are maintained in the [current miner connection guide](../../docs/miners/connection.md#upgrade-an-existing-miner).

`upgrade.py` is a single-file bootstrap for Python 3.8 or newer. It discovers one
running systemd miner, inspects its runtime, startup schema, service account and
state paths, and selects a supported migration before changing services. Updates
under the same cohort authority preserve existing startup bytes, journals and
custom directory bindings in place, including root-run miners. Unsupported
transitions stop before cutover. Explicit supported local grant and history limits
are retained byte-for-byte. Before cutover and repeat recognition, the selected
runtime checks native startup inputs as the existing service account in its
working directory, without opening wallets or journals.
Endpoint activation retains a root-owned recovery intent before stopping a
service. A retry validates its exact command/configuration bindings and resumes a
stopped service or adopts an already healthy selected runtime. Original rollback
overrides survive interruptions; successful cutover is recorded before enrollment.
Stage counts, elapsed time and historical-duration ETA are emitted without a new
execution deadline.

`--install-model-client` is an independent user installation mode for Linux and
macOS with Python 3.10 through 3.14. When invoked with an older system Python,
it selects an already installed supported interpreter before fetching the
manifest; `UMI_MODEL_CLIENT_PYTHON` can name a supported interpreter outside the
usual PATH or Homebrew locations. It validates the same manifest/status binding,
then installs the exact source and locked dependencies without discovering an
endpoint or using its environment. See the connection guide for its commands,
repeat-install behavior and retained release directories. Model-only track intent
keeps its existing no-service-change behavior and does not install this client.

`current.json` is the canonical endpoint-upgrade profile for its selected cohort;
it currently names C5 for retained endpoint work. C7+ public-model participation
uses the separate model client and each cohort's signed history. The catalog's
effective profile fields follow signed cohort amendments automatically; the
original mixed plan is retained for recovery. A matching live deployment can supply a newer compatible source
revision. An explicit `runtime.deployment_revision` instead binds the exact
maintenance `runtime.revision` to the existing live deployment. Policy or track
changes require matching public records; future cohort rules are selected by the
manifest rather than inferred from cohort numbers.

Runtime installation uses the exact policy-selected CPython and dependency pins,
isolated imports and an absolute `/usr/bin/env` executable. The service account
verifies source and scoring pins before promotion. A failed runtime or health
check keeps or restores the previous selected installation. Enrollment retries
retain the exact signed request and claim instead of creating new signatures.

Qualification lives in `tests/test_miner_upgrade.py`,
`tests/test_miner_upgrade_historical.py`, `tests/test_miner_upgrade_recovery.py` and
`tests/test_miner_startup_ownership.py`,
including older startup layouts, repeated updates, custom paths, root services, policy-pin refusal and a
PATH-shadowed `env` executable. Existing protocol state must never be reset to
work around an unsupported upgrade.
Standalone client isolation, repeat installation, failed selection and endpoint
preservation are covered by `tests/test_model_client_install.py`.
