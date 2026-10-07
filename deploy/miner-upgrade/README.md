# Miner cohort updater

Operator commands, supported installations, status meanings and future-cohort
upgrades are maintained in the [current miner connection guide](../../docs/miners/connection.md#upgrade-an-existing-miner).

`upgrade.py` is a single-file bootstrap for Python 3.8 or newer. It discovers one
running systemd miner, inspects its runtime, startup schema, service account and
state paths, and selects a supported migration before changing services. Updates
under the same cohort authority preserve existing startup bytes, journals and
custom directory bindings in place, including root-run miners. Unsupported
transitions stop before cutover.

`current.json` is the canonical profile for policy, transport, track and authority
bindings. A matching live deployment can supply a newer compatible source
revision. Policy or track changes require matching public records; future cohort
rules are selected by the manifest rather than inferred from cohort numbers.

Runtime installation uses the exact policy-selected CPython and dependency pins,
isolated imports and an absolute `/usr/bin/env` executable. The service account
verifies source and scoring pins before promotion. A failed runtime or health
check keeps or restores the previous selected installation. Enrollment retries
retain the exact signed request and claim instead of creating new signatures.

Qualification lives in `tests/test_miner_upgrade.py`, including older startup
layouts, repeated updates, custom paths, root services, policy-pin refusal and a
PATH-shadowed `env` executable. Existing protocol state must never be reset to
work around an unsupported upgrade.
