# Retained bootstrap renewal deployment

Current validators use the [supervisor guide](../../docs/PERMANENT_VALIDATOR_SUPERVISOR.md).
This template is retained for signed bootstrap-history recovery; it does not
authorize starting a new bootstrap campaign. Remove it only when supported
recovery no longer consumes that history.

This directory contains the systemd unit and configuration template for the
coordinator-side renewal controller. The controller starts only after the manual
sequence-3 bootstrap result is public and verified. Sequences 1, 2, and 3 are the
preserved manual seed history. The controller publishes sequence 4 as its first
automatic renewal, then later renewals for the exact same pinned worker and frozen
service row.

Use [the operator runbook](https://github.com/Umi-BitSign/umi/blob/9960523a4466194eff1ca5cb656ff78d2b9057d5/docs/BOOTSTRAP_RENEWAL_OPERATOR.md). Do not point
the service at a branch checkout or start it before completing the adoption
checks.
