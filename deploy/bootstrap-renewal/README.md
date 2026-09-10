# UID 200 bootstrap renewal deployment

This directory contains the systemd unit and configuration template for the
coordinator-side renewal controller. The controller starts only after the manual
sequence-2 bootstrap result is public and verified. It then publishes sequence 3
and later renewals for the exact same pinned worker and frozen service row.

Use [the operator runbook](../../docs/BOOTSTRAP_RENEWAL_OPERATOR.md). Do not point
the service at a branch checkout or start it before completing the adoption
checks.
