[Documentation](README.md) / Miners

# What SN78 miners should run now

C5 certification is complete and C5 competition rewards are live. C6 intake is
closed and public-model evaluation is running. Follow the cohort progress API
for counted completion and its scoped ETA; evaluation is separate from final
certification and reward activation.

## Submit a model for an open cohort

1. Keep the submitting hotkey registered on subnet **78**. Registration alone is
   not cohort participation and does not guarantee a score or reward.
2. [Install or update the published model client](miners/connection.md#install-or-update-the-model-submission-client) as the account that owns your wallet.
3. Prepare the runnable bundle, signed submission and cohort consent using the
   [model contribution requirements](contributors/models.md). Keep the exact
   signed participation request and original source directory.
4. Follow the [public-model upload steps](miners/model.md#model-files-for-recoverable-cohorts).
   Direct-R2 cohorts send model bytes to R2; the coordinator handles signed metadata,
   admission and review. A running endpoint is not required to submit this track.
5. After upload, [query current admission](miners/model.md#check-admission-after-upload)
   with the original request. The initial receipt stays `pending_attestation`;
   it is not a live status display.

Use the [cohort catalog](https://api.umi.vision/v1/competition/cohorts) to identify
the exact cohort and its history, accepted tracks, readiness and admission URL.
For C6 and later, prepare public models. C7–C10 remain held; their original mixed
plans require the authenticated model-only amendment before opening. An older
endpoint plan is not an instruction to enroll an endpoint for a held successor.
Install the published client update before submitting to an amended cohort;
keep existing signed requests and resume them unchanged after updating.

## Understand the result

| What you see | What it establishes |
| --- | --- |
| Upload/participation receipt with `pending_attestation` | The owner retained that request. This original acknowledgement does not update. |
| `query-cohort-admission` returns `pending_attestation` | The current admission certificate is still pending for that exact request. |
| `query-cohort-admission` returns `admission_certified` | Participation has a verified admission certificate. It is separate from scoring and final cohort certification. |
| Published quality results | Evaluation results are available, with the published provisional/final scope. |
| Finalized reward allocation and chain incentives | Reward activation has reached the chain. A dashboard balance or admission receipt alone does not prove a payment. |

If the live admission query remains pending, preserve the request and report the
cohort ID, consent digest, hotkey/UID, client revision and relevant retry reason.
Do not create new nonces or replace the signed request merely to clear a temporary
server hold. Do not share wallet secrets or presigned R2 capabilities.

## Existing endpoint installations

The [connection guide](miners/connection.md) remains authoritative for supported
runtime upgrades, policy files and retained endpoint-state compatibility. Preserve
existing assignment, grant, nonce and retirement journals. Endpoint participation
and public-model participation are distinct; running an endpoint does not submit
a model for C6.

The [bridge specification](operators/bridge.md) remains relevant to historical
policies and retained verification/recovery consumers. Its HTTPS keepalive rules
are not the current C5 competition reward mechanism and do not replace C6 model
submission. Check the [public results API](reference/competition-results-api.md)
for the selected cohort and published result scope.
