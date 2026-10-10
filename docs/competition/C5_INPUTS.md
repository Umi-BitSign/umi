[Documentation](../README.md) / C5 public inputs

# C5 public inputs

C5 uses these canonical public inputs:

- [Competition policy](C5_POLICY.json), policy digest
  `61f6c05143804c297aed524b6e067233567d30fe4eb50ab3289e7bfdad8e26fa`.
- [Endpoint transport policy](C5_TRANSPORT_POLICY.json), policy and file digest
  `f182c1cbfa3985338944735cc55b52b46b12b0207436d79dd5978087483f01a8`.
- Runtime revision `ea32437d294bc0108c59812ff956477bd8f90d17`.

The live [status](https://api.umi.vision/v1/competition/status) and
[readiness](https://api.umi.vision/v1/competition/readiness) responses determine
whether intake is currently open. Verify that their `policy_sha256` equals the
competition-policy digest above before signing a submission. Preserve the exact
policy files and accepted receipt with the submission.

The C5 transport permits UID 54
(`5FLKx6h7DwWRuqq1dcfQafsBw5i9cbchNEFAEHrqSRthGnDZ`) to issue work. It is a
different policy from C4 even though its inference and resource limits are
unchanged. A miner must not reuse a C4 policy-bound grant or assignment database
for C5. Keep existing nonce and response evidence, and use a separate private C5
grant directory and policy-bound assignment state.

C5 phase blocks are operating targets. Coordinator or validator downtime delays
and resumes unfinished work; it does not discard the cohort or advance intake to
C6. The [request-tail rule](launch.md#timing-and-recovery) also applies to retained
C5 work using its original request opening. It preserves completed evidence and
requires independent closure certification. C4 remains the effective reward
cohort until C5 produces a certified successor row.
