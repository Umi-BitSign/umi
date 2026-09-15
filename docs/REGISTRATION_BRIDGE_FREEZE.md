# Registration bridge reward freeze

The signed `umi-registration-bridge-policy-body/4` policy restricts bridge
reward eligibility to the registrations in its finalized snapshot. It matches
UID, hotkey, and registration block. Replacing a UID or re-registering a hotkey
does not inherit the previous registration's eligibility.

The initial freeze snapshot is block 9,076,034:
`0xbd146374d904ef80c272e9df451154fe4ef842703083c1d224400adc965797d1`.
Snapshot SHA-256:
`de3c80bff45b783214ed53df432f4b7468b9b6db723c9a70503f98e4cbd2f664`.

Existing registrations still need healthy endpoints and must pass the current
miner eligibility checks. A validator permit still excludes a miner. Existing
registrations can repair their endpoints after the freeze. Coldkey, endpoint-IP,
and signed funding groups retain their previous allocation rules.

This freezes bridge reward admission. It does not disable on-chain registration,
prevent UID replacement, prove operator identity, or remove suspected spammers
already present in the snapshot. New registrations receive zero bridge weight
from validators applying this policy. Other validators and subnet consensus can
affect final incentives.

A code merge alone does not activate the freeze. Activation requires the signed
policy and release, adoption by the validators, and finalized weight readback.
Historical v1/v2/v3 policies keep their original meaning. The freeze continues
until replaced by an explicitly signed successor policy.
# Audit-history capacity

The worker retains every submission transition and receipt. Its bounded history
allowance is now 512 MiB and 4,096 files. The earlier 64 MiB allowance filled on
the live validators and blocked renewal. This is temporary operational headroom,
not automatic archival: operators must monitor growth. Reaching either limit
still stops submission; do not delete journals or unresolved attempts to resume.
