# Bridge reward admission reopened, September 16, 2026

Signed supervisor directive sequence 18 removes the registration snapshot at
block 9,076,034. New registrations and re-registrations can qualify using the
current finalized roster. The health checks, coldkey/IP/funding grouping,
validator and owner exclusions, and weight allocation are unchanged.

The successor uses policy body version 3 with `lifetime=until_superseded`.
There is no scheduled submission cutoff or sunset. It does not reopen the
retired pilot or activate translation competition rewards.

At finalized block 9,081,644, on-chain registration was enabled, with both
`Burn` and `MinBurn` equal to 750,000,000 rao (0.75 TAO). That is a dated
observation, not a guaranteed future quote. On-chain registration was already
enabled during the reward freeze; this update removes the separate reward gate.

## Signed publication

- Policy SHA-256:
  `d4c8713ec623423edc87a06088e4048733ca68bb448b00e8e669134f10ec05aa`
- Policy valid from finalized block: `9081624`
- [Signed policy](https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/validator-supervisor/registration-bridge/policies/d4c8713ec623423edc87a06088e4048733ca68bb448b00e8e669134f10ec05aa/signed-policy.json)
- Input bundle SHA-256:
  `76d548d0117c4ac6544d15d8938f5d36cd21b29f39f2bdecd2888fbe19e5e7d7`
- Linux amd64 sequence 18 directive SHA-256:
  `e1ba1e2cf4ab19e1ff2df4cdde0b2adbd69939e70bccb8c0c835e587a85cfc68`
- Linux arm64 sequence 18 directive SHA-256:
  `9a0adf8c877ed5a55793d1ebcfd30cf106df3337d8e6753de6917840eace184d`

The worker release remains `c322687639e6e5f6ee6b26e1b105b7443a166607`.
Both architecture feeds include the successor for every earlier cursor, and
their public readback matches the signed artifacts. Host artifacts and earlier
signed directives were not replaced. Running supervisors adopt the policy
through the signed feed; operators do not need to reinstall.

The reviewed funding snapshot is unchanged. New registrations use the existing
coldkey/IP checks; new funding assertions need a later signed snapshot refresh.
Registration and endpoint health do not guarantee immediate incentives, recovery
of registration fees, or protection from deregistration.
