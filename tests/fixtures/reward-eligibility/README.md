# Fixed-point reference vectors

`arithmetic.json` contains 24 inputs and outputs from a Rust oracle using
`substrate-fixed` at revision
`d5f70362f2e05b5f33fb51cd7baa825323e4e6c5`. That is the library revision in
Subtensor `c004cebf360f4088187ee49d851dfb1a1eaaf710`'s Cargo.lock.

The vectors cover ordinary inherited stake, normalization to zero and sums outside
the supported signed range. Full-width integers are test data, not RFC 8785
protocol payloads. The Python test compares inherited balances and eligibility
against these stored reference outputs without needing Rust or network access.
The fixture provenance records the deterministic seed and hashes of the full
1,024-input differential run.

The oracle uses U96F32 proportions and inherited balances, I64F64 combined stake,
checked division with a zero default, and I32F32 normalized stake. Checked sum
overflow marks an unsupported range; it does not model an overflowing epoch.
These vectors establish arithmetic agreement with that source profile, not a
deployed runtime identity or a payment guarantee.
