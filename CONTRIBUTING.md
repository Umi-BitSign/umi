# Contributing to UMI

UMI is licensed under Apache-2.0 and open for implementation review and component
testing. Translation weights remain inactive. A local run, test result, or
rehearsal bundle is not activation evidence.

## Set up the repository

Python 3.10 through 3.14 is supported. FFmpeg and FFprobe are required for policy
construction, shadow rehearsal, media inspection, and the full test suite.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

## Safety rules

- Keep `component_test_no_weight`, `shadow_rehearsal_no_weight`, and
  `calibration_no_weight` distinct.
- Do not add signing, submission, or broadcast behavior to an offline builder or
  replay command.
- Treat every chain snapshot as one block hash. Do not combine best-head and
  finalized reads.
- Reject missing proofs, incomplete block intervals, unknown runtime revisions,
  unbounded network bodies, and noncanonical JSON.
- Preserve exact rational arithmetic through scoring. Use the pinned Bittensor
  conversion only at chain encoding.
- Keep canary labels and reference text sealed until the declared reveal.
- Never commit contributor video, consent records, wallet secrets, or private
  object URLs.

## Pull requests

Each pull request should identify the whitepaper requirement it implements, add
adversarial tests, and state any stage it does not reach. Run `make check` before
requesting review. Changes to a digest formula, schema, normalization behavior,
runtime pin, or activation parameter need an explicit compatibility note.
