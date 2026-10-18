# Supervisor compatibility controls

`c5-reference-history24-amd64.json` and `c5-reference-approval.json` retain the
original canonical signed common-channel history and approved C5 policy. They
exercise the historical bootstrap-to-translation preflight without changing any
signature or signed clock. Unit tests explicitly use synthetic native ports at
a height within that retained window; these fixtures are not current deployment
instructions or native chain evidence.
