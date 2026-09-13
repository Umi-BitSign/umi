# Temporary registration-funding cap

The funding-cap worker supports a new signed bridge policy. Deployment is a
separate step: check the applied policy in each validator's journal and its
finalized weight row before announcing activation.

Under `equal_live_coldkey_ip_funder_groups/1`, passing miners are connected by
shared coldkey, HTTPS endpoint IP, or a common recorded pre-registration sender.
Each connected group receives one equal raw-weight budget, divided among its
passing UIDs. A failed endpoint or excluded validator cannot connect two groups.

The coordinator carries a funding snapshot inside the signed policy. Every
funding assertion binds UID, hotkey, coldkey and registration block. Validators
ignore an assertion if any identity field has changed. Recycled UIDs cannot
inherit an earlier registration's funding group. The snapshot includes the
source report's SHA-256 and each contributing history's SHA-256.

Only complete indexer histories with one non-self sender add a funding edge.
Unknown, incomplete and multiple-sender histories retain coldkey/IP grouping.
Known shared-service senders can be excluded before signing. This is a stated
shared-sender cap, not proof that recipients are one person or that a particular
transfer paid a registration fee. Exchanges can use shared withdrawal wallets.

The [cached checker](REGISTRATION_FUNDING_AUDIT.md) needs a Taostats API key.
One coordinator checker serves both validators; individual weight writers do
not receive the key or duplicate its requests. New registrations are queued and
completed histories reused. A report alone cannot change weights: new bindings
must be carried in a newly signed policy and directive. An API outage does not
invalidate a previously signed snapshot.

Old signed policies and journals retain their original bytes and allocation
rules. The update does not ban registrations, change permits, introduce a /24
network cap, or extend the bridge. Submissions stop before block `9,073,731`;
the hard sunset remains `9,075,171`. This rule is not made a requirement of the
planned 70% endpoint / 30% model-contribution competition.
