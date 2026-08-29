# bitsign MVP

Implementation entry point: [execution plan](IMPLEMENTATION_PLAN.md). It freezes the
engineering decisions, repository layout, API-contract order, work packages, tests,
and external approval boundaries needed for another agent to execute the plan. The
LaTeX documents remain the product specification, engineering rationale, and
external pilot protocol. If an implementation detail conflicts, follow the execution
plan and update the older document in the same change.

This launch plan evaluates whether bitsign can turn a short ASL message into useful
English text for a low-stakes, in-person community-event check-in. The signer reviews
the result and decides whether to share it. The product remains an optional
communication aid, with professional interpreters and established accessibility
services available for complex or high-consequence communication.

The plan defines:

- a narrow first-use case and explicit exclusions;
- public capability labels backed by frozen, signer-independent evaluation;
- community, model, system, security, accessibility, and reliability gates;
- a closed pilot with 8 to 12 Deaf or hard-of-hearing ASL signers; and
- objective continue, constrain, change, and stop decisions.

Routine communication clips are processed only to return the requested result and
are excluded from training. Any research collection uses separate informed consent,
retention, access, withdrawal, and deletion rules. Pilot recruitment begins only
after every release gate passes and the build earns a pilot-eligible capability
label. The internal vertical slice, contribution build, and external pilot are separate
gated releases; completion of one does not authorize the next.
