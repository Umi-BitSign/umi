# Competition mediator diagnostic

This service post-processes already durable model hypotheses through a pinned,
tool-free Claude CLI. It owns no wallet, validator key, cohort signing key,
reference answer, score, reward state or chain-write path.

The mediator is shadow-only until a later cohort publishes a score contract
before intake. Provider failure, authentication failure, malformed output,
prompt-injection detection and an interrupted prior call all produce a terminal
diagnostic result and cannot delay cohort progress.

`system-prompt-v1.txt` is immutable input to one invocation identity. Record its
SHA-256 with the exact runner release, Claude CLI binary, provider model, output
schema, request budget and timeout. Changing any of them creates a new identity
and requires the injection qualification suite again.

The runtime must:

- retain source evidence and output digests locally, then pass only the
  hypothesis and approved public context as canonical JSON on standard input;
- bind every approved context to a public or synthetic provenance digest before
  the local case-ID join, while omitting the case ID and provenance from the
  provider request;
- use an exact Claude binary digest with tools disabled, restricted mode, safe
  mode, no user/project/local setting sources, strict MCP isolation, no
  permission handler, no browser, no slash commands and no session persistence;
- run from an empty, owned directory with mode `0500`;
- disable auto memory and refuse user, project, managed-policy or parent-directory
  memory, settings, MCP, agents, commands, skills, plugins and hooks, including
  `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.mcp.json` and `.claude/`
  customization paths, which Claude Code could otherwise load automatically;
- expose only the credential home and the minimal fixed environment required by
  the CLI;
- reserve the request in `MediatorJournal` before the call and retain the exact
  response before publishing the diagnostic; and
- never retry a `running` journal record after restart, because the external
  provider outcome is unknown.

Run the deployed worker as a dedicated `umi-mediator` account. Its credential
home, journal and output root are the only writable paths. The unit must have no
supplementary groups and no readable validator wallets, cohort signer roots or
settlement state. Use `ProtectSystem=strict`, `ProtectHome=true`,
`NoNewPrivileges=true`, `PrivateTmp=true`, `PrivateDevices=true`, an empty
capability set, `ProtectProc=invisible`, native-only system calls and namespaces,
and explicit `ReadOnlyPaths`/`ReadWritePaths` for the immutable release and
private mediator state. The process still needs outbound HTTPS to Anthropic;
that network access is held by the CLI process and is never exposed as a model
tool.

Every returned string remains untrusted data. No downstream component may
execute it, interpolate it into a command or policy prompt, or grant it scoring
or chain authority. A future score adapter may consume only the published,
versioned schema after injection detection, independent verification and
deterministic invariants all pass. Any failure produces no mediator score.

The closed output schema and process isolation prevent untrusted text from
acquiring capabilities or writing protected state. Every response must include
ordered, non-overlapping verbatim source spans; the runner rejects invented or
reordered grounding. Semantic resistance is also qualified with neutral/attack
pairs. A score-bearing release fails if an attack changes that grounding or its
normalized protected fields, suppresses an unsupported-claim or injection flag,
or improves the attacker's score.

`umi.competition_mediator_qualification` is the executable qualification gate.
It will not contact the provider without `--execute-live-provider`. It resolves
every neutral/attack request through the at-most-once journal, requires the
attack to be detected, requires the exact source grounding and normalized
protected projection to equal the neutral counterpart, rejects forbidden
markers, and checks the worst-case total cost before the first call. Free-form
summaries and explanations remain untrusted and may paraphrase; they never
authorize scoring. The report itself always denies scoring and chain writes.

The checked-in qualification corpus is
`tests/fixtures/mediator-injection-cases.json`. It covers direct commands, role
spoofing, quoted instructions, encoded payloads, multilingual and Unicode
variants, JSON breakout text, policy conflicts, secret requests and long
distractors, plus XML, Markdown, bidirectional-text and schema-poisoning attacks,
in both the hypothesis and public-context fields. Passing unit tests alone is
insufficient: the pinned external model must pass all fourteen pairs before
release. This does not prove that an LLM can never be semantically manipulated;
the enforceable guarantee is that untrusted text has no capabilities and any
detected manipulation, malformed output, or later verifier disagreement fails
closed without a score.

Run a reviewed release's live gate only from its private service account and
private state root:

```sh
python -I -B -m umi.competition_mediator_qualification \
  --execute-live-provider \
  --fixture /opt/umi-mediator/tests/mediator-injection-cases.json \
  --invocation /etc/umi/mediator/invocation.json \
  --system-prompt /opt/umi-mediator/system-prompt-v1.txt \
  --cli /home/mediator/.local/share/claude/versions/EXACT_VERSION \
  --journal /var/lib/umi-mediator/qualification-journal \
  --working-directory /var/lib/umi-mediator/runtime/work \
  --home /home/mediator \
  --report /var/lib/umi-mediator/qualification-report.json \
  --maximum-total-cost-microusd REVIEWED_TOTAL_CEILING
```

`runtime/runner-release.json` must be the reviewed manifest whose exact SHA-256
is bound in `invocation.json`. The working directory itself is empty and mode
`0500`. An exact rerun reads terminal results from the journal; an interrupted
request remains `prior_outcome_unknown` and is never sent again under the same
identity.
