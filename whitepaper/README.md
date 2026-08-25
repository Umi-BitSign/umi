# UMI: A Trust-Minimized ASL-to-English Translation Subnet

Canonical public whitepaper and conformance specification

Protocol version: 0.1

Status: pre-mainnet; undergoing public testnet calibration

## Abstract

This whitepaper defines UMI, a Bittensor subnet that measures and rewards systems for
translating raw American Sign Language video into English text. Miners perform the
translation. Validators independently challenge and score them against references
that were committed before assignment and concealed until responses close. Sealed
ground truth, deterministic text metrics, single-use challenges, signed records, and
reproducible audit bundles minimize the trust placed in any publisher or validator.

The subnet launches with one emission-bearing mechanism by design. This gives the
network one reproducible ranking while the task, data supply, and adversarial controls
are calibrated. The chain supports multiple mechanisms. Any later expansion is a
governed protocol extension with its own evidence, threat analysis, emission policy,
and UID budget.

## 1. Mechanism overview

The launch protocol evaluates one useful output: English text translated from raw ASL
video. It supports end-to-end video models, pose-based systems, hosted APIs, and model
ensembles without prescribing how a miner produces its answer.

A scoring cycle has six stages:

1. A challenge publisher prepares consented ASL clips and independent English
   references, encrypts the references to a future reveal round, and anchors the
   batch commitment.
2. After the pool of eligible batches closes, validators use post-close chain entropy
   to select batches and miners. This prevents publishers or validators from choosing
   work after seeing the selection seed.
3. Validators send authenticated raw-video challenges. Miners return bounded,
   signed English hypotheses before the deadline.
4. Once responses close, validators decrypt the committed references and score every
   assignment with the same deterministic character error rate (CER) or word error
   rate (WER) policy. Missing or invalid work remains in the denominator and scores
   zero.
5. Each validator publishes enough signed evidence for an independent auditor to
   reproduce every score and the exact weight vector before chain encoding.
6. Validators submit weights through the chain-native timelocked path. Yuma Consensus
   combines independent validator weights into incentives and dividends.

Scoring applies only to translation services. End-user application behavior is
outside scope. The protocol assumes no trusted scoring API or trusted hardware
environment. Human review remains necessary to establish reference quality, while
the emission-bearing calculation after reveal is deterministic and independently
reproducible.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY describe conformance
requirements throughout this whitepaper.

## 2. Launch profile and design principles

| Topic | Version 0.1 decision |
|---|---|
| Language pair | ASL (`ase`) to English (`en`) |
| Primary task | Raw video to English text |
| On-chain mechanisms | One by design, MechId 0 |
| Later mechanisms | Governed extension only; no launch emission reserved |
| Emission-bearing metric | Deterministic CER or WER against a sealed reference set |
| Challenge source | Consented, quality-reviewed, fresh human recordings |
| Challenge reuse | A revealed script group and its clips are permanently spent |
| Pose extraction | Input-quality and research diagnostic, zero score weight |
| Semantic similarity | Shadow metric, zero score weight |
| LLM judging | Excluded from weight calculation |
| Miner confidence | Excluded from weight calculation |
| Latency | Measured in shadow mode until network effects are calibrated |
| Corpus contribution | External data pipeline, outside subnet weights in version 0.1 |

One mechanism keeps launch incentives aligned with the useful output and gives
validators one ranking to reproduce. The chain permits multiple mechanisms; version
0.1 deliberately uses one. Later mechanisms require a protocol amendment and evidence
that their task produces independent value.

### 2.1 Trust-minimized design rules

Version 0.1 follows these rules:

1. The emission-bearing score is a pure function of committed inputs, signed responses, revealed references, and a versioned scoring policy.
2. Every conforming validator computes its own scores from source evidence. Shared score and ranking APIs are ineligible as validator inputs.
3. Ground truth is fixed before miner assignment and concealed until all responses close.
4. The candidate pool closes before the selection seed exists.
5. Missing work remains in the denominator and scores zero.
6. Freshness, uniqueness, and reliability are eligibility conditions with fail-closed outcomes.
7. Weight submission uses chain-native timelocked commit-reveal.
8. Public audit evidence is sufficient to reproduce pre-quantization weights exactly.
9. Owner-controlled parameters cannot regrade a committed batch.
10. A trusted hardware environment is absent from the scoring trust boundary.

### 2.2 Adopted subnet patterns

The launch mechanism combines proven shapes from operational Bittensor systems without copying their task-specific assumptions.

| Source pattern | Use in this protocol |
|---|---|
| [Score Vision](https://github.com/score-technologies/score-vision): structured video outputs and lightweight sampled validation | Bounded schemas, sparse motion diagnostics, and validator costs well below miner inference costs |
| [Apex](https://github.com/macrocosm-os/apex): identical sandboxed objective functions across validators | One canonical scoring package, fixtures, and exact score reproduction |
| [OpenRoboto](https://github.com/openroboto-ai/openroboto-subnet/blob/main/docs/SUBNET_OVERVIEW.md): hash-pinned artifacts and evaluation entropy fixed after submission | Batch commitments before selection, post-close entropy, and content-addressed audit evidence |
| [Chutes audit](https://github.com/chutesai/chutes-audit): long-window reliability and inspectable work records | Rolling scores, assigned failures, signed records, and separate availability telemetry |
| [Data Universe](https://docs.macrocosmos.ai/subnets/subnet-13-data-universe/subnet-13-incentive-mechanism): freshness, uniqueness, and credibility | Single-use challenges, deduplication, source diversity, and publisher reliability gates |

The protocol also follows Bittensor's current [Yuma Consensus](https://www.bittensor.com/docs/internals/consensus), [signed-request](https://www.bittensor.com/docs/guides/signed-requests), and [validator weight](https://www.bittensor.com/docs/guides/validating) interfaces.

## 3. Scope

Version 0.1 covers:

- short-form and continuous ASL video;
- English text output;
- fresh challenge creation and retirement;
- authenticated miner inference over HTTP;
- deterministic scoring and validator weight production;
- public score recomputation after ground-truth reveal;
- consent, provenance, retention, and audit requirements.

The following remain outside the launch protocol:

- English-to-sign generation and avatars;
- speech recognition and speech synthesis;
- sign languages other than ASL;
- high-consequence medical, legal, or financial use;
- claims of interpreter equivalence or accessibility certification;
- emission-bearing human opinion scores;
- contributor recruitment and administration beyond the eligibility rules below.

## 4. Actors and trust boundaries

### 4.1 Miner

A miner serves an authenticated translation endpoint and returns one English hypothesis for each assigned video. Miner internals are unrestricted. A miner MAY call an external model or combine several models.

### 4.2 Validator

A validator selects eligible batches and miners, issues challenges, verifies signed responses, decrypts ground truth after the reveal round, calculates scores, publishes an audit bundle, and submits weights.

### 4.3 Challenge publisher

A challenge publisher creates eligible clips and reference sets, timelock-encrypts ground truth, publishes the encrypted batch, and anchors its hash before any miner receives a challenge.

### 4.4 Contributor and reviewer

A contributor records a prompted ASL clip under an explicit consent policy. Independent reviewers see the clip without its prompt and provide English reconstructions or reject the sample. These roles operate through the data pipeline in version 0.1.

### 4.5 Auditor

An auditor verifies batch ordering, response signatures, ground-truth reveal, score calculation, challenge retirement, and the resulting weight vector.

### 4.6 Residual trust

Version 0.1 makes these trust assumptions explicit:

- A challenge publisher knows the ground truth and could leak it.
- Human review establishes reference quality and cannot be reduced to a text metric.
- Video delivery and audit artifacts use off-chain storage.
- Bittensor consensus assumes enough independent validator stake follows the protocol.
- Timelock availability depends on the chain's configured randomness system.
- Consent attestations establish authorization; the chain cannot prove that a person gave informed consent.

Publisher diversity, single-use challenges, signed manifests, and post-reveal audits bound these risks. They do not remove them.

## 5. Version identifiers

Every scored request MUST bind the following versions:

| Identifier | Launch value or source |
|---|---|
| Application protocol | `umi-asl/0.1` |
| Ground-truth schema | `umi-ground-truth/1` |
| Scoring policy | SHA-256 of the canonical policy document |
| HTTP authentication | `btauth/1` |
| Chain runtime | Runtime metadata and spec version at a pinned block |
| Subnet weights | Current `WeightsVersionKey` |
| Weight concealment | Current chain commit-reveal version |

A breaking request, ground-truth, or scoring change MUST increment its version. A scoring change MUST declare an activation block and MUST NOT alter any batch committed under an earlier policy hash.

## 6. Miner API

### 6.1 Transport

Miners MUST expose `POST /v1/translate` at their announced serving endpoint. Requests MUST use `btauth/1`. Deployments with several server processes MUST share replay state.

Validators MUST sign the exact request bytes. Miners MUST bind each response to the serving hotkey with a signature over the canonical response digest. JSON canonicalization follows RFC 8785.

### 6.2 Request

```json
{
  "protocol": "umi-asl/0.1",
  "batch_id": "base64url-128-bit-id",
  "challenge_id": "base64url-128-bit-id",
  "issued_block": 123456,
  "issued_block_hash": "0x...",
  "deadline_block": 123462,
  "video": {
    "url": "https://short-lived.example/object",
    "sha256": "hex-encoded-sha256",
    "size_bytes": 1234567,
    "media_type": "video/mp4"
  },
  "task": {
    "source_language": "ase",
    "target_language": "en",
    "stratum": "short_utterance"
  },
  "scoring_policy_hash": "hex-encoded-sha256"
}
```

Requirements:

- `batch_id` and `challenge_id` MUST be opaque random values with at least 128 bits of entropy.
- The URL MUST expire after `deadline_block` and MUST contain no label, prompt, signer name, or task answer.
- The validator MUST verify downloaded bytes against `video.sha256` before issuing the request.
- A miner MUST verify the downloaded bytes before inference and echo the digest in its response.
- The task and policy hash MUST match the committed batch manifest.

### 6.3 Response

```json
{
  "protocol": "umi-asl/0.1",
  "batch_id": "base64url-128-bit-id",
  "challenge_id": "base64url-128-bit-id",
  "issued_block_hash": "0x...",
  "received_video_sha256": "hex-encoded-sha256",
  "hypothesis": "english text",
  "model_revision": "optional-opaque-sha256"
}
```

The signed digest is:

```text
SHA256("umi-response-v1\0" || RFC8785(response_without_signature))
```

The validator records the serving hotkey and signature separately from the response body.

### 6.4 Response rules

- The first valid signed response received by `deadline_block` is final.
- A missing, late, malformed, unsigned, or digest-mismatched response scores zero.
- A transport retry MUST reuse the same challenge ID. A validator MUST NOT retry after receiving a valid response.
- A hypothesis over 128 normalized tokens scores zero.
- `model_revision` is optional and carries zero score weight.
- A miner MUST return an explicit error status if it cannot fetch or decode the exact video. Synthetic outputs and placeholder translations are invalid.

## 7. Challenge eligibility

An emission-bearing challenge MUST satisfy every requirement in this section.

### 7.1 Media profile

- MP4 container with H.264 video and no audio track;
- duration from 2 through 15 seconds;
- maximum 1280 by 720 pixels, 30 frames per second, and 16 MiB;
- stable view of the signing space, including face, torso, and the hands used by the signer;
- metadata stripped before hashing and delivery;
- successful decode by the protocol conformance decoder.

The quality check MAY use pose extraction as one signal. It MUST support valid one-handed signs and MUST fail closed when its required model is unavailable.

### 7.2 Linguistic strata

Each batch uses this target mix:

| Stratum | Share | Metric |
|---|---:|---|
| Fingerspelling and numbers | 15% | CER over best reference |
| Short everyday utterances | 35% | WER over best reference |
| Continuous everyday signing | 50% | WER over best reference |

Batch rounding MUST be deterministic and declared in the public manifest. Domain-specific and high-consequence material is ineligible in version 0.1.

### 7.3 References

- A clip MUST have from one through five accepted English references.
- References MUST be fixed before the batch commitment.
- At least three fluent reviewers MUST view the clip without the original prompt.
- At least two reviewers MUST confirm that the clip conveys the prompted meaning.
- An accepted blind reconstruction MAY enter the reference set after duplicate and quality review.
- One contributor or reviewer MUST NOT approve their own work.
- The public ground-truth payload MUST preserve reference ordering.

References describe acceptable English renderings. Loose paraphrases that change meaning are ineligible.

### 7.4 Freshness and diversity

- A script group MUST receive emission-bearing evaluation in one reveal cohort only.
- Every clip in that script group MUST retire when the cohort reveals.
- Exact video hashes, protocol frame digests, and revealed normalized script hashes MUST be checked against the spent registry.
- A batch MUST contain at least five signers, with no signer supplying more than 20% of its clips.
- A rolling four-batch scoring window MUST contain at least two challenge publishers.
- One publisher MUST NOT supply more than 50% of scored clips in that window.

Several signer variants for one script MAY appear in the same sealed cohort. They retire together.

### 7.5 Consent and provenance

The publisher MUST hold a signed consent record that covers benchmark delivery to independent network participants, scoring, audit retention, and the limits of deletion after distribution. Training, public release, and product use require separate permission flags.

Emission-bearing clips MUST have a provenance manifest and MUST exclude minors in version 0.1. A consent or rights failure makes the clip ineligible and voids its score.

## 8. Batch lifecycle

### 8.1 Prepare

The publisher creates a public manifest and a ground-truth payload. The public manifest contains batch metadata, clip hashes, strata, media properties, publisher hotkey, scoring policy hash, and a hash of the encrypted ground-truth object. It contains no prompt or reference text.

The ground-truth payload has this logical shape:

```json
{
  "schema": "umi-ground-truth/1",
  "batch_id": "...",
  "scoring_policy_hash": "...",
  "items": [
    {
      "challenge_id": "...",
      "metric": "wer",
      "references": ["reference one", "reference two"],
      "normalized_script_sha256": "...",
      "consent_manifest_sha256": "..."
    }
  ]
}
```

### 8.2 Seal and anchor

The publisher timelock-encrypts the canonical ground-truth payload to a future randomness round. It publishes the ciphertext to at least three independent mirrors. Every scoring validator MUST retrieve and hash-check the complete ciphertext before issuing a challenge.

Before issuance, the publisher anchors this commitment on the subnet:

```text
SHA256(
  "umi-batch-v1\0" ||
  RFC8785(public_manifest) ||
  SHA256(ciphertext) ||
  reveal_round
)
```

The commitment MUST fit the live metadata limits. Large batches MUST be split. The manifest records the anchoring block and transaction identifier.

### 8.3 Select

The candidate batch pool closes at a declared block. Its root is the SHA-256 digest of the lexicographically sorted eligible batch commitments. The common selection seed is:

```text
SHA256("umi-select-v1\0" || closing_block_hash || candidate_pool_root)
```

The closing block hash MUST be unavailable when publishers enter the pool. Validators select the batches with the lowest hashes of the common seed and batch commitment.

Validators select miner hotkeys deterministically. The launch sampler hashes the common seed, validator hotkey, batch ID, and candidate miner hotkey, then selects the lowest hashes. Current score MUST NOT affect selection.

Each validator targets up to 32 miners per batch. At least 20% of assignments SHOULD go to miners with the fewest valid observations in the rolling window.

### 8.4 Serve and respond

The validator issues signed requests and records receive time, status, response bytes, and miner signature. All responses close before the declared ground-truth reveal round. If the ground truth becomes available before `deadline_block`, the whole batch is void.

### 8.5 Reveal and score

After the randomness round arrives, validators decrypt the previously fetched ciphertext, verify its hash and schema, and calculate scores. A ground-truth decryption failure voids the affected batch. A miner response failure remains a zero.

### 8.6 Retire and audit

After reveal, the publisher and validators add the script group, video hashes, and frame digests to the spent registry. The validator publishes the audit bundle defined in Section 12. Retirement authorizes no additional data use.

## 9. Deterministic scoring

### 9.1 Text normalization

For each hypothesis and reference:

1. apply Unicode NFKC;
2. apply Unicode lowercase mapping;
3. tokenize letters and numbers, retaining apostrophes only when surrounded by letters or numbers;
4. replace all other characters with a separator;
5. collapse separators and whitespace;
6. remove leading and trailing whitespace.

Implementations MUST pass a shared normalization fixture before they can submit weights.

### 9.2 WER

For token sequences `h` and `r`:

```text
WER(h, r) = levenshtein_tokens(h, r) / max(1, token_count(r))
score_wer(h, R) = max over r in R of clamp(1 - WER(h, r), 0, 1)
```

### 9.3 CER

CER uses the same formula over Unicode grapheme clusters after removing whitespace. The clip score is the best score across its committed references.

### 9.4 Assigned failures

Every assigned challenge appears in the denominator. A rejected or missing response has clip score zero. Validators MUST NOT calculate a miner score from successful responses alone.

### 9.5 Batch and rolling score

For miner `i` and stratum `k`, let `mean(i, k)` be the arithmetic mean of all assigned clip scores in the rolling window. The accuracy score is:

```text
A_i = 0.15 * mean(i, fingerspelling)
    + 0.35 * mean(i, short_utterance)
    + 0.50 * mean(i, continuous)
```

A miner becomes weight-eligible after at least 12 assigned challenges in the latest four valid batches, including at least two from every stratum. Missing assignments do not count toward the observation minimum.

### 9.6 Utility and weights

The launch utility is:

```text
U_i = max(0, A_i - 0.10)^2
```

Validators submit relative weights proportional to `U_i`. They MUST apply the chain's canonical normalization and quantization. If the number of positive utilities is below the live `MinAllowedWeights`, a validator MUST skip that weight update and emit a health alert. Uniform fallback weights are forbidden.

All score state is keyed by miner hotkey. A UID change MUST NOT merge two hotkey histories.

Each validator MUST derive this state from signed source records and its own prior audit bundles. Importing another validator's score database, ranking, or weight vector is a protocol violation.

### 9.7 Shadow metrics

Validators SHOULD report these separately:

- response latency and timeout rate;
- semantic similarity from a pinned open model;
- BLEU and chrF;
- pose visibility and motion-quality diagnostics;
- per-publisher, per-signer-cohort, and per-stratum scores;
- calibration of any miner-supplied confidence field received from experimental clients.

Shadow metrics have zero influence on version 0.1 weights.

## 10. Chain integration

### 10.1 Mechanism topology

Launch uses one mechanism, MechId 0. The owner MUST verify the live mechanism count and UID constraints at a pinned block before activation. A validator MUST refuse to start if the chain topology differs from its configured topology.

### 10.2 Live state

At the start of each tempo, a validator reads these values from one pinned block:

- runtime spec version;
- mechanism count;
- tempo and epoch position;
- weights rate limit;
- `WeightsVersionKey`;
- `MinAllowedWeights` and maximum weight constraints;
- commit-reveal enabled flag and reveal period;
- validator permit and serving requirements.

The validator exposes the pinned block and values in health telemetry. Hard-coded block timing is forbidden.

### 10.3 Weight submission

Validators MUST use the current mechanism-aware weight interface. When commit-reveal is enabled, they MUST use the chain's timelocked weight path and verify that the commit was accepted. Chain auto-reveal is the expected path. Legacy manual reveal scheduling is outside version 0.1.

The subnet SHOULD enable commit-reveal weights. Its immunity period MUST exceed the configured concealment window so a new miner can receive revealed scores before becoming prunable.

## 11. Data policy

### 11.1 Data classes

| Class | Permitted use |
|---|---|
| Benchmark-only | Challenge delivery, scoring, bounded audit retention |
| Training-approved | Benchmark use plus model training under the recorded license |
| Public-release-approved | Training-approved use plus publication under the recorded terms |

Permissions are additive only when the consent record explicitly grants them. Benchmark participation alone grants no training or publication right.

### 11.2 Retention and deletion

Publishers MUST publish retention periods for raw video, derived features, consent records, and audit bundles. A valid deletion request stops future hosting and challenge use where legally and technically possible.

Raw video is delivered to independent miners. The protocol cannot force deletion of copies already received. Consent language MUST state this limitation clearly. On-chain commitments, spent hashes, and completed scoring records remain immutable.

### 11.3 Privacy

Public manifests MUST exclude names, contact details, wallet mappings, private object URLs, and raw consent records. Audit bundles use opaque participant identifiers. Raw video publication requires the public-release permission class.

## 12. Audit bundle

Within one tempo after reveal, each validator MUST publish a content-addressed bundle containing:

- public batch manifest and on-chain commitment proof;
- encrypted ground-truth object and revealed plaintext;
- reveal round and decryption evidence;
- assigned miner hotkeys;
- exact signed response bodies or a declared missing-response record;
- normalized text fixtures and per-reference edit distances;
- per-clip, per-stratum, rolling, and utility scores;
- final pre-quantization weight vector;
- protocol, scoring policy, software revision, and pinned chain state;
- spent-registry updates;
- all void, exclusion, and error reasons.

Another conforming implementation MUST reproduce every clip score and pre-quantization weight exactly. A mismatch is a validator fault and blocks mainnet readiness until resolved.

## 13. Security requirements

| Threat | Required control |
|---|---|
| Label leakage | Opaque IDs, scrubbed metadata, silent video, label-free URLs |
| Challenge lookup | Fresh human clips and single-use script-group retirement |
| Replay or substitution | Video digest, frame digest, spent registry, block-bound signatures |
| Publisher and miner collusion | Publisher share cap, multiple publishers, leak investigation, public audit |
| Validator cherry-picking | Deterministic batch and miner sampling |
| Miner impersonation | `btauth/1` plus serving-hotkey response signature |
| Selective response scoring | Assigned failures included as zero |
| Confidence gaming | Confidence has zero weight |
| Prompt injection through output | No LLM judge in the weight path |
| Synthetic fallback | Production scoring fails closed on missing video, model, reference, or decoder |
| Missing corpus score | No corpus mechanism and no uniform fallback weights |
| Weight copying | Fresh rankings plus chain-native timelocked weight submission |
| Data poisoning | Blind review, provenance, signer diversity, publisher caps |
| Runtime drift | Pinned chain reads, version checks, fail-closed startup |

External model access is allowed. Miners remain responsible for data handling, model terms, service availability, and protecting challenge material during the scoring window.

## 14. Mainnet activation gates

Emission-bearing launch requires all of the following:

- one mechanism confirmed on the live chain;
- current HTTP authentication and weight interfaces implemented;
- at least three independently administered validators;
- at least three active miners from two independent implementations;
- at least two active challenge publishers;
- ten consecutive testnet tempos with exact independent score recomputation;
- no synthetic, placeholder, answer-bearing ID, or unrevealed-reference fallback in production code;
- 100% of scored clips carrying eligible consent and provenance records;
- 100% of scored scripts and clips passing the spent-registry check;
- successful ground-truth sealing, late-response, early-reveal, mirror-loss, replay, and runtime-upgrade drills;
- published calibration results for batch size, deadlines, quality floor, strata, and miner sampling;
- a public incident and batch-void procedure.

Bootstrap datasets MAY support model training and shadow evaluation. They are ineligible for mainnet weight calculation.

## 15. Pre-mainnet calibration profile

These values define the version 0.1 testnet profile. Calibration MAY change them
before mainnet through a new scoring policy hash and a published activation block.

| Parameter | Initial value |
|---|---:|
| Batch size | 12 clips |
| Miners queried per validator and batch | up to 32 |
| Rolling score window | 4 valid batches |
| Minimum assigned clips | 12 |
| Minimum clips per stratum | 2 |
| Quality floor | 0.10 |
| Utility exponent | 2 |
| Maximum references | 5 |
| Maximum hypothesis length | 128 tokens |
| Target response window | 60 seconds, encoded as a live block deadline |
| Maximum clip duration | 15 seconds |
| Maximum clip size | 16 MiB |
| Semantic score weight | 0 |
| Pose score weight | 0 |
| Latency score weight | 0 |

## 16. Extension rules

Version 0.1 reserves no emission for a future task. An extension must provide benchmark evidence, a threat analysis, and a migration plan.

Subtensor supports independent mechanisms with separate weights, Yuma runs, bond pools, and emission shares. The global `MaxMechanismCount` is governance-controlled. The live value at the migration block is authoritative.

Version 0.1 pins `MechanismCountCurrent` to one at launch and keeps the initial
commodity unified. A multi-mechanism expansion MUST account for the live UID budget,
root approval for a global cap increase when required, count-change rate limits,
split reset behavior, validator cost, and miner specialization before the owner
changes the count.

Potential extension mechanisms are:

| Extension | Independent value test | Activation blocker |
|---|---|---|
| Motion perception | A reusable structured motion representation improves translation or another measured consumer | Independent pose ground truth and non-circular scoring |
| Model artifact tournament | Public checkpoints improve held-out ASL translation quality | Reproducible packaging, isolated evaluation, and plagiarism controls |
| Corpus production | New consented data improves a later held-out model or benchmark | Personhood, provenance, deduplication, delayed utility, and collusion controls |
| Human adjudication | Blind judgments resolve cases deterministic references cannot cover | Reviewer privacy, anchor accuracy, Sybil resistance, and aggregate-only reporting |
| Organic serving | Signed real demand measures availability and useful throughput | Anti-self-dealing receipts and a ground-truth or quality-audit path |

No extension receives a positive split merely because a mechanism slot is available.
Its score must remain independently reproducible and its output must have a named
consumer.

An emission-bearing semantic metric requires a pinned model and tokenizer, deterministic inference fixtures, adversarial evaluation, and a hard contribution cap. Human judgment requires a separate privacy, personhood, collusion, and reviewer-integrity design. Neither change can alter already committed batches.

## 17. Conformance summary

A conforming miner:

- serves the versioned authenticated API;
- verifies the video digest;
- signs a bounded English response;
- returns explicit failures;
- exposes no answer-bearing fallback.

A conforming validator:

- reads chain state at a pinned block;
- selects batches and miners deterministically;
- closes responses before reveal;
- scores every assignment with the exact public algorithm;
- rejects ineligible, reused, or unverifiable data;
- publishes a reproducible audit bundle;
- uses the current mechanism-aware timelocked weight path.

A conforming publisher:

- supplies eligible consented data;
- fixes references before commitment;
- publishes and mirrors the sealed batch before issuance;
- anchors its hash on chain;
- retires every revealed script group;
- keeps private participant information out of public artifacts.
