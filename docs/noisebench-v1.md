# NoiseBench V1 adapter contract

This document defines the only input accepted by NoiseBench V1. The parser rejects duplicate keys, unknown keys, invalid UTF-8, blank JSONL lines, floating-point configuration values, and fields outside these schemas.

## Dataset layout

```text
dataset/
├── manifest.json
├── public-traces.jsonl
└── private-labels.jsonl
```

`manifest.json` contains one JSON object. Each JSONL file contains one object per line and ends each line with `\n`.

## Manifest

Schema: `noisebench/manifest/v1`

| Field | V1 rule |
| --- | --- |
| `dataset_id` | Non-empty exporter-defined ID. |
| `public_trace_schema` | `noisebench/public-trace/v1` |
| `private_label_schema` | `noisebench/private-label/v1` |
| `producer` | Non-empty `name` and `version`; optional 40-character lowercase Git commit; integer-only JSON `configuration`. |
| `observer_profile` | `noisebench-observer/v1` |
| `feature_version` | `noisebench-features/v1` |
| `attacker` | Exact frozen ranker settings below. |
| `split` | Actor split, 60/20/20, seeds `[11,23,47,71,101]`. |
| `bootstrap` | Seed `31337`, 10,000 replicates. |
| `coverage` | Exporter's expected decision count or `null`; minimum 9,500 bps. |
| `claim` | Maximum advantage 500 bps, confidence 9,500 bps, channel drop 500 bps. |
| `power` | At least 100 held-out actors and 1,000 scoreable held-out decisions; fixed shadow control. |
| `hashes` | Four lowercase SHA-256 values. |
| `expected_fixture_result` | `null` for normal exports. Reserved for pinned controls. |

The frozen blocks are:

```json
{
  "attacker": {
    "family": "regularized-logistic-ranker/v1",
    "learning_rate_micros": 10000,
    "l2_micros": 1000,
    "training_steps": 400,
    "preprocessing": "train-zscore/v1",
    "tie_break": "candidate-id-lexicographic/v1"
  },
  "split": {
    "unit": "actor",
    "train_bps": 6000,
    "validation_bps": 2000,
    "test_bps": 2000,
    "seeds": [11, 23, 47, 71, 101]
  },
  "bootstrap": { "seed": 31337, "replicates": 10000 },
  "coverage": { "expected_decisions": 5000, "minimum_bps": 9500 },
  "claim": {
    "max_advantage_bps": 500,
    "confidence_bps": 9500,
    "channel_contribution_min_drop_bps": 500
  },
  "power": {
    "minimum_held_out_actors": 100,
    "minimum_scoreable_decisions": 1000,
    "shadow_rule": "seeded-extreme-ordinal/v1",
    "shadow_seed": 424242,
    "shadow_min_advantage_bps": 1000
  }
}
```

`expected_decisions` must count all planner decisions that should have produced either candidates or a refusal. Set it to `null` only when the exporter cannot establish the denominator. Unknown coverage produces `INSUFFICIENT_THREAT`.

## Public trace

Schema: `noisebench/public-trace/v1`

A scoreable row records only what the declared observer sees. Candidate order is public and must match contiguous ordinals starting at zero.

```json
{
  "schema": "noisebench/public-trace/v1",
  "trace_id": "actor-17-seed-11-decision-0",
  "seed": 11,
  "actor_id": "actor-17",
  "sequence_index": 0,
  "observed_time_bucket": 481203,
  "bundle": {
    "program_id": "planner-program-v1",
    "asset_id": "asset-usdc"
  },
  "candidates": [
    {
      "candidate_id": "candidate-a",
      "ordinal": 0,
      "destination_id": "destination-4f9d",
      "amount_atoms": "25000000"
    },
    {
      "candidate_id": "candidate-b",
      "ordinal": 1,
      "destination_id": "destination-8a21",
      "amount_atoms": "25010000"
    }
  ],
  "refusal": null
}
```

Rules:

- `trace_id`, `actor_id`, `program_id`, and `asset_id` are non-empty.
- `seed` appears in the manifest's fixed seed list.
- `sequence_index` starts at zero and stays contiguous within each `(seed, actor_id)` history.
- A scoreable row has at least two candidates and `refusal: null`.
- Candidate IDs are unique within a row.
- `amount_atoms` is a base-10 `u128` string with no sign, decimal point, exponent, or leading zero, except the value `"0"`.
- Identifiers may be stable pseudonyms. Stability across an actor's history is load-bearing for a longitudinal audit.

A planner refusal is public evidence, not a missing row:

```json
{
  "schema": "noisebench/public-trace/v1",
  "trace_id": "actor-17-seed-11-decision-1",
  "seed": 11,
  "actor_id": "actor-17",
  "sequence_index": 1,
  "observed_time_bucket": 481204,
  "bundle": {
    "program_id": "planner-program-v1",
    "asset_id": "asset-usdc"
  },
  "candidates": [],
  "refusal": { "reason_code": "planner_declined" }
}
```

A refusal has no candidates and no private label. It counts as observed coverage but not as a scoreable decision.

## Private label

Schema: `noisebench/private-label/v1`

```json
{
  "schema": "noisebench/private-label/v1",
  "trace_id": "actor-17-seed-11-decision-0",
  "true_candidate_id": "candidate-b"
}
```

Every scoreable public trace has exactly one private label. The label names one candidate in that trace. Refusals have none. NoiseBench uses the label only to score a candidate; feature extraction never reads it.

## Linkage and coverage

NoiseBench rejects duplicated trace IDs, duplicated labels, labels without public rows, labels on refusals, missing labels on scoreable rows, labels that name no candidate, and sequence gaps.

Coverage is:

```text
floor(scoreable_decisions * 10,000 / expected_decisions)
```

The outcomes differ by cause:

- Missing `expected_decisions` or coverage below 9,500 bps is valid `INSUFFICIENT_THREAT`.
- Zero expected decisions, observed decisions above the declared total, or other inconsistent coverage evidence is `INVALID_EVIDENCE`.

## Canonicalization and hashes

NoiseBench canonicalizes parsed typed values rather than hashing source formatting.

1. Sort public traces by `(seed, actor_id, sequence_index, trace_id)`.
2. Sort private labels by `trace_id`.
3. Serialize compact JSON with struct field order and no floating-point values.
4. Add one newline after each JSONL record.
5. For the manifest component, remove `hashes.manifest_sha256` and `hashes.dataset_sha256`, then serialize compact JSON.
6. Compute SHA-256 for the manifest bytes, public bytes, and label bytes.
7. Compute the dataset hash from the domain and three raw 32-byte digests:

```text
SHA256(
  UTF8("noisebench/dataset/v1\0") ||
  manifest_digest ||
  public_digest ||
  labels_digest
)
```

Store the four lowercase hexadecimal digests in `manifest.hashes`. Hashes are content addresses and tamper evidence. They are not signatures.

The crate exposes `seal_dataset` and `write_canonical_dataset` for Rust exporters. Other exporters must reproduce the byte contract exactly.

## Causal feature profile

The bundle-only view has:

- intercept;
- amount digit count and roundness;
- normalized ordinal, candidate count, amount rank, and nearest amount gap;
- stable SHA-256 program and asset buckets.

The longitudinal view adds five channels:

| Channel | Inputs |
| --- | --- |
| `destination_history` | Destination frequency, recency, and prior-bundle destination recurrence. |
| `amount_history` | Exact amount frequency and distance from prior amounts. |
| `cadence` | Prior public row count and mean observed-time delta. |
| `transitions` | Prior-bundle amount recurrence. |
| `prior_ordinal` | Candidate ordinal recurrence. |

For each `(seed, actor_id)`, NoiseBench sorts public rows, builds the current candidates from a read-only prior-history snapshot, then appends the current public row. Current or future private labels never enter history.

## Attacker and metric

NoiseBench hashes `(seed, actor_id)` into disjoint 60/20/20 actor splits. It trains one regularized logistic ranker per seed. Preprocessing fits means and population standard deviations on training candidates only. The ranker uses 400 full-batch steps, learning rate 0.01, L2 0.001, and candidate-ID lexical tie breaks.

For each held-out trace, top-1 advantage is:

```text
correct - (1 / candidate_count)
```

NoiseBench averages decisions within each `(seed, actor_id)` cluster, then weights clusters equally. A deterministic 10,000-replicate cluster bootstrap reports a 95% percentile interval in signed basis points.

The addressed shadow task replaces labels with a seeded extreme ordinal rule and runs the same pipeline. If its lower confidence bound stays below 1,000 basis points, NoiseBench returns `INSUFFICIENT_THREAT` because the attacker pipeline failed its sanity check.

Every seed must contain scoreable train, validation, and test actors. Missing per-seed partitions return `INSUFFICIENT_THREAT` before model training, even when aggregate held-out counts meet the stated minimums.

## Channel ablation

Each attribution removes one channel before training. NoiseBench freezes the attacker family, hyperparameters, splits, seeds, and bootstrap, then retrains and reevaluates on the ablated training, validation, and test views. A channel is named only when the full longitudinal claim fails and the paired ablation drop's lower bound reaches 500 basis points.

Removing a feature from an already fitted model is not a V1 ablation.

## Verdict precedence

NoiseBench evaluates outcomes in this order:

1. `INVALID_EVIDENCE`: malformed schema, false or inconsistent coverage evidence, broken linkage or sequence, or hash mismatch.
2. `INSUFFICIENT_THREAT`: unknown or low coverage, too few held-out actors or decisions, failed shadow control, or a confidence interval that crosses the claim threshold.
3. `CLAIM_REJECTED`: the lower confidence bound of the bundle-only or longitudinal advantage exceeds 500 basis points.
4. `CLAIM_SUPPORTED`: both upper confidence bounds are at or below 500 basis points.

The final verdict is scoped to the declared dataset, observer profile, feature set, attacker family, metric, threshold, and confidence level. Reports list untested channels beside every result.

## Report V1

`noisebench audit DATASET --json report.json` writes `noisebench/report/v1` with these fields:

| Field | Meaning |
| --- | --- |
| `dataset_sha256` | Verified dataset address, or `null` when integrity failed before an address could be trusted. |
| `verdict` | One of the four verdicts above. |
| `primary_reason_code` | The main machine-readable cause. |
| `reason_codes` | Sorted causes that support the verdict. |
| `exit_code` | `0`, `2`, `3`, or `4`. |
| `scope` | Dataset ID, observer, features, attacker, metric, threshold, and confidence. `null` for invalid evidence. |
| `integrity` | Validity flag and checks performed or failed. |
| `coverage` | Expected, observed, and scoreable counts plus coverage basis points. |
| `power` | Held-out actors, scoreable held-out decisions, shadow result, and adequacy. |
| `estimates` | Bundle-only and longitudinal point estimates with lower and upper bounds. |
| `channel_contributions` | Full, retrained-ablated, and paired-drop estimates for each channel. |
| `tested_channels` | Channels confidently named for a rejected longitudinal claim. |
| `untested_channels` | Observer signals outside V1. |
| `control_label` | `SYNTHETIC_CALIBRATION_CONTROL` only for the pinned positive control. |
| `component_hashes` | Verified manifest, public, and label addresses. |
| `tool` | NoiseBench version and optional build-time source commit. |

All estimates use signed integer basis points. Missing statistical sections are `null` or empty when an earlier precedence rule stops the audit.

## Exporter checklist

- Export all expected decisions, including refusals.
- Use stable actor and destination pseudonyms within each history.
- Emit public evidence for every fixed seed. Omitted declared seeds are invalid evidence.
- Keep private labels out of public identifiers and timestamps.
- Validate contiguous sequence indexes and one-to-one labels.
- Seal the final canonical records, then stop mutating them.
- Record the planner version, 40-character source commit when available, and integer-only configuration.
- Run `noisebench audit DATASET --json report.json` and preserve the dataset directory with the report.
