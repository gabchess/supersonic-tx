# NoiseBench

Noise is easy to add. Privacy is harder to prove.

A transaction can look ambiguous once and still identify its owner after repeated use. NoiseBench tests that gap. It replays public planner traces in sequence, trains the same attacker on bundle-only and full-history views, and refuses claims that the evidence cannot support.

## Run the proof

You need Rust 1.89 or newer.

```bash
git clone --branch feat/noisebench-audit-public --single-branch https://github.com/gabchess/supersonic-tx.git
cd supersonic-tx
```

Then run the pinned reference suite:

```bash
./scripts/noisebench suite fixtures/
```

The launcher supports POSIX shells and also finds Rust at the default `~/.cargo/bin/cargo` path. On Windows, run the equivalent Cargo command:

```powershell
cargo run --release --locked -- suite fixtures/
```

Expected result:

```text
exchangeable-control: CLAIM_SUPPORTED (scoped_claim_supported) [match]
invalid-evidence: INVALID_EVIDENCE (content_hash_mismatch) [match]
longitudinal-leak: CLAIM_REJECTED (longitudinal_claim_exceeded) [match]
low-signal: INSUFFICIENT_THREAT (coverage_below_minimum) [match]
4/4 expected outcomes matched
```

The suite proves the gate, not a production planner. Its four pinned fixtures force NoiseBench to separate four different evidence states:

| Fixture | Why it exists | Required result |
| --- | --- | --- |
| `exchangeable-control` | Synthetic positive control with known exchangeability | `CLAIM_SUPPORTED` |
| `longitudinal-leak` | Bundle-level ambiguity with a repeated destination signal | `CLAIM_REJECTED` |
| `low-signal` | Valid evidence with only 10% declared coverage | `INSUFFICIENT_THREAT` |
| `invalid-evidence` | A valid label changed after the dataset was sealed | `INVALID_EVIDENCE` |

The calibrated leak fixture has a bundle-only advantage of -180 basis points (95% CI -430 to 80). The full-history attacker reaches 6,790 basis points (95% CI 6,700 to 6,880), and retrained ablation names `destination_history`. The positive control stays below the 500 basis point claim threshold in both views. These measurements apply only to the checked-in synthetic fixtures.

## Verdicts and exits

| Verdict or failure | Exit | Meaning |
| --- | ---: | --- |
| `CLAIM_SUPPORTED` | 0 | Both tested views stay at or below the declared threshold at the declared confidence level. |
| `CLAIM_REJECTED` | 2 | At least one tested view exceeds the threshold with confidence. |
| `INSUFFICIENT_THREAT` | 3 | The evidence is valid, but coverage, power, attacker sanity, or confidence is too weak. |
| `INVALID_EVIDENCE` | 4 | Schema, linkage, sequence, coverage consistency, or content addressing failed. |
| CLI misuse | 64 | The command or arguments are invalid. |
| Internal failure | 70 | NoiseBench could not complete or write the requested report. |

`CLAIM_SUPPORTED` means supported under the declared dataset, observer profile, feature set, attacker family, metric, threshold, and confidence level. It never means "this planner is private." Every supported report prints this scope and lists untested channels.

## Audit a planner

An adapter exports three files:

```text
my-traces/
├── manifest.json
├── public-traces.jsonl
└── private-labels.jsonl
```

Then run:

```bash
./scripts/noisebench audit my-traces/ --json report.json
```

The [V1 adapter guide](docs/noisebench-v1.md) defines every field, validation rule, hash, and frozen parameter.

## Frozen method

NoiseBench V1 fixes the method so a planner cannot tune the test after seeing a result:

1. Strict parsing rejects duplicate and unknown keys.
2. SHA-256 addresses the canonical manifest, public traces, private labels, and full dataset.
3. Actor-level 60/20/20 splits run across five fixed seeds.
4. A train-only z-scored logistic ranker tests bundle-only and causal full-history views.
5. A deterministic 10,000-replicate actor-cluster bootstrap estimates top-1 advantage over chance.
6. Each channel ablation retrains the same pipeline on ablated train, validation, and test views.
7. Integrity and evidence-sufficiency checks run before claim evaluation.

The full-history view uses only prior public rows for the same actor and seed. Private labels mark the correct candidate; they never enter a feature.

## Content addressing

NoiseBench sorts records before hashing, encodes each JSON value without floats, and terminates every JSONL record with a newline. The dataset address is:

```text
SHA256(
  "noisebench/dataset/v1\0" ||
  manifest_sha256_bytes ||
  public_sha256_bytes ||
  labels_sha256_bytes
)
```

The manifest component excludes `manifest_sha256` and `dataset_sha256` from its own preimage. A hash makes evidence content-addressed and tamper-evident. It is not a signature.

## Tested channels

V1 tests candidate amount shape and ordinal, destination history, amount history, amount transitions, and prior ordinal recurrence.

V1 does not test candidate-conditioned timing, program, asset, or bundle-size interactions; RPC or network timing; validator-private information; funding graphs; external identity; pre-dataset history; recovery transactions; cross-wallet coordination; compromised hosts; or any observer signal absent from the schema. Reports carry this list.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
sh tests/entrypoint_contract.sh
./scripts/noisebench suite fixtures/
```

CI runs these commands with Rust 1.89. The reference generator is deterministic and guarded against accidental fixture replacement:

```bash
NOISEBENCH_REGENERATE=1 cargo test --test regenerate_fixtures --locked -- --ignored
```

Changing a fixture requires reviewing and committing its new content address. Do not update a pin to make a failing result pass.

## Limits

NoiseBench is a regression gate for a declared observer and attacker. It does not prove anonymity, model every Solana observer, inspect live traffic, or certify a planner. A planner can pass V1 and still leak through an untested channel. The right response is to add a preregistered adapter, observer feature, or attacker version, then rerun the evidence.

Licensed under MIT.
