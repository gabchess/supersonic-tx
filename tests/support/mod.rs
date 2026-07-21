#![allow(dead_code)]

use std::{collections::BTreeMap, fs, path::Path};

use noisebench::{
    attackers::{split_actor, Split},
    features::{CandidateFeatures, RankedObservation},
    integrity::{seal_dataset, write_canonical_dataset, LoadedDataset},
    schema::{
        AttackerConfig, BootstrapConfig, Bundle, Candidate, ClaimConfig, CoverageConfig,
        ExpectedFixtureResult, Hashes, Manifest, PowerConfig, PrivateLabel, Producer, PublicTrace,
        SplitConfig,
    },
    verdict::{ReasonCode, Verdict},
    SuitePin, SuitePins,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

pub fn manifest(expected_decisions: Option<u64>) -> Manifest {
    Manifest {
        schema: "noisebench/manifest/v1".into(),
        dataset_id: "test-dataset".into(),
        public_trace_schema: "noisebench/public-trace/v1".into(),
        private_label_schema: "noisebench/private-label/v1".into(),
        producer: Producer {
            name: "noisebench-tests".into(),
            version: "1".into(),
            source_commit: None,
            configuration: json!({"fixture": true}),
        },
        observer_profile: "noisebench-observer/v1".into(),
        feature_version: "noisebench-features/v1".into(),
        attacker: AttackerConfig {
            family: "regularized-logistic-ranker/v1".into(),
            learning_rate_micros: 10_000,
            l2_micros: 1_000,
            training_steps: 400,
            preprocessing: "train-zscore/v1".into(),
            tie_break: "candidate-id-lexicographic/v1".into(),
        },
        split: SplitConfig {
            unit: "actor".into(),
            train_bps: 6_000,
            validation_bps: 2_000,
            test_bps: 2_000,
            seeds: vec![11, 23, 47, 71, 101],
        },
        bootstrap: BootstrapConfig {
            seed: 31_337,
            replicates: 10_000,
        },
        coverage: CoverageConfig {
            expected_decisions,
            minimum_bps: 9_500,
        },
        claim: ClaimConfig {
            max_advantage_bps: 500,
            confidence_bps: 9_500,
            channel_contribution_min_drop_bps: 500,
        },
        power: PowerConfig {
            minimum_held_out_actors: 100,
            minimum_scoreable_decisions: 1_000,
            shadow_rule: "seeded-extreme-ordinal/v1".into(),
            shadow_seed: 424_242,
            shadow_min_advantage_bps: 1_000,
        },
        hashes: Hashes {
            public_sha256: "0".repeat(64),
            labels_sha256: "0".repeat(64),
            manifest_sha256: "0".repeat(64),
            dataset_sha256: "0".repeat(64),
        },
        expected_fixture_result: None::<ExpectedFixtureResult>,
    }
}

pub fn valid_dataset(reverse_lines: bool) -> (Manifest, Vec<PublicTrace>, Vec<PrivateLabel>) {
    let make_trace = |seed: u64, index: u64| PublicTrace {
        schema: "noisebench/public-trace/v1".into(),
        trace_id: format!("t-{seed}-{index}"),
        seed,
        actor_id: "actor-a".into(),
        sequence_index: index,
        observed_time_bucket: index * 10,
        bundle: Bundle {
            program_id: "program".into(),
            asset_id: "asset".into(),
        },
        candidates: vec![
            Candidate {
                candidate_id: format!("t-{seed}-{index}-c-0"),
                ordinal: 0,
                destination_id: "destination-a".into(),
                amount_atoms: "10".into(),
            },
            Candidate {
                candidate_id: format!("t-{seed}-{index}-c-1"),
                ordinal: 1,
                destination_id: "destination-b".into(),
                amount_atoms: "20".into(),
            },
        ],
        refusal: None,
    };
    let mut public: Vec<_> = noisebench::schema::SPLIT_SEEDS
        .into_iter()
        .flat_map(|seed| [make_trace(seed, 0), make_trace(seed, 1)])
        .collect();
    let mut labels: Vec<_> = public
        .iter()
        .map(|trace| PrivateLabel {
            schema: "noisebench/private-label/v1".into(),
            trace_id: trace.trace_id.clone(),
            true_candidate_id: trace.candidates[0].candidate_id.clone(),
        })
        .collect();
    if reverse_lines {
        public.reverse();
        labels.reverse();
    }
    (manifest(Some(10)), public, labels)
}

pub fn write_valid_dataset() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, public, labels) = valid_dataset(false);
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    dir
}

pub fn copy_fixture_for_audit(name: &str) -> TempDir {
    let source = Path::new("fixtures").join(name);
    let mut manifest: Manifest =
        noisebench::schema::parse_strict(&fs::read(source.join("manifest.json")).unwrap()).unwrap();
    let public = fs::read_to_string(source.join("public-traces.jsonl"))
        .unwrap()
        .lines()
        .map(|line| noisebench::schema::parse_strict(line.as_bytes()).unwrap())
        .collect::<Vec<PublicTrace>>();
    let labels = fs::read_to_string(source.join("private-labels.jsonl"))
        .unwrap()
        .lines()
        .map(|line| noisebench::schema::parse_strict(line.as_bytes()).unwrap())
        .collect::<Vec<PrivateLabel>>();
    manifest.expected_fixture_result = None;
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    let dir = tempfile::tempdir().unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    if name == "invalid-evidence" {
        let path = dir.path().join("private-labels.jsonl");
        let text = fs::read_to_string(&path).unwrap();
        fs::write(
            path,
            text.replacen("\"true_candidate_id\"", "\"tampered\"", 1),
        )
        .unwrap();
    }
    dir
}

pub fn write_aggregate_powered_split_gap_dataset() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, mut public, mut labels) = fixture_dataset(
        "split-gap",
        FixtureKind::Exchangeable,
        Verdict::ClaimSupported,
        ReasonCode::ScopedClaimSupported,
    );
    public.retain(|trace| {
        trace.seed != 11 || split_actor(&trace.actor_id, trace.seed) == Split::Test
    });
    labels.retain(|label| public.iter().any(|trace| trace.trace_id == label.trace_id));
    manifest.dataset_id = "split-gap".into();
    manifest.coverage.expected_decisions = Some(public.len() as u64);
    manifest.expected_fixture_result = None;
    manifest.producer.configuration = json!({"test": "aggregate-power-split-gap"});
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    dir
}

pub fn mutate_first_label(path: &Path) {
    let label_path = path.join("private-labels.jsonl");
    let text = fs::read_to_string(&label_path).unwrap();
    fs::write(label_path, text.replacen("-c-0\"", "-c-1\"", 1)).unwrap();
}

pub fn load_valid_dataset() -> LoadedDataset {
    let dir = write_valid_dataset();
    noisebench::integrity::load_dataset(dir.path()).unwrap()
}

pub fn two_step_dataset() -> LoadedDataset {
    load_valid_dataset()
}

pub fn scaling_probe() -> Vec<RankedObservation> {
    observations_for_each_split(4, 2)
}

pub fn large_exchangeable_view() -> Vec<RankedObservation> {
    observations_for_each_split(40, 4)
}

pub fn known_predictions() -> Vec<noisebench::attackers::Prediction> {
    let mut rows = Vec::new();
    for (actor, correct_count) in [("actor-a", 3_usize), ("actor-b", 2_usize)] {
        for index in 0..4 {
            rows.push(noisebench::attackers::Prediction {
                seed: 11,
                actor_id: actor.into(),
                trace_id: format!("{actor}-{index}"),
                correct: index < correct_count,
                chance: 0.5,
            });
        }
    }
    rows
}

pub fn full_predictions() -> Vec<noisebench::attackers::Prediction> {
    known_predictions()
}

pub fn ablated_predictions() -> Vec<noisebench::attackers::Prediction> {
    known_predictions()
        .into_iter()
        .enumerate()
        .map(|(index, mut row)| {
            if index == 2 || index == 6 {
                row.correct = false;
            }
            row
        })
        .collect()
}

pub fn supported_report() -> noisebench::report::ReportV1 {
    let dataset = load_valid_dataset();
    noisebench::verdict::assess_dataset(
        &dataset,
        noisebench::statistics::StatisticalEvidence {
            bundle_only: estimate(0, -100, 100),
            longitudinal: estimate(0, -100, 100),
            shadow: estimate(2_500, 2_000, 3_000),
            held_out_actors: 100,
            scoreable_decisions: 1_000,
            channel_contributions: Vec::new(),
        },
    )
}

pub fn estimate(
    point_bps: i32,
    lower_bps: i32,
    upper_bps: i32,
) -> noisebench::statistics::EstimateBps {
    noisebench::statistics::EstimateBps {
        point_bps,
        lower_bps,
        upper_bps,
    }
}

fn observations_for_each_split(
    actors_per_split: usize,
    candidate_count: usize,
) -> Vec<RankedObservation> {
    let seed = 11;
    let mut counts = [0_usize; 3];
    let mut rows = Vec::new();
    for index in 0_u64.. {
        let actor_id = format!("probe-{index}");
        let split = split_actor(&actor_id, seed);
        let slot = match split {
            Split::Train => 0,
            Split::Validation => 1,
            Split::Test => 2,
        };
        if counts[slot] >= actors_per_split {
            if counts.into_iter().all(|count| count >= actors_per_split) {
                break;
            }
            continue;
        }
        counts[slot] += 1;
        let candidates = (0..candidate_count)
            .map(|ordinal| CandidateFeatures {
                candidate_id: format!("{actor_id}-c-{ordinal}"),
                is_true: ordinal == 0,
                values: vec![1.0, ordinal as f64 / (candidate_count - 1) as f64],
            })
            .collect();
        rows.push(RankedObservation::new(
            format!("trace-{actor_id}"),
            seed,
            actor_id,
            0,
            1.0 / candidate_count as f64,
            vec!["intercept", "ordinal_ratio"],
            candidates,
        ));
    }
    rows
}

pub fn generate_reference_fixtures(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if root.exists() {
        fs::remove_dir_all(root)?;
    }
    fs::create_dir_all(root)?;
    let specifications = [
        (
            "exchangeable-control",
            FixtureKind::Exchangeable,
            Verdict::ClaimSupported,
            ReasonCode::ScopedClaimSupported,
        ),
        (
            "invalid-evidence",
            FixtureKind::Invalid,
            Verdict::InvalidEvidence,
            ReasonCode::ContentHashMismatch,
        ),
        (
            "longitudinal-leak",
            FixtureKind::LongitudinalLeak,
            Verdict::ClaimRejected,
            ReasonCode::LongitudinalClaimExceeded,
        ),
        (
            "low-signal",
            FixtureKind::LowSignal,
            Verdict::InsufficientThreat,
            ReasonCode::CoverageBelowMinimum,
        ),
    ];
    let mut pins = Vec::new();
    for (name, kind, verdict, reason) in specifications {
        let (mut manifest, public, labels) = fixture_dataset(name, kind, verdict, reason);
        let address = seal_dataset(&mut manifest, &public, &labels)?;
        let path = root.join(name);
        write_canonical_dataset(&path, &manifest, &public, &labels)?;
        if kind == FixtureKind::Invalid {
            tamper_with_valid_alternate_label(&path)?;
        }
        pins.push(SuitePin {
            fixture: name.into(),
            verdict,
            primary_reason_code: reason,
            dataset_sha256: address.dataset_sha256,
        });
    }
    let pins = SuitePins {
        schema: "noisebench/suite-pins/v1".into(),
        fixtures: pins,
    };
    let mut bytes = serde_json::to_vec(&pins)?;
    bytes.push(b'\n');
    fs::write(root.join("expected.json"), bytes)?;
    Ok(())
}

pub fn directory_digest(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (relative, bytes) in files {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureKind {
    Exchangeable,
    Invalid,
    LongitudinalLeak,
    LowSignal,
}

fn fixture_dataset(
    name: &str,
    kind: FixtureKind,
    verdict: Verdict,
    reason: ReasonCode,
) -> (Manifest, Vec<PublicTrace>, Vec<PrivateLabel>) {
    let large = matches!(
        kind,
        FixtureKind::Exchangeable | FixtureKind::LongitudinalLeak
    );
    let seeds = vec![11, 23, 47, 71, 101];
    let actors_per_seed = if large {
        100
    } else if matches!(kind, FixtureKind::LowSignal | FixtureKind::Invalid) {
        4
    } else {
        20
    };
    let sequence_count = if large { 10 } else { 5 };
    let mut public = Vec::new();
    let mut labels = Vec::new();
    for seed in seeds {
        let actors = if large {
            exact_split_actors(name, seed)
        } else {
            (0..actors_per_seed)
                .map(|index| format!("{name}-s{seed}-a{index}"))
                .collect()
        };
        for actor in actors {
            for sequence in 0..sequence_count {
                let true_ordinal = deterministic_index(
                    if kind == FixtureKind::LongitudinalLeak {
                        "leak-label"
                    } else {
                        "control-label"
                    },
                    &actor,
                    seed,
                    sequence,
                    4,
                );
                let trace_id = format!("{name}-{seed}-{actor}-{sequence}");
                let candidates: Vec<_> = (0..4)
                    .map(|ordinal| {
                        let destination_id =
                            if kind == FixtureKind::LongitudinalLeak && ordinal == true_ordinal {
                                format!("signal-{actor}")
                            } else {
                                format!("decoy-{name}-{seed}-{actor}-{sequence}-{ordinal}")
                            };
                        Candidate {
                            candidate_id: format!("{trace_id}-c-{ordinal}"),
                            ordinal: ordinal as u32,
                            destination_id,
                            amount_atoms: (1_000
                                + deterministic_index(
                                    "amount",
                                    &actor,
                                    seed,
                                    sequence * 4 + ordinal,
                                    900_000,
                                ))
                            .to_string(),
                        }
                    })
                    .collect();
                labels.push(PrivateLabel {
                    schema: "noisebench/private-label/v1".into(),
                    trace_id: trace_id.clone(),
                    true_candidate_id: candidates[true_ordinal].candidate_id.clone(),
                });
                public.push(PublicTrace {
                    schema: "noisebench/public-trace/v1".into(),
                    trace_id,
                    seed,
                    actor_id: actor.clone(),
                    sequence_index: sequence as u64,
                    observed_time_bucket: sequence as u64 * 10,
                    bundle: Bundle {
                        program_id: "mock-outcome-router".into(),
                        asset_id: format!("mock-asset-{seed}"),
                    },
                    candidates,
                    refusal: None,
                });
            }
        }
    }
    let expected = if kind == FixtureKind::LowSignal {
        Some(1_000)
    } else {
        Some(public.len() as u64)
    };
    let mut manifest = manifest(expected);
    manifest.dataset_id = name.into();
    manifest.producer.configuration = if kind == FixtureKind::Exchangeable {
        json!({"control_label": "SYNTHETIC_CALIBRATION_CONTROL", "fixture": name})
    } else {
        json!({"fixture": name})
    };
    manifest.expected_fixture_result = Some(ExpectedFixtureResult {
        verdict: verdict.as_str().into(),
        reason_code: reason.as_str().into(),
    });
    (manifest, public, labels)
}

fn exact_split_actors(prefix: &str, seed: u64) -> Vec<String> {
    let targets = [
        (Split::Train, 60_usize),
        (Split::Validation, 20),
        (Split::Test, 20),
    ];
    let mut counts = BTreeMap::new();
    let mut actors = Vec::new();
    for index in 0_u64.. {
        let actor = format!("{prefix}-s{seed}-a{index}");
        let split = split_actor(&actor, seed);
        let target = targets
            .iter()
            .find(|(candidate, _)| *candidate == split)
            .unwrap()
            .1;
        let count = counts.entry(split).or_insert(0_usize);
        if *count < target {
            *count += 1;
            actors.push(actor);
        }
        if targets
            .iter()
            .all(|(split, target)| counts.get(split).copied().unwrap_or(0) == *target)
        {
            break;
        }
    }
    actors
}

fn deterministic_index(
    domain: &str,
    actor: &str,
    seed: u64,
    sequence: usize,
    upper: usize,
) -> usize {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(actor.as_bytes());
    hasher.update(seed.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    let digest = hasher.finalize();
    (u64::from_be_bytes(digest[..8].try_into().unwrap()) as usize) % upper
}

fn tamper_with_valid_alternate_label(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let public_text = fs::read_to_string(path.join("public-traces.jsonl"))?;
    let first_trace: PublicTrace = noisebench::schema::parse_strict(
        public_text
            .lines()
            .next()
            .ok_or("missing public trace")?
            .as_bytes(),
    )?;
    let label_path = path.join("private-labels.jsonl");
    let label_text = fs::read_to_string(&label_path)?;
    let mut lines: Vec<String> = label_text.lines().map(str::to_owned).collect();
    let label_index = lines
        .iter()
        .position(|line| {
            noisebench::schema::parse_strict::<PrivateLabel>(line.as_bytes())
                .is_ok_and(|label| label.trace_id == first_trace.trace_id)
        })
        .ok_or("missing label for first public trace")?;
    let mut first_label: PrivateLabel =
        noisebench::schema::parse_strict(lines[label_index].as_bytes())?;
    first_label.true_candidate_id = first_trace
        .candidates
        .iter()
        .find(|candidate| candidate.candidate_id != first_label.true_candidate_id)
        .ok_or("missing alternate candidate")?
        .candidate_id
        .clone();
    lines[label_index] = serde_json::to_string(&first_label)?;
    fs::write(label_path, format!("{}\n", lines.join("\n")))?;
    Ok(())
}

fn collect_files(
    root: &Path,
    path: &Path,
    files: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else {
            files.push((
                path.strip_prefix(root)?.to_string_lossy().into_owned(),
                fs::read(path)?,
            ));
        }
    }
    Ok(())
}
