use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{features::RankedObservation, schema::Manifest};

const SPLIT_DOMAIN: &[u8] = b"noisebench/split/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Split {
    Train,
    Validation,
    Test,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Prediction {
    pub seed: u64,
    pub actor_id: String,
    pub trace_id: String,
    pub correct: bool,
    pub chance: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttackRun {
    pub validation: Vec<Prediction>,
    pub test: Vec<Prediction>,
    pub scaling_sources: BTreeSet<Split>,
    pub scaling_means_by_seed: BTreeMap<u64, Vec<f64>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShadowRun {
    pub attack: AttackRun,
    pub test_accuracy: f64,
}

#[derive(Debug)]
struct Scaling {
    means: Vec<f64>,
    deviations: Vec<f64>,
}

#[derive(Debug)]
struct Model {
    scaling: Scaling,
    weights: Vec<f64>,
}

pub fn split_actor(actor_id: &str, seed: u64) -> Split {
    let mut hasher = Sha256::new();
    hasher.update(SPLIT_DOMAIN);
    hasher.update(seed.to_be_bytes());
    hasher.update(actor_id.as_bytes());
    let digest = hasher.finalize();
    let bucket = u64::from_be_bytes(digest[..8].try_into().expect("sha256 prefix")) % 10_000;
    match bucket {
        0..=5_999 => Split::Train,
        6_000..=7_999 => Split::Validation,
        _ => Split::Test,
    }
}

pub fn rank_scores(mut scores: Vec<(String, f64)>) -> Result<Vec<(String, f64)>, AttackerError> {
    if scores.iter().any(|(_, score)| !score.is_finite()) {
        return Err(AttackerError::NonFinite);
    }
    scores.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    Ok(scores)
}

pub fn run_attack(
    observations: &[RankedObservation],
    manifest: &Manifest,
) -> Result<AttackRun, AttackerError> {
    manifest.validate_v1()?;
    if observations.is_empty() {
        return Err(AttackerError::EmptyData);
    }
    validate_observations(observations, manifest)?;
    let mut by_seed: BTreeMap<u64, Vec<&RankedObservation>> = BTreeMap::new();
    for row in observations {
        by_seed.entry(row.seed).or_default().push(row);
    }
    let mut validation = Vec::new();
    let mut test = Vec::new();
    let mut scaling_means_by_seed = BTreeMap::new();
    for (seed, rows) in by_seed {
        let train: Vec<_> = rows
            .iter()
            .copied()
            .filter(|row| split_actor(&row.actor_id, seed) == Split::Train)
            .collect();
        let validation_rows: Vec<_> = rows
            .iter()
            .copied()
            .filter(|row| split_actor(&row.actor_id, seed) == Split::Validation)
            .collect();
        let test_rows: Vec<_> = rows
            .iter()
            .copied()
            .filter(|row| split_actor(&row.actor_id, seed) == Split::Test)
            .collect();
        if train.is_empty() || validation_rows.is_empty() || test_rows.is_empty() {
            return Err(AttackerError::EmptySplit(seed));
        }
        let model = fit_model(&train, manifest)?;
        scaling_means_by_seed.insert(seed, model.scaling.means.clone());
        validation.extend(predict(&model, &validation_rows)?);
        test.extend(predict(&model, &test_rows)?);
    }
    validation.sort_by(prediction_order);
    test.sort_by(prediction_order);
    Ok(AttackRun {
        validation,
        test,
        scaling_sources: BTreeSet::from([Split::Train]),
        scaling_means_by_seed,
    })
}

pub fn run_shadow_sanity(
    observations: &[RankedObservation],
    manifest: &Manifest,
) -> Result<ShadowRun, AttackerError> {
    let mut shadow = observations.to_vec();
    for row in &mut shadow {
        let ordinal_index = row
            .feature_names()
            .iter()
            .position(|name| *name == "ordinal_ratio")
            .ok_or(AttackerError::MissingOrdinal)?;
        let choose_final = (row.seed ^ manifest.power.shadow_seed) % 2 == 1;
        let target = row
            .candidates
            .iter()
            .min_by(|left, right| {
                let ordering = left.values[ordinal_index].total_cmp(&right.values[ordinal_index]);
                if choose_final {
                    ordering.reverse()
                } else {
                    ordering
                }
            })
            .ok_or(AttackerError::NoCandidates)?
            .candidate_id
            .clone();
        for candidate in &mut row.candidates {
            candidate.is_true = candidate.candidate_id == target;
        }
    }
    let attack = run_attack(&shadow, manifest)?;
    let correct = attack
        .test
        .iter()
        .filter(|prediction| prediction.correct)
        .count();
    let test_accuracy = correct as f64 / attack.test.len() as f64;
    Ok(ShadowRun {
        attack,
        test_accuracy,
    })
}

fn validate_observations(
    observations: &[RankedObservation],
    manifest: &Manifest,
) -> Result<(), AttackerError> {
    let width = observations
        .first()
        .and_then(|row| row.candidates.first())
        .map(|candidate| candidate.values.len())
        .ok_or(AttackerError::NoCandidates)?;
    for row in observations {
        if !manifest.split.seeds.contains(&row.seed)
            || row.candidates.len() < 2
            || row
                .candidates
                .iter()
                .filter(|candidate| candidate.is_true)
                .count()
                != 1
            || row.candidates.iter().any(|candidate| {
                candidate.values.len() != width
                    || candidate.values.iter().any(|value| !value.is_finite())
            })
            || !row.chance.is_finite()
            || !(0.0..=1.0).contains(&row.chance)
        {
            return Err(AttackerError::InvalidObservation);
        }
    }
    Ok(())
}

fn fit_model(rows: &[&RankedObservation], manifest: &Manifest) -> Result<Model, AttackerError> {
    let width = rows[0].candidates[0].values.len();
    let count = rows.iter().map(|row| row.candidates.len()).sum::<usize>() as f64;
    let mut means = vec![0.0; width];
    let mut squares = vec![0.0; width];
    for candidate in rows.iter().flat_map(|row| &row.candidates) {
        for (index, value) in candidate.values.iter().copied().enumerate() {
            means[index] += value;
            squares[index] += value * value;
        }
    }
    let mut deviations = vec![1.0; width];
    for index in 1..width {
        means[index] /= count;
        let variance = (squares[index] / count - means[index] * means[index]).max(0.0);
        let deviation = variance.sqrt();
        deviations[index] = if deviation > 1e-12 { deviation } else { 1.0 };
    }
    means[0] = 0.0;
    let scaling = Scaling { means, deviations };
    let mut weights = vec![0.0; width];
    let learning_rate = manifest.attacker.learning_rate_micros as f64 / 1_000_000.0;
    let l2 = manifest.attacker.l2_micros as f64 / 1_000_000.0;
    for _ in 0..manifest.attacker.training_steps {
        let mut gradient = vec![0.0; width];
        for candidate in rows.iter().flat_map(|row| &row.candidates) {
            let values = scaling.transform(&candidate.values);
            let probability = sigmoid(dot(&weights, &values));
            let residual = probability - f64::from(candidate.is_true);
            for (target, value) in gradient.iter_mut().zip(values) {
                *target += residual * value;
            }
        }
        for index in 0..width {
            gradient[index] /= count;
            if index != 0 {
                gradient[index] += l2 * weights[index];
            }
            weights[index] -= learning_rate * gradient[index];
        }
    }
    if weights.iter().any(|weight| !weight.is_finite()) {
        return Err(AttackerError::NonFinite);
    }
    Ok(Model { scaling, weights })
}

fn predict(model: &Model, rows: &[&RankedObservation]) -> Result<Vec<Prediction>, AttackerError> {
    rows.iter()
        .map(|row| {
            let scores = row
                .candidates
                .iter()
                .map(|candidate| {
                    (
                        candidate.candidate_id.clone(),
                        dot(&model.weights, &model.scaling.transform(&candidate.values)),
                    )
                })
                .collect();
            let predicted = rank_scores(scores)?
                .into_iter()
                .next()
                .ok_or(AttackerError::NoCandidates)?
                .0;
            let truth = row
                .candidates
                .iter()
                .find(|candidate| candidate.is_true)
                .ok_or(AttackerError::InvalidObservation)?;
            Ok(Prediction {
                seed: row.seed,
                actor_id: row.actor_id.clone(),
                trace_id: row.trace_id.clone(),
                correct: predicted == truth.candidate_id,
                chance: row.chance,
            })
        })
        .collect()
}

impl Scaling {
    fn transform(&self, values: &[f64]) -> Vec<f64> {
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if index == 0 {
                    *value
                } else {
                    (*value - self.means[index]) / self.deviations[index]
                }
            })
            .collect()
    }
}

fn prediction_order(left: &Prediction, right: &Prediction) -> std::cmp::Ordering {
    (left.seed, left.actor_id.as_str(), left.trace_id.as_str()).cmp(&(
        right.seed,
        right.actor_id.as_str(),
        right.trace_id.as_str(),
    ))
}

fn dot(left: &[f64], right: &[f64]) -> f64 {
    left.iter()
        .zip(right)
        .map(|(left, right)| left * right)
        .sum()
}

fn sigmoid(value: f64) -> f64 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exponential = value.exp();
        exponential / (1.0 + exponential)
    }
}

#[derive(Debug, Error)]
pub enum AttackerError {
    #[error(transparent)]
    Schema(#[from] crate::schema::SchemaError),
    #[error("attacker dataset is empty")]
    EmptyData,
    #[error("attacker seed {0} has an empty train, validation, or test split")]
    EmptySplit(u64),
    #[error("observation has no candidates")]
    NoCandidates,
    #[error("observation is invalid or has inconsistent features")]
    InvalidObservation,
    #[error("attacker produced a non-finite value")]
    NonFinite,
    #[error("shadow sanity requires the ordinal feature")]
    MissingOrdinal,
}
