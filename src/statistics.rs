use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    attackers::{run_attack, run_shadow_sanity, AttackerError, Prediction},
    features::{build_feature_view, FeatureChannel, FeatureError, FeatureMode},
    integrity::LoadedDataset,
};

type ClusterKey = (u64, String);
type PredictionKey = (u64, String, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EstimateBps {
    pub point_bps: i32,
    pub lower_bps: i32,
    pub upper_bps: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelContribution {
    pub channel: FeatureChannel,
    pub full: EstimateBps,
    pub ablated: EstimateBps,
    pub drop: EstimateBps,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatisticalEvidence {
    pub bundle_only: EstimateBps,
    pub longitudinal: EstimateBps,
    pub shadow: EstimateBps,
    pub held_out_actors: u64,
    pub scoreable_decisions: u64,
    pub channel_contributions: Vec<ChannelContribution>,
}

pub fn estimate_advantage(
    predictions: &[Prediction],
    replicates: usize,
    seed: u64,
) -> Result<EstimateBps, StatisticsError> {
    if predictions.is_empty() {
        return Err(StatisticsError::EmptyPredictions);
    }
    if replicates == 0 {
        return Err(StatisticsError::InvalidBootstrap);
    }
    let clusters = cluster_values(predictions)?;
    estimate_clusters(&clusters, replicates, seed)
}

pub fn estimate_paired_drop(
    full: &[Prediction],
    ablated: &[Prediction],
    replicates: usize,
    seed: u64,
) -> Result<EstimateBps, StatisticsError> {
    if full.is_empty() || ablated.is_empty() {
        return Err(StatisticsError::EmptyPredictions);
    }
    if replicates == 0 {
        return Err(StatisticsError::InvalidBootstrap);
    }
    let full = prediction_map(full)?;
    let ablated = prediction_map(ablated)?;
    if full.keys().ne(ablated.keys()) {
        return Err(StatisticsError::UnpairedPredictions);
    }
    let mut clusters: BTreeMap<ClusterKey, Vec<f64>> = BTreeMap::new();
    for (key, full_prediction) in full {
        let ablated_prediction = &ablated[&key];
        if (full_prediction.chance - ablated_prediction.chance).abs() > 1e-12 {
            return Err(StatisticsError::UnpairedPredictions);
        }
        clusters
            .entry((key.0, key.1))
            .or_default()
            .push(f64::from(full_prediction.correct) - f64::from(ablated_prediction.correct));
    }
    estimate_clusters(&cluster_means(clusters), replicates, seed)
}

pub fn analyze_dataset(dataset: &LoadedDataset) -> Result<StatisticalEvidence, StatisticsError> {
    let replicates = dataset.manifest.bootstrap.replicates as usize;
    let seed = dataset.manifest.bootstrap.seed;
    let bundle_view = build_feature_view(dataset, FeatureMode::BundleOnly)?;
    let full_view = build_feature_view(dataset, FeatureMode::Longitudinal { omit: None })?;
    let bundle_run = run_attack(&bundle_view, &dataset.manifest)?;
    let full_run = run_attack(&full_view, &dataset.manifest)?;
    let shadow_run = run_shadow_sanity(&full_view, &dataset.manifest)?;
    let bundle_only = estimate_advantage(&bundle_run.test, replicates, seed)?;
    let longitudinal = estimate_advantage(&full_run.test, replicates, seed)?;
    let shadow = estimate_advantage(&shadow_run.attack.test, replicates, seed)?;
    let mut channel_contributions = Vec::new();
    for channel in FeatureChannel::ALL {
        let view = build_feature_view(
            dataset,
            FeatureMode::Longitudinal {
                omit: Some(channel),
            },
        )?;
        let run = run_attack(&view, &dataset.manifest)?;
        channel_contributions.push(ChannelContribution {
            channel,
            full: longitudinal,
            ablated: estimate_advantage(&run.test, replicates, seed)?,
            drop: estimate_paired_drop(&full_run.test, &run.test, replicates, seed)?,
        });
    }
    channel_contributions.sort_by_key(|contribution| contribution.channel.as_str());
    let held_out_actors = full_run
        .test
        .iter()
        .map(|prediction| (prediction.seed, prediction.actor_id.as_str()))
        .collect::<BTreeSet<_>>()
        .len() as u64;
    Ok(StatisticalEvidence {
        bundle_only,
        longitudinal,
        shadow,
        held_out_actors,
        scoreable_decisions: full_run.test.len() as u64,
        channel_contributions,
    })
}

fn prediction_map(
    predictions: &[Prediction],
) -> Result<BTreeMap<PredictionKey, &Prediction>, StatisticsError> {
    let mut values = BTreeMap::new();
    for prediction in predictions {
        if !prediction.chance.is_finite() || !(0.0..=1.0).contains(&prediction.chance) {
            return Err(StatisticsError::NonFinitePrediction);
        }
        let key = (
            prediction.seed,
            prediction.actor_id.clone(),
            prediction.trace_id.clone(),
        );
        if values.insert(key, prediction).is_some() {
            return Err(StatisticsError::DuplicatePrediction);
        }
    }
    Ok(values)
}

fn cluster_values(
    predictions: &[Prediction],
) -> Result<BTreeMap<ClusterKey, f64>, StatisticsError> {
    let mut clusters: BTreeMap<ClusterKey, Vec<f64>> = BTreeMap::new();
    for prediction in prediction_map(predictions)?.into_values() {
        clusters
            .entry((prediction.seed, prediction.actor_id.clone()))
            .or_default()
            .push(f64::from(prediction.correct) - prediction.chance);
    }
    Ok(cluster_means(clusters))
}

fn cluster_means(clusters: BTreeMap<ClusterKey, Vec<f64>>) -> BTreeMap<ClusterKey, f64> {
    clusters
        .into_iter()
        .map(|(key, values)| {
            let mean = values.iter().sum::<f64>() / values.len() as f64;
            (key, mean)
        })
        .collect()
}

fn estimate_clusters(
    clusters: &BTreeMap<ClusterKey, f64>,
    replicates: usize,
    seed: u64,
) -> Result<EstimateBps, StatisticsError> {
    if clusters.is_empty() {
        return Err(StatisticsError::EmptyPredictions);
    }
    let values: Vec<f64> = clusters.values().copied().collect();
    let point = values.iter().sum::<f64>() / values.len() as f64;
    let mut rng = DeterministicRng::new(seed);
    let mut samples = Vec::with_capacity(replicates);
    for _ in 0..replicates {
        let total = (0..values.len())
            .map(|_| values[rng.index(values.len())])
            .sum::<f64>();
        samples.push(total / values.len() as f64);
    }
    samples.sort_by(f64::total_cmp);
    let last = samples.len() - 1;
    let lower = samples[last * 25 / 1_000];
    let upper = samples[last * 975 / 1_000];
    Ok(EstimateBps {
        point_bps: to_bps(point),
        lower_bps: to_bps(lower),
        upper_bps: to_bps(upper),
    })
}

fn to_bps(value: f64) -> i32 {
    (value * 10_000.0).round() as i32
}

struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn index(&mut self, upper: usize) -> usize {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        (value as usize) % upper
    }
}

#[derive(Debug, Error)]
pub enum StatisticsError {
    #[error(transparent)]
    Feature(#[from] FeatureError),
    #[error(transparent)]
    Attacker(#[from] AttackerError),
    #[error("predictions are empty")]
    EmptyPredictions,
    #[error("bootstrap replicate count must be positive")]
    InvalidBootstrap,
    #[error("prediction evidence is not paired")]
    UnpairedPredictions,
    #[error("duplicate prediction identity")]
    DuplicatePrediction,
    #[error("prediction contains a non-finite or invalid chance")]
    NonFinitePrediction,
}
