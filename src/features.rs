use std::collections::BTreeMap;

use thiserror::Error;

use crate::{integrity::LoadedDataset, schema::Candidate};

// ponytail: V1 omits trace-level context until candidate-linked interactions can rank it.
const BUNDLE_NAMES: [&str; 6] = [
    "intercept",
    "amount_digits",
    "amount_roundness",
    "ordinal_ratio",
    "amount_rank",
    "nearest_amount_gap",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeatureChannel {
    DestinationHistory,
    AmountHistory,
    Transitions,
    PriorOrdinal,
}

impl FeatureChannel {
    pub const ALL: [Self; 4] = [
        Self::DestinationHistory,
        Self::AmountHistory,
        Self::Transitions,
        Self::PriorOrdinal,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DestinationHistory => "destination_history",
            Self::AmountHistory => "amount_history",
            Self::Transitions => "transitions",
            Self::PriorOrdinal => "prior_ordinal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureMode {
    BundleOnly,
    Longitudinal { omit: Option<FeatureChannel> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateFeatures {
    pub candidate_id: String,
    pub is_true: bool,
    pub values: Vec<f64>,
}

impl CandidateFeatures {
    pub fn feature(&self, names: &[&'static str], name: &str) -> f64 {
        let index = names
            .iter()
            .position(|candidate| *candidate == name)
            .unwrap();
        self.values[index]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankedObservation {
    pub trace_id: String,
    pub seed: u64,
    pub actor_id: String,
    pub sequence_index: u64,
    pub chance: f64,
    feature_names: Vec<&'static str>,
    pub candidates: Vec<CandidateFeatures>,
}

impl RankedObservation {
    pub fn new(
        trace_id: impl Into<String>,
        seed: u64,
        actor_id: impl Into<String>,
        sequence_index: u64,
        chance: f64,
        feature_names: Vec<&'static str>,
        candidates: Vec<CandidateFeatures>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            seed,
            actor_id: actor_id.into(),
            sequence_index,
            chance,
            feature_names,
            candidates,
        }
    }

    pub fn candidate(&self, id: &str) -> &CandidateFeatures {
        self.candidates
            .iter()
            .find(|row| row.candidate_id == id)
            .unwrap()
    }

    pub fn feature_names(&self) -> &[&'static str] {
        &self.feature_names
    }
}

#[derive(Default)]
struct History {
    decisions: u64,
    destinations: BTreeMap<String, (u64, u64)>,
    amounts: BTreeMap<u128, u64>,
    previous_destinations: Vec<String>,
    previous_amounts: Vec<u128>,
    ordinals: BTreeMap<u32, u64>,
}

pub fn build_feature_view(
    dataset: &LoadedDataset,
    mode: FeatureMode,
) -> Result<Vec<RankedObservation>, FeatureError> {
    let mut traces: Vec<_> = dataset.public.iter().collect();
    traces.sort_by_key(|trace| {
        (
            trace.seed,
            trace.actor_id.as_str(),
            trace.sequence_index,
            trace.trace_id.as_str(),
        )
    });
    let names = feature_names(mode);
    let mut histories: BTreeMap<(u64, String), History> = BTreeMap::new();
    let mut rows = Vec::new();
    for trace in traces {
        let history = histories
            .entry((trace.seed, trace.actor_id.clone()))
            .or_default();
        if trace.refusal.is_none() {
            let label = dataset
                .labels
                .get(&trace.trace_id)
                .ok_or(FeatureError::MissingLabel)?;
            let amounts: Vec<u128> = trace
                .candidates
                .iter()
                .map(|candidate| {
                    candidate
                        .amount_atoms
                        .parse()
                        .map_err(|_| FeatureError::Amount)
                })
                .collect::<Result<_, _>>()?;
            let candidates = trace
                .candidates
                .iter()
                .enumerate()
                .map(|(index, candidate)| {
                    let values = candidate_values(candidate, index, &amounts, trace, history, mode);
                    CandidateFeatures {
                        candidate_id: candidate.candidate_id.clone(),
                        is_true: candidate.candidate_id == label.true_candidate_id,
                        values,
                    }
                })
                .collect();
            rows.push(RankedObservation {
                trace_id: trace.trace_id.clone(),
                seed: trace.seed,
                actor_id: trace.actor_id.clone(),
                sequence_index: trace.sequence_index,
                chance: 1.0 / trace.candidates.len() as f64,
                feature_names: names.clone(),
                candidates,
            });
        }
        update_history(history, trace)?;
    }
    Ok(rows)
}

fn candidate_values(
    candidate: &Candidate,
    index: usize,
    amounts: &[u128],
    trace: &crate::schema::PublicTrace,
    history: &History,
    mode: FeatureMode,
) -> Vec<f64> {
    let amount = amounts[index];
    let digits = candidate.amount_atoms.len() as f64;
    let trailing = candidate
        .amount_atoms
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'0')
        .count() as f64;
    let rank = amounts.iter().filter(|other| **other < amount).count() as f64;
    let nearest = amounts
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != index)
        .map(|(_, other)| amount.abs_diff(*other))
        .min()
        .unwrap_or(0);
    let mut values = vec![
        1.0,
        digits,
        trailing / digits.max(1.0),
        candidate.ordinal as f64 / (trace.candidates.len() - 1) as f64,
        rank / (trace.candidates.len() - 1) as f64,
        (nearest as f64 + 1.0).ln(),
    ];
    let FeatureMode::Longitudinal { omit } = mode else {
        return values;
    };
    let denom = history.decisions.max(1) as f64;
    if omit != Some(FeatureChannel::DestinationHistory) {
        let (count, last) = history
            .destinations
            .get(&candidate.destination_id)
            .copied()
            .unwrap_or((0, 0));
        values.extend([
            count as f64 / denom,
            if count == 0 {
                0.0
            } else {
                1.0 / (1 + trace.sequence_index.saturating_sub(last)) as f64
            },
            history
                .previous_destinations
                .iter()
                .filter(|old| **old == candidate.destination_id)
                .count() as f64
                / history.previous_destinations.len().max(1) as f64,
        ]);
    }
    if omit != Some(FeatureChannel::AmountHistory) {
        let count = history.amounts.get(&amount).copied().unwrap_or(0);
        let distance = history
            .amounts
            .keys()
            .map(|old| old.abs_diff(amount))
            .min()
            .unwrap_or(0);
        values.extend([count as f64 / denom, (distance as f64 + 1.0).ln()]);
    }
    if omit != Some(FeatureChannel::Transitions) {
        values.push(
            history
                .previous_amounts
                .iter()
                .filter(|old| **old == amount)
                .count() as f64
                / history.previous_amounts.len().max(1) as f64,
        );
    }
    if omit != Some(FeatureChannel::PriorOrdinal) {
        values.push(
            history
                .ordinals
                .get(&candidate.ordinal)
                .copied()
                .unwrap_or(0) as f64
                / denom,
        );
    }
    values
}

fn feature_names(mode: FeatureMode) -> Vec<&'static str> {
    let mut names = BUNDLE_NAMES.to_vec();
    let FeatureMode::Longitudinal { omit } = mode else {
        return names;
    };
    for (channel, channel_names) in [
        (
            FeatureChannel::DestinationHistory,
            &[
                "destination_frequency",
                "destination_recency",
                "destination_transition_frequency",
            ][..],
        ),
        (
            FeatureChannel::AmountHistory,
            &["amount_frequency", "amount_distance"][..],
        ),
        (
            FeatureChannel::Transitions,
            &["amount_transition_frequency"][..],
        ),
        (
            FeatureChannel::PriorOrdinal,
            &["prior_ordinal_recurrence"][..],
        ),
    ] {
        if omit != Some(channel) {
            names.extend(channel_names);
        }
    }
    names
}

fn update_history(
    history: &mut History,
    trace: &crate::schema::PublicTrace,
) -> Result<(), FeatureError> {
    history.decisions += 1;
    history.previous_destinations = trace
        .candidates
        .iter()
        .map(|candidate| candidate.destination_id.clone())
        .collect();
    history.previous_amounts.clear();
    for candidate in &trace.candidates {
        let amount: u128 = candidate
            .amount_atoms
            .parse()
            .map_err(|_| FeatureError::Amount)?;
        history.previous_amounts.push(amount);
        let entry = history
            .destinations
            .entry(candidate.destination_id.clone())
            .or_insert((0, 0));
        entry.0 += 1;
        entry.1 = trace.sequence_index;
        *history.amounts.entry(amount).or_default() += 1;
        *history.ordinals.entry(candidate.ordinal).or_default() += 1;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum FeatureError {
    #[error("scoreable trace has no private label")]
    MissingLabel,
    #[error("invalid amount reached feature extraction")]
    Amount,
}
