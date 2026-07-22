use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::schema::{parse_strict, Manifest, PrivateLabel, PublicTrace, SchemaError};

const DATASET_DOMAIN: &[u8] = b"noisebench/dataset/v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAddress {
    pub manifest_sha256: String,
    pub public_sha256: String,
    pub labels_sha256: String,
    pub dataset_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    Sufficient,
    Unknown,
    BelowMinimum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEvidence {
    pub expected_decisions: Option<u64>,
    pub observed_decisions: u64,
    pub scoreable_decisions: u64,
    pub coverage_bps: Option<u16>,
    pub status: CoverageStatus,
}

#[derive(Debug)]
pub struct LoadedDataset {
    pub manifest: Manifest,
    pub public: Vec<PublicTrace>,
    pub labels: BTreeMap<String, PrivateLabel>,
    pub address: ContentAddress,
    pub coverage: CoverageEvidence,
}

pub fn address_dataset(
    manifest: &Manifest,
    public: &[PublicTrace],
    labels: &[PrivateLabel],
) -> Result<ContentAddress, IntegrityError> {
    let public_bytes = canonical_jsonl(public, |trace| {
        (
            trace.seed,
            trace.actor_id.clone(),
            trace.sequence_index,
            trace.trace_id.clone(),
        )
    })?;
    let label_bytes = canonical_jsonl(labels, |label| label.trace_id.clone())?;
    let manifest_bytes = canonical_manifest(manifest)?;
    let public_digest = Sha256::digest(&public_bytes);
    let label_digest = Sha256::digest(&label_bytes);
    let manifest_digest = Sha256::digest(&manifest_bytes);
    let mut dataset = Sha256::new();
    dataset.update(DATASET_DOMAIN);
    dataset.update(manifest_digest);
    dataset.update(public_digest);
    dataset.update(label_digest);
    Ok(ContentAddress {
        manifest_sha256: hex_digest(&manifest_digest),
        public_sha256: hex_digest(&public_digest),
        labels_sha256: hex_digest(&label_digest),
        dataset_sha256: hex_digest(&dataset.finalize()),
    })
}

pub fn seal_dataset(
    manifest: &mut Manifest,
    public: &[PublicTrace],
    labels: &[PrivateLabel],
) -> Result<ContentAddress, IntegrityError> {
    manifest.validate_v1()?;
    for trace in public {
        trace.validate_v1(manifest)?;
    }
    for label in labels {
        label.validate_v1()?;
    }
    let public_bytes = canonical_jsonl(public, |trace| {
        (
            trace.seed,
            trace.actor_id.clone(),
            trace.sequence_index,
            trace.trace_id.clone(),
        )
    })?;
    let label_bytes = canonical_jsonl(labels, |label| label.trace_id.clone())?;
    manifest.hashes.public_sha256 = hex_digest(&Sha256::digest(public_bytes));
    manifest.hashes.labels_sha256 = hex_digest(&Sha256::digest(label_bytes));
    manifest.hashes.manifest_sha256 = "0".repeat(64);
    manifest.hashes.dataset_sha256 = "0".repeat(64);
    let addressed = address_dataset(manifest, public, labels)?;
    manifest.hashes.manifest_sha256 = addressed.manifest_sha256.clone();
    manifest.hashes.dataset_sha256 = addressed.dataset_sha256.clone();
    Ok(addressed)
}

pub fn write_canonical_dataset(
    path: &Path,
    manifest: &Manifest,
    public: &[PublicTrace],
    labels: &[PrivateLabel],
) -> Result<(), IntegrityError> {
    if path.exists() {
        if fs::read_dir(path)?.next().transpose()?.is_some() {
            return Err(IntegrityError::OutputNotEmpty);
        }
    } else {
        fs::create_dir_all(path)?;
    }
    let mut manifest_bytes = canonical_value_bytes(&serde_json::to_value(manifest)?)?;
    manifest_bytes.push(b'\n');
    fs::write(path.join("manifest.json"), manifest_bytes)?;
    fs::write(
        path.join("public-traces.jsonl"),
        canonical_jsonl(public, |trace| {
            (
                trace.seed,
                trace.actor_id.clone(),
                trace.sequence_index,
                trace.trace_id.clone(),
            )
        })?,
    )?;
    fs::write(
        path.join("private-labels.jsonl"),
        canonical_jsonl(labels, |label| label.trace_id.clone())?,
    )?;
    Ok(())
}

pub fn load_dataset(path: &Path) -> Result<LoadedDataset, IntegrityError> {
    let manifest: Manifest = parse_strict(&fs::read(path.join("manifest.json"))?)?;
    manifest.validate_v1()?;
    let public: Vec<PublicTrace> = read_jsonl(&path.join("public-traces.jsonl"))?;
    let labels: Vec<PrivateLabel> = read_jsonl(&path.join("private-labels.jsonl"))?;
    for trace in &public {
        trace.validate_v1(&manifest)?;
    }
    for label in &labels {
        label.validate_v1()?;
    }
    validate_sequences_and_linkage(&public, &labels)?;
    let coverage = coverage_evidence(&manifest, &public)?;
    let address = address_dataset(&manifest, &public, &labels)?;
    for (name, declared, computed) in [
        (
            "manifest",
            &manifest.hashes.manifest_sha256,
            &address.manifest_sha256,
        ),
        (
            "public",
            &manifest.hashes.public_sha256,
            &address.public_sha256,
        ),
        (
            "labels",
            &manifest.hashes.labels_sha256,
            &address.labels_sha256,
        ),
        (
            "dataset",
            &manifest.hashes.dataset_sha256,
            &address.dataset_sha256,
        ),
    ] {
        if declared != computed {
            return Err(IntegrityError::ContentHashMismatch {
                component: name,
                declared: declared.clone(),
                computed: computed.clone(),
            });
        }
    }
    let observed_seeds: BTreeSet<_> = public.iter().map(|trace| trace.seed).collect();
    if manifest
        .split
        .seeds
        .iter()
        .any(|seed| !observed_seeds.contains(seed))
    {
        return Err(IntegrityError::LinkageInvalid(
            "declared split seed has no public trace",
        ));
    }
    Ok(LoadedDataset {
        manifest,
        public,
        labels: labels
            .into_iter()
            .map(|label| (label.trace_id.clone(), label))
            .collect(),
        address,
        coverage,
    })
}

fn coverage_evidence(
    manifest: &Manifest,
    public: &[PublicTrace],
) -> Result<CoverageEvidence, IntegrityError> {
    let observed_decisions = public.len() as u64;
    let scoreable_decisions = public
        .iter()
        .filter(|trace| trace.refusal.is_none())
        .count() as u64;
    let (coverage_bps, status) = match manifest.coverage.expected_decisions {
        None => (None, CoverageStatus::Unknown),
        Some(0) => return Err(IntegrityError::CoverageInconsistent),
        Some(expected) if observed_decisions > expected => {
            return Err(IntegrityError::CoverageInconsistent)
        }
        Some(expected) => {
            let basis_points =
                ((u128::from(scoreable_decisions) * 10_000) / u128::from(expected)) as u16;
            let status = if basis_points >= manifest.coverage.minimum_bps {
                CoverageStatus::Sufficient
            } else {
                CoverageStatus::BelowMinimum
            };
            (Some(basis_points), status)
        }
    };
    Ok(CoverageEvidence {
        expected_decisions: manifest.coverage.expected_decisions,
        observed_decisions,
        scoreable_decisions,
        coverage_bps,
        status,
    })
}

fn validate_sequences_and_linkage(
    public: &[PublicTrace],
    labels: &[PrivateLabel],
) -> Result<(), IntegrityError> {
    let mut traces = BTreeMap::new();
    let mut sequences: BTreeMap<(u64, &str), BTreeSet<u64>> = BTreeMap::new();
    for trace in public {
        if traces.insert(trace.trace_id.as_str(), trace).is_some() {
            return Err(IntegrityError::LinkageInvalid("duplicate trace id"));
        }
        sequences
            .entry((trace.seed, trace.actor_id.as_str()))
            .or_default()
            .insert(trace.sequence_index);
    }
    for indexes in sequences.values() {
        if indexes.iter().copied().ne(0..indexes.len() as u64) {
            return Err(IntegrityError::SequenceInvalid);
        }
    }
    let mut label_ids = BTreeSet::new();
    for label in labels {
        if !label_ids.insert(label.trace_id.as_str()) {
            return Err(IntegrityError::LinkageInvalid("duplicate private label"));
        }
        let trace = traces
            .get(label.trace_id.as_str())
            .ok_or(IntegrityError::LinkageInvalid("label without public trace"))?;
        if trace.refusal.is_some()
            || !trace
                .candidates
                .iter()
                .any(|candidate| candidate.candidate_id == label.true_candidate_id)
        {
            return Err(IntegrityError::LinkageInvalid(
                "label does not name a scoreable candidate",
            ));
        }
    }
    for trace in public {
        if trace.refusal.is_none() != label_ids.contains(trace.trace_id.as_str()) {
            return Err(IntegrityError::LinkageInvalid(
                "scoreable and label records are not one-to-one",
            ));
        }
    }
    Ok(())
}

fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, IntegrityError> {
    let bytes = fs::read(path)?;
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        return Err(IntegrityError::JsonLineNotTerminated);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| IntegrityError::InvalidUtf8)?;
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            if line.is_empty() {
                return Err(IntegrityError::EmptyJsonLine(index + 1));
            }
            Ok(parse_strict(line.as_bytes())?)
        })
        .collect()
}

fn canonical_manifest(manifest: &Manifest) -> Result<Vec<u8>, IntegrityError> {
    let mut value = serde_json::to_value(manifest)?;
    let hashes = value
        .get_mut("hashes")
        .and_then(Value::as_object_mut)
        .ok_or(IntegrityError::Canonicalization)?;
    hashes.remove("manifest_sha256");
    hashes.remove("dataset_sha256");
    canonical_value_bytes(&value)
}

fn canonical_jsonl<T, K>(values: &[T], key: impl Fn(&T) -> K) -> Result<Vec<u8>, IntegrityError>
where
    T: Serialize + Clone,
    K: Ord,
{
    let mut values = values.to_vec();
    values.sort_by_key(key);
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend(canonical_value_bytes(&serde_json::to_value(value)?)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn canonical_value_bytes(value: &Value) -> Result<Vec<u8>, IntegrityError> {
    if contains_float(value) {
        return Err(IntegrityError::Canonicalization);
    }
    Ok(serde_json::to_vec(value)?)
}

fn contains_float(value: &Value) -> bool {
    match value {
        Value::Number(number) => !(number.is_i64() || number.is_u64()),
        Value::Array(values) => values.iter().any(contains_float),
        Value::Object(values) => values.values().any(contains_float),
        _ => false,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Schema(#[from] SchemaError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("dataset directory is not empty")]
    OutputNotEmpty,
    #[error("dataset contains invalid UTF-8")]
    InvalidUtf8,
    #[error("JSONL line {0} is empty")]
    EmptyJsonLine(usize),
    #[error("JSONL records must end with a newline")]
    JsonLineNotTerminated,
    #[error("dataset cannot be canonically encoded")]
    Canonicalization,
    #[error("coverage evidence is internally inconsistent")]
    CoverageInconsistent,
    #[error("trace sequence is not contiguous from zero")]
    SequenceInvalid,
    #[error("dataset linkage is invalid: {0}")]
    LinkageInvalid(&'static str),
    #[error("{component} hash mismatch: declared {declared}, computed {computed}")]
    ContentHashMismatch {
        component: &'static str,
        declared: String,
        computed: String,
    },
}
