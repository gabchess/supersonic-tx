use std::{collections::BTreeSet, fmt};

use serde::{
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Number, Value};
use thiserror::Error;

pub const MANIFEST_SCHEMA: &str = "noisebench/manifest/v1";
pub const PUBLIC_TRACE_SCHEMA: &str = "noisebench/public-trace/v1";
pub const PRIVATE_LABEL_SCHEMA: &str = "noisebench/private-label/v1";
pub const OBSERVER_PROFILE: &str = "noisebench-observer/v1";
pub const FEATURE_VERSION: &str = "noisebench-features/v1";
pub const SPLIT_SEEDS: [u64; 5] = [11, 23, 47, 71, 101];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub dataset_id: String,
    pub public_trace_schema: String,
    pub private_label_schema: String,
    pub producer: Producer,
    pub observer_profile: String,
    pub feature_version: String,
    pub attacker: AttackerConfig,
    pub split: SplitConfig,
    pub bootstrap: BootstrapConfig,
    pub coverage: CoverageConfig,
    pub claim: ClaimConfig,
    pub power: PowerConfig,
    pub hashes: Hashes,
    pub expected_fixture_result: Option<ExpectedFixtureResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub name: String,
    pub version: String,
    pub source_commit: Option<String>,
    pub configuration: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttackerConfig {
    pub family: String,
    pub learning_rate_micros: u64,
    pub l2_micros: u64,
    pub training_steps: u32,
    pub preprocessing: String,
    pub tie_break: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SplitConfig {
    pub unit: String,
    pub train_bps: u16,
    pub validation_bps: u16,
    pub test_bps: u16,
    pub seeds: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    pub seed: u64,
    pub replicates: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageConfig {
    pub expected_decisions: Option<u64>,
    pub minimum_bps: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClaimConfig {
    pub max_advantage_bps: u16,
    pub confidence_bps: u16,
    pub channel_contribution_min_drop_bps: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PowerConfig {
    pub minimum_held_out_actors: u64,
    pub minimum_scoreable_decisions: u64,
    pub shadow_rule: String,
    pub shadow_seed: u64,
    pub shadow_min_advantage_bps: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hashes {
    pub public_sha256: String,
    pub labels_sha256: String,
    pub manifest_sha256: String,
    pub dataset_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFixtureResult {
    pub verdict: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicTrace {
    pub schema: String,
    pub trace_id: String,
    pub seed: u64,
    pub actor_id: String,
    pub sequence_index: u64,
    pub observed_time_bucket: u64,
    pub bundle: Bundle,
    pub candidates: Vec<Candidate>,
    pub refusal: Option<Refusal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub program_id: String,
    pub asset_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub candidate_id: String,
    pub ordinal: u32,
    pub destination_id: String,
    pub amount_atoms: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivateLabel {
    pub schema: String,
    pub trace_id: String,
    pub true_candidate_id: String,
}

impl Manifest {
    pub fn validate_v1(&self) -> Result<(), SchemaError> {
        require(
            self.schema == MANIFEST_SCHEMA,
            "unsupported manifest schema",
        )?;
        require(!self.dataset_id.is_empty(), "empty dataset id")?;
        require(
            self.public_trace_schema == PUBLIC_TRACE_SCHEMA
                && self.private_label_schema == PRIVATE_LABEL_SCHEMA,
            "record schema mismatch",
        )?;
        require(
            !self.producer.name.is_empty() && !self.producer.version.is_empty(),
            "empty producer metadata",
        )?;
        require(
            self.producer
                .source_commit
                .as_ref()
                .is_none_or(|value| value.len() == 40 && is_lower_hex(value)),
            "invalid producer source commit",
        )?;
        require(
            self.producer.configuration.is_object()
                && configuration_is_canonicalizable(&self.producer.configuration),
            "producer configuration must be an integer-only JSON object",
        )?;
        require(
            self.observer_profile == OBSERVER_PROFILE && self.feature_version == FEATURE_VERSION,
            "observer or feature version mismatch",
        )?;
        require(
            self.attacker.family == "regularized-logistic-ranker/v1"
                && self.attacker.learning_rate_micros == 10_000
                && self.attacker.l2_micros == 1_000
                && self.attacker.training_steps == 400
                && self.attacker.preprocessing == "train-zscore/v1"
                && self.attacker.tie_break == "candidate-id-lexicographic/v1",
            "attacker contract mismatch",
        )?;
        require(
            self.split.unit == "actor"
                && self.split.train_bps == 6_000
                && self.split.validation_bps == 2_000
                && self.split.test_bps == 2_000
                && u32::from(self.split.train_bps)
                    + u32::from(self.split.validation_bps)
                    + u32::from(self.split.test_bps)
                    == 10_000
                && self.split.seeds == SPLIT_SEEDS,
            "split contract mismatch",
        )?;
        require(
            self.bootstrap.seed == 31_337 && self.bootstrap.replicates == 10_000,
            "bootstrap contract mismatch",
        )?;
        require(
            self.coverage.minimum_bps == 9_500,
            "coverage threshold mismatch",
        )?;
        require(
            self.claim.max_advantage_bps == 500
                && self.claim.confidence_bps == 9_500
                && self.claim.channel_contribution_min_drop_bps == 500,
            "claim contract mismatch",
        )?;
        require(
            self.power.minimum_held_out_actors >= 100
                && self.power.minimum_scoreable_decisions >= 1_000
                && self.power.shadow_rule == "seeded-extreme-ordinal/v1"
                && self.power.shadow_seed == 424_242
                && self.power.shadow_min_advantage_bps == 1_000,
            "power contract mismatch",
        )?;
        require(
            [
                &self.hashes.public_sha256,
                &self.hashes.labels_sha256,
                &self.hashes.manifest_sha256,
                &self.hashes.dataset_sha256,
            ]
            .into_iter()
            .all(|value| value.len() == 64 && is_lower_hex(value)),
            "invalid sha256 field",
        )?;
        if let Some(expected) = &self.expected_fixture_result {
            require(
                [
                    "CLAIM_SUPPORTED",
                    "CLAIM_REJECTED",
                    "INSUFFICIENT_THREAT",
                    "INVALID_EVIDENCE",
                ]
                .contains(&expected.verdict.as_str()),
                "invalid fixture verdict",
            )?;
            require(
                !expected.reason_code.is_empty(),
                "empty fixture reason code",
            )?;
        }
        Ok(())
    }
}

impl PublicTrace {
    pub fn validate_v1(&self, manifest: &Manifest) -> Result<(), SchemaError> {
        require(
            self.schema == PUBLIC_TRACE_SCHEMA,
            "unsupported public trace schema",
        )?;
        require(
            manifest.split.seeds.contains(&self.seed),
            "undeclared trace seed",
        )?;
        require(
            !self.trace_id.is_empty()
                && !self.actor_id.is_empty()
                && !self.bundle.program_id.is_empty()
                && !self.bundle.asset_id.is_empty(),
            "empty public trace identifier",
        )?;
        match &self.refusal {
            None => require(
                self.candidates.len() >= 2,
                "scoreable trace needs two candidates",
            )?,
            Some(refusal) => {
                require(
                    self.candidates.is_empty(),
                    "refusal cannot contain candidates",
                )?;
                require(!refusal.reason_code.is_empty(), "empty refusal reason")?;
            }
        }
        let mut ids = BTreeSet::new();
        for (index, candidate) in self.candidates.iter().enumerate() {
            require(
                candidate.ordinal as usize == index,
                "candidate ordinal mismatch",
            )?;
            require(
                !candidate.candidate_id.is_empty() && !candidate.destination_id.is_empty(),
                "empty candidate identifier",
            )?;
            require(
                ids.insert(candidate.candidate_id.as_str()),
                "duplicate candidate id",
            )?;
            require(valid_atoms(&candidate.amount_atoms), "invalid amount atoms")?;
        }
        Ok(())
    }
}

impl PrivateLabel {
    pub fn validate_v1(&self) -> Result<(), SchemaError> {
        require(
            self.schema == PRIVATE_LABEL_SCHEMA,
            "unsupported private label schema",
        )?;
        require(
            !self.trace_id.is_empty() && !self.true_candidate_id.is_empty(),
            "empty private label identifier",
        )
    }
}

pub fn parse_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SchemaError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(serde_json::from_value(value)?)
}

fn require(condition: bool, message: &'static str) -> Result<(), SchemaError> {
    condition.then_some(()).ok_or(SchemaError::Invalid(message))
}

fn valid_atoms(value: &str) -> bool {
    !value.is_empty()
        && value.parse::<u128>().is_ok()
        && (value == "0"
            || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn configuration_is_canonicalizable(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(number) => number.as_i64().is_some(),
        Value::Array(values) => values.iter().all(configuration_is_canonicalizable),
        Value::Object(values) => values.values().all(configuration_is_canonicalizable),
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(|number| StrictValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key: {key}"
                )));
            }
            let StrictValue(value) = entries.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("invalid NoiseBench schema: {0}")]
    Invalid(&'static str),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}
