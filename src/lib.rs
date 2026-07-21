pub mod attackers;
pub mod features;
pub mod integrity;
pub mod report;
pub mod schema;
pub mod statistics;
pub mod verdict;

use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    schema::{parse_strict, Manifest},
    verdict::{audit_fixture_path_result, AuditError, ReasonCode, Verdict},
};

pub const REPORT_SCHEMA: &str = "noisebench/report/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuitePin {
    pub fixture: String,
    pub verdict: Verdict,
    pub primary_reason_code: ReasonCode,
    pub dataset_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuitePins {
    pub schema: String,
    pub fixtures: Vec<SuitePin>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuiteEntry {
    pub fixture: String,
    pub verdict: Verdict,
    pub primary_reason_code: ReasonCode,
    pub dataset_sha256: String,
    pub expected_match: bool,
    pub report: crate::report::ReportV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuiteReport {
    pub entries: Vec<SuiteEntry>,
}

impl SuiteReport {
    pub fn matches_all_expected(&self) -> bool {
        self.entries.len() == 4 && self.entries.iter().all(|entry| entry.expected_match)
    }
}

pub fn run_suite(root: &Path) -> Result<SuiteReport, SuiteError> {
    let pins: SuitePins = parse_strict(&fs::read(root.join("expected.json"))?)?;
    if pins.schema != "noisebench/suite-pins/v1" || pins.fixtures.len() != 4 {
        return Err(SuiteError::Pins);
    }
    let mut sorted = pins.fixtures.clone();
    sorted.sort_by(|left, right| left.fixture.cmp(&right.fixture));
    if sorted != pins.fixtures {
        return Err(SuiteError::Pins);
    }
    let mut unique = BTreeMap::new();
    let mut entries = Vec::new();
    for pin in pins.fixtures {
        if unique.insert(pin.fixture.clone(), ()).is_some() {
            return Err(SuiteError::Pins);
        }
        let path = root.join(&pin.fixture);
        let manifest: Manifest = parse_strict(&fs::read(path.join("manifest.json"))?)?;
        let declared = manifest
            .expected_fixture_result
            .as_ref()
            .ok_or(SuiteError::Pins)?;
        let mut report = audit_fixture_path_result(&path)?;
        let expected_match = report.verdict == pin.verdict
            && report.primary_reason_code == pin.primary_reason_code
            && manifest.hashes.dataset_sha256 == pin.dataset_sha256
            && declared.verdict == pin.verdict.as_str()
            && declared.reason_code == pin.primary_reason_code.as_str();
        if expected_match && pin.fixture == "exchangeable-control" {
            report.control_label = Some("SYNTHETIC_CALIBRATION_CONTROL".into());
        } else {
            report.control_label = None;
        }
        entries.push(SuiteEntry {
            fixture: pin.fixture,
            verdict: report.verdict,
            primary_reason_code: report.primary_reason_code,
            dataset_sha256: manifest.hashes.dataset_sha256,
            expected_match,
            report,
        });
    }
    Ok(SuiteReport { entries })
}

#[derive(Debug, Error)]
pub enum SuiteError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Schema(#[from] crate::schema::SchemaError),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error("suite pins are malformed, duplicated, or unsorted")]
    Pins,
}
