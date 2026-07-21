use serde::{Deserialize, Serialize};

use crate::{
    statistics::EstimateBps,
    verdict::{ReasonCode, Verdict},
    REPORT_SCHEMA,
};

pub const SUPPORTED_SCOPE_NOTICE: &str = "Supported only under the declared dataset, observer profile, feature set, attacker family, metric, 5% threshold, and 95% confidence level. This is not a claim that the planner is private.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportV1 {
    pub schema: String,
    pub dataset_sha256: Option<String>,
    pub verdict: Verdict,
    pub primary_reason_code: ReasonCode,
    pub reason_codes: Vec<ReasonCode>,
    pub exit_code: u8,
    pub scope: Option<ScopeReport>,
    pub integrity: IntegrityReport,
    pub coverage: CoverageReport,
    pub power: Option<PowerReport>,
    pub estimates: Option<EstimatesReport>,
    pub channel_contributions: Vec<ChannelContributionReport>,
    pub tested_channels: Vec<String>,
    pub untested_channels: Vec<String>,
    pub control_label: Option<String>,
    pub component_hashes: Option<ComponentHashesReport>,
    pub tool: ToolReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeReport {
    pub dataset_id: String,
    pub observer_profile: String,
    pub feature_version: String,
    pub attacker_family: String,
    pub metric: String,
    pub max_advantage_bps: u16,
    pub confidence_bps: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntegrityReport {
    pub valid: bool,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoverageReport {
    pub expected_decisions: Option<u64>,
    pub observed_decisions: Option<u64>,
    pub scoreable_decisions: Option<u64>,
    pub coverage_bps: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PowerReport {
    pub held_out_actors: u64,
    pub scoreable_decisions: u64,
    pub shadow_advantage_bps: i32,
    pub shadow_lower_bps: i32,
    pub adequate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EstimatesReport {
    pub bundle_only: EstimateBps,
    pub longitudinal: EstimateBps,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelContributionReport {
    pub channel: String,
    pub full_point_bps: i32,
    pub ablated_point_bps: i32,
    pub drop_point_bps: i32,
    pub drop_lower_bps: i32,
    pub drop_upper_bps: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComponentHashesReport {
    pub manifest_sha256: String,
    pub public_sha256: String,
    pub labels_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolReport {
    pub version: String,
    pub source_commit: Option<String>,
}

pub fn render_terminal(report: &ReportV1) -> String {
    let mut lines = vec![format!(
        "{} ({}) [exit {}]",
        report.verdict.as_str(),
        report.primary_reason_code.as_str(),
        report.exit_code
    )];
    if report.reason_codes.len() > 1 {
        lines.push(format!(
            "{} additional reason{}",
            report.reason_codes.len() - 1,
            if report.reason_codes.len() == 2 {
                ""
            } else {
                "s"
            }
        ));
    }
    if let Some(dataset) = &report.dataset_sha256 {
        lines.push(format!("dataset: {dataset}"));
    }
    if let Some(estimates) = &report.estimates {
        lines.push(format!(
            "bundle advantage: {} bps (95% CI {}..{})",
            estimates.bundle_only.point_bps,
            estimates.bundle_only.lower_bps,
            estimates.bundle_only.upper_bps
        ));
        lines.push(format!(
            "longitudinal advantage: {} bps (95% CI {}..{})",
            estimates.longitudinal.point_bps,
            estimates.longitudinal.lower_bps,
            estimates.longitudinal.upper_bps
        ));
    }
    if report.verdict == Verdict::ClaimSupported {
        lines.push(SUPPORTED_SCOPE_NOTICE.into());
    }
    if !report.tested_channels.is_empty() {
        lines.push(format!(
            "named channels: {}",
            report.tested_channels.join(", ")
        ));
    }
    lines.push("Untested channels:".into());
    lines.extend(
        report
            .untested_channels
            .iter()
            .map(|channel| format!("- {channel}")),
    );
    lines.join("\n")
}

pub(crate) fn tool_report() -> ToolReport {
    ToolReport {
        version: env!("CARGO_PKG_VERSION").into(),
        source_commit: option_env!("NOISEBENCH_SOURCE_COMMIT").map(str::to_owned),
    }
}

pub(crate) fn report_schema() -> String {
    REPORT_SCHEMA.into()
}
