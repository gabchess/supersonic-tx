use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    attackers::{split_actor, Split},
    integrity::{load_dataset, CoverageStatus, IntegrityError, LoadedDataset},
    report::{
        report_schema, tool_report, ChannelContributionReport, ComponentHashesReport,
        CoverageReport, EstimatesReport, IntegrityReport, PowerReport, ReportV1, ScopeReport,
    },
    statistics::{analyze_dataset, StatisticalEvidence, StatisticsError},
};

pub const UNTESTED_CHANNELS: [&str; 8] = [
    "RPC and network timing",
    "validator-private information",
    "funding graphs and external identity",
    "history before the dataset begins",
    "recovery and consolidation transactions",
    "cross-wallet coordination",
    "a compromised host",
    "observer signals absent from the schema",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    ClaimSupported,
    ClaimRejected,
    InsufficientThreat,
    InvalidEvidence,
}

impl Verdict {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::ClaimSupported => 0,
            Self::ClaimRejected => 2,
            Self::InsufficientThreat => 3,
            Self::InvalidEvidence => 4,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimSupported => "CLAIM_SUPPORTED",
            Self::ClaimRejected => "CLAIM_REJECTED",
            Self::InsufficientThreat => "INSUFFICIENT_THREAT",
            Self::InvalidEvidence => "INVALID_EVIDENCE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    SchemaInvalid,
    CoverageInconsistent,
    ContentHashMismatch,
    LinkageInvalid,
    SequenceInvalid,
    CoverageUnknown,
    CoverageBelowMinimum,
    SamplePowerBelowMinimum,
    AttackerSanityFailed,
    ConfidenceInconclusive,
    BundleClaimExceeded,
    LongitudinalClaimExceeded,
    BundleAndLongitudinalClaimExceeded,
    ScopedClaimSupported,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchemaInvalid => "schema_invalid",
            Self::CoverageInconsistent => "coverage_inconsistent",
            Self::ContentHashMismatch => "content_hash_mismatch",
            Self::LinkageInvalid => "linkage_invalid",
            Self::SequenceInvalid => "sequence_invalid",
            Self::CoverageUnknown => "coverage_unknown",
            Self::CoverageBelowMinimum => "coverage_below_minimum",
            Self::SamplePowerBelowMinimum => "sample_power_below_minimum",
            Self::AttackerSanityFailed => "attacker_sanity_failed",
            Self::ConfidenceInconclusive => "confidence_inconclusive",
            Self::BundleClaimExceeded => "bundle_claim_exceeded",
            Self::LongitudinalClaimExceeded => "longitudinal_claim_exceeded",
            Self::BundleAndLongitudinalClaimExceeded => "bundle_and_longitudinal_claim_exceeded",
            Self::ScopedClaimSupported => "scoped_claim_supported",
        }
    }
}

pub fn audit_path(path: &Path) -> ReportV1 {
    match audit_path_result(path) {
        Ok(report) => report,
        Err(error) => invalid_report(ReasonCode::SchemaInvalid, error.to_string()),
    }
}

pub fn audit_path_result(path: &Path) -> Result<ReportV1, AuditError> {
    audit_path_result_inner(path, false)
}

pub(crate) fn audit_fixture_path_result(path: &Path) -> Result<ReportV1, AuditError> {
    audit_path_result_inner(path, true)
}

fn audit_path_result_inner(
    path: &Path,
    allow_fixture_expectation: bool,
) -> Result<ReportV1, AuditError> {
    let dataset = match load_dataset(path) {
        Ok(dataset) => dataset,
        Err(error) => {
            return Ok(invalid_report(
                reason_for_integrity(&error),
                error.to_string(),
            ))
        }
    };
    if !allow_fixture_expectation && dataset.manifest.expected_fixture_result.is_some() {
        return Ok(invalid_report(
            ReasonCode::SchemaInvalid,
            "expected_fixture_result is reserved for the reference suite".into(),
        ));
    }
    let mut insufficient_reasons = coverage_reason(&dataset).into_iter().collect::<Vec<_>>();
    let (held_out_actors, scoreable_decisions, every_split_populated) =
        raw_held_out_power(&dataset);
    if held_out_actors < dataset.manifest.power.minimum_held_out_actors
        || scoreable_decisions < dataset.manifest.power.minimum_scoreable_decisions
        || !every_split_populated
    {
        insufficient_reasons.push(ReasonCode::SamplePowerBelowMinimum);
    }
    if !insufficient_reasons.is_empty() {
        return Ok(valid_report(
            &dataset,
            Verdict::InsufficientThreat,
            insufficient_reasons,
            None,
            false,
        ));
    }
    let evidence = analyze_dataset(&dataset)?;
    Ok(assess_dataset(&dataset, evidence))
}

fn raw_held_out_power(dataset: &LoadedDataset) -> (u64, u64, bool) {
    let scoreable: Vec<_> = dataset
        .public
        .iter()
        .filter(|trace| trace.refusal.is_none())
        .collect();
    let populated: BTreeSet<_> = scoreable
        .iter()
        .map(|trace| (trace.seed, split_actor(&trace.actor_id, trace.seed)))
        .collect();
    let every_split_populated = dataset.manifest.split.seeds.iter().all(|seed| {
        [Split::Train, Split::Validation, Split::Test]
            .into_iter()
            .all(|split| populated.contains(&(*seed, split)))
    });
    let held_out: Vec<_> = scoreable
        .into_iter()
        .filter(|trace| split_actor(&trace.actor_id, trace.seed) == Split::Test)
        .collect();
    let actors = held_out
        .iter()
        .map(|trace| (trace.seed, trace.actor_id.as_str()))
        .collect::<BTreeSet<_>>()
        .len() as u64;
    (actors, held_out.len() as u64, every_split_populated)
}

pub fn assess_dataset(dataset: &LoadedDataset, evidence: StatisticalEvidence) -> ReportV1 {
    let mut insufficient_reasons = coverage_reason(dataset).into_iter().collect::<Vec<_>>();
    let enough_actors = evidence.held_out_actors >= dataset.manifest.power.minimum_held_out_actors;
    let enough_decisions =
        evidence.scoreable_decisions >= dataset.manifest.power.minimum_scoreable_decisions;
    if !enough_actors || !enough_decisions {
        insufficient_reasons.push(ReasonCode::SamplePowerBelowMinimum);
    }
    if evidence.shadow.lower_bps < i32::from(dataset.manifest.power.shadow_min_advantage_bps) {
        insufficient_reasons.push(ReasonCode::AttackerSanityFailed);
    }
    if !insufficient_reasons.is_empty() {
        return valid_report(
            dataset,
            Verdict::InsufficientThreat,
            insufficient_reasons,
            Some(evidence),
            false,
        );
    }
    let threshold = i32::from(dataset.manifest.claim.max_advantage_bps);
    let bundle_rejected = evidence.bundle_only.lower_bps > threshold;
    let longitudinal_rejected = evidence.longitudinal.lower_bps > threshold;
    if bundle_rejected || longitudinal_rejected {
        let reason = match (bundle_rejected, longitudinal_rejected) {
            (true, true) => ReasonCode::BundleAndLongitudinalClaimExceeded,
            (true, false) => ReasonCode::BundleClaimExceeded,
            (false, true) => ReasonCode::LongitudinalClaimExceeded,
            (false, false) => unreachable!(),
        };
        return valid_report(
            dataset,
            Verdict::ClaimRejected,
            vec![reason],
            Some(evidence),
            true,
        );
    }
    if evidence.bundle_only.upper_bps <= threshold && evidence.longitudinal.upper_bps <= threshold {
        return valid_report(
            dataset,
            Verdict::ClaimSupported,
            vec![ReasonCode::ScopedClaimSupported],
            Some(evidence),
            false,
        );
    }
    valid_report(
        dataset,
        Verdict::InsufficientThreat,
        vec![ReasonCode::ConfidenceInconclusive],
        Some(evidence),
        false,
    )
}

fn coverage_reason(dataset: &LoadedDataset) -> Option<ReasonCode> {
    match dataset.coverage.status {
        CoverageStatus::Sufficient => None,
        CoverageStatus::Unknown => Some(ReasonCode::CoverageUnknown),
        CoverageStatus::BelowMinimum => Some(ReasonCode::CoverageBelowMinimum),
    }
}

fn valid_report(
    dataset: &LoadedDataset,
    verdict: Verdict,
    mut reasons: Vec<ReasonCode>,
    evidence: Option<StatisticalEvidence>,
    name_channels: bool,
) -> ReportV1 {
    reasons.sort_by_key(|reason| reason.as_str());
    let primary_reason_code = reasons[0];
    let mut tested_channels: Vec<_> = evidence
        .as_ref()
        .filter(|_| name_channels)
        .into_iter()
        .flat_map(|evidence| &evidence.channel_contributions)
        .filter(|contribution| {
            evidence.as_ref().is_some_and(|evidence| {
                evidence.longitudinal.lower_bps
                    > i32::from(dataset.manifest.claim.max_advantage_bps)
            }) && contribution.drop.lower_bps
                >= i32::from(dataset.manifest.claim.channel_contribution_min_drop_bps)
        })
        .map(|contribution| contribution.channel.as_str().to_owned())
        .collect();
    tested_channels.sort();
    let mut channel_contributions: Vec<_> = evidence
        .as_ref()
        .map(|evidence| {
            evidence
                .channel_contributions
                .iter()
                .map(|contribution| ChannelContributionReport {
                    channel: contribution.channel.as_str().into(),
                    full_point_bps: contribution.full.point_bps,
                    ablated_point_bps: contribution.ablated.point_bps,
                    drop_point_bps: contribution.drop.point_bps,
                    drop_lower_bps: contribution.drop.lower_bps,
                    drop_upper_bps: contribution.drop.upper_bps,
                })
                .collect()
        })
        .unwrap_or_default();
    channel_contributions.sort_by(|left, right| left.channel.cmp(&right.channel));
    let power = evidence.as_ref().map(|evidence| PowerReport {
        held_out_actors: evidence.held_out_actors,
        scoreable_decisions: evidence.scoreable_decisions,
        shadow_advantage_bps: evidence.shadow.point_bps,
        shadow_lower_bps: evidence.shadow.lower_bps,
        adequate: evidence.held_out_actors >= dataset.manifest.power.minimum_held_out_actors
            && evidence.scoreable_decisions >= dataset.manifest.power.minimum_scoreable_decisions
            && evidence.shadow.lower_bps
                >= i32::from(dataset.manifest.power.shadow_min_advantage_bps),
    });
    let estimates = evidence.as_ref().map(|evidence| EstimatesReport {
        bundle_only: evidence.bundle_only,
        longitudinal: evidence.longitudinal,
    });
    let mut checks = vec!["schema", "linkage", "coverage", "content_address"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    checks.sort();
    let mut untested_channels = UNTESTED_CHANNELS
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    untested_channels.sort();
    ReportV1 {
        schema: report_schema(),
        dataset_sha256: Some(dataset.address.dataset_sha256.clone()),
        verdict,
        primary_reason_code,
        reason_codes: reasons,
        exit_code: verdict.exit_code(),
        scope: Some(scope(dataset)),
        integrity: IntegrityReport {
            valid: true,
            checks,
        },
        coverage: CoverageReport {
            expected_decisions: dataset.coverage.expected_decisions,
            observed_decisions: Some(dataset.coverage.observed_decisions),
            scoreable_decisions: Some(dataset.coverage.scoreable_decisions),
            coverage_bps: dataset.coverage.coverage_bps,
        },
        power,
        estimates,
        channel_contributions,
        tested_channels,
        untested_channels,
        control_label: None,
        component_hashes: Some(ComponentHashesReport {
            manifest_sha256: dataset.address.manifest_sha256.clone(),
            public_sha256: dataset.address.public_sha256.clone(),
            labels_sha256: dataset.address.labels_sha256.clone(),
        }),
        tool: tool_report(),
    }
}

fn invalid_report(reason: ReasonCode, check: String) -> ReportV1 {
    let verdict = Verdict::InvalidEvidence;
    let mut untested_channels = UNTESTED_CHANNELS
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    untested_channels.sort();
    ReportV1 {
        schema: report_schema(),
        dataset_sha256: None,
        verdict,
        primary_reason_code: reason,
        reason_codes: vec![reason],
        exit_code: verdict.exit_code(),
        scope: None,
        integrity: IntegrityReport {
            valid: false,
            checks: vec![check],
        },
        coverage: CoverageReport {
            expected_decisions: None,
            observed_decisions: None,
            scoreable_decisions: None,
            coverage_bps: None,
        },
        power: None,
        estimates: None,
        channel_contributions: Vec::new(),
        tested_channels: Vec::new(),
        untested_channels,
        control_label: None,
        component_hashes: None,
        tool: tool_report(),
    }
}

fn scope(dataset: &LoadedDataset) -> ScopeReport {
    ScopeReport {
        dataset_id: dataset.manifest.dataset_id.clone(),
        observer_profile: dataset.manifest.observer_profile.clone(),
        feature_version: dataset.manifest.feature_version.clone(),
        attacker_family: dataset.manifest.attacker.family.clone(),
        metric: "macro-actor-top1-advantage/v1".into(),
        max_advantage_bps: dataset.manifest.claim.max_advantage_bps,
        confidence_bps: dataset.manifest.claim.confidence_bps,
    }
}

fn reason_for_integrity(error: &IntegrityError) -> ReasonCode {
    match error {
        IntegrityError::CoverageInconsistent => ReasonCode::CoverageInconsistent,
        IntegrityError::ContentHashMismatch { .. } => ReasonCode::ContentHashMismatch,
        IntegrityError::LinkageInvalid(_) => ReasonCode::LinkageInvalid,
        IntegrityError::SequenceInvalid => ReasonCode::SequenceInvalid,
        _ => ReasonCode::SchemaInvalid,
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error(transparent)]
    Statistics(#[from] StatisticsError),
}
