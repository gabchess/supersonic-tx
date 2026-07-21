#[test]
fn package_exposes_v1_report_schema() {
    assert_eq!(noisebench::REPORT_SCHEMA, "noisebench/report/v1");
}
