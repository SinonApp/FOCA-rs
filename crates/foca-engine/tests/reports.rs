//! Reports and insights after scans.

mod common;

mod reports {
    // Builds reports with foca_report directly.
    #[cfg(feature = "report")]
    mod all_rules_lang;
    #[cfg(feature = "report")]
    mod blocked_scope;
    mod insights;
    // Uses foca_report directly (custody hashes), which is linked only with the `report` feature.
    #[cfg(feature = "report")]
    mod report_after_scan;
    mod report_company;
}
