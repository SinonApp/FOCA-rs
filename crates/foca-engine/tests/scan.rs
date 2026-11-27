//! Scan runs: stages, lifecycle, sources, deadlines, resume.

mod common;

mod scan {
    mod auto_resume;
    mod crawl;
    mod followup;
    mod lifecycle;
    mod mobile_cap;
    mod render_sources;
    mod rescan_sources;
    mod scan_steps;
    mod search_resilience;
    mod source_deadline;
    mod sources;
    mod stages;
}
