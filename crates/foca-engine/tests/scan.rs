//! Scan runs: stages, lifecycle, sources, deadlines, resume.

mod common;

mod scan {
    mod auto_resume;
    mod lifecycle;
    mod render_sources;
    mod rescan_sources;
    mod scan_steps;
    mod source_deadline;
    mod sources;
    mod stages;
}
