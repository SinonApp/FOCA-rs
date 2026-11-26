//! Narrowed run of chosen scan items (`scan_start { only: ["source:crt", "step:brute", ...] }`):
//! a follow-up or retry of items the user picked runs only the stages that own them.
//!
//! Item keys are those of `scan_control` (`stage:<id>`, `source:<id>`, `step:<id>`). A search
//! source brings the document pipeline (Download, Metadata, Analysis) for the documents it
//! finds; a subdomain step or the TLS source runs only that part of the Network stage; a whole
//! `stage:` item runs that stage with all its parts. The Report stage always runs.

use std::collections::BTreeSet;

use super::{control, RESOLVER_STEPS, SRC_SUBDOMAINS, SRC_TLS, STAGES};

/// Chosen items of a narrowed run.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Selection {
    items: Vec<(String, String)>,
    stages: BTreeSet<usize>,
}

fn pos(id: &str) -> usize {
    STAGES.iter().position(|x| x.0 == id).unwrap_or(0)
}

impl Selection {
    /// Parses item keys; `None` when no key names a known scan item (a normal scan).
    pub(crate) fn parse(keys: &[String]) -> Option<Selection> {
        let mut items = Vec::new();
        let mut stages = BTreeSet::new();
        let analysis = pos("analysis");
        for k in keys {
            let Some((kind, id)) = k.split_once(':') else {
                continue;
            };
            let Some(owner) = control::owner_stage(kind, id) else {
                continue;
            };
            // documents found or fetched again go through the rest of the document pipeline
            if owner <= analysis {
                stages.extend(owner..=analysis);
            } else {
                stages.insert(owner);
            }
            items.push((kind.to_string(), id.to_string()));
        }
        if items.is_empty() {
            return None;
        }
        stages.insert(pos("report"));
        Some(Selection { items, stages })
    }

    /// Item keys, as given.
    pub(crate) fn keys(&self) -> Vec<String> {
        self.items.iter().map(|(k, i)| format!("{k}:{i}")).collect()
    }

    /// Ids of the stages this run executes, in pipeline order.
    pub(crate) fn stage_ids(&self) -> Vec<&'static str> {
        self.stages.iter().map(|&i| STAGES[i].0).collect()
    }

    /// The stage runs in this selection.
    pub(crate) fn runs(&self, stage: usize) -> bool {
        self.stages.contains(&stage)
    }

    /// The first stage that runs.
    pub(crate) fn first(&self) -> usize {
        self.stages.first().copied().unwrap_or(0)
    }

    /// Position of a stage among the stages that run and their count, for progress.
    pub(crate) fn slot(&self, stage: usize) -> (usize, usize) {
        let rank = self.stages.iter().filter(|&&s| s < stage).count();
        (rank, self.stages.len())
    }

    fn has(&self, kind: &str, id: &str) -> bool {
        self.items.iter().any(|(k, i)| k == kind && i == id)
    }

    /// The whole stage was chosen (all its parts run as in a normal scan).
    pub(crate) fn whole(&self, stage: &str) -> bool {
        self.has("stage", stage)
    }

    /// A resolver step (`brute`, `permute`) runs: chosen alone, through the whole subdomain
    /// source or through the whole Network stage.
    pub(crate) fn step(&self, id: &str) -> bool {
        self.whole("network") || self.has("source", SRC_SUBDOMAINS) || self.has("step", id)
    }

    /// Subdomain enumeration runs at all.
    pub(crate) fn subdomains(&self) -> bool {
        RESOLVER_STEPS.iter().any(|s| self.step(s))
    }

    /// Only some resolver steps were chosen (no NSEC walk, no PTR pass).
    pub(crate) fn steps_only(&self) -> bool {
        !self.whole("network") && !self.has("source", SRC_SUBDOMAINS)
    }

    /// A source is part of this run: its stage was chosen whole, or the source itself (the
    /// subdomain source also through one of its steps). Sources without an owner stage (the CT
    /// host list `dns`, InternetDB, plugins) follow the stage that queries them.
    pub(crate) fn source(&self, id: &str) -> bool {
        if id == SRC_SUBDOMAINS {
            return self.subdomains();
        }
        match control::owner_stage("source", id) {
            Some(owner) => self.whole(STAGES[owner].0) || self.has("source", id),
            None if id == "dns" => self.runs(0),
            None => self.whole("network"),
        }
    }

    /// TLS inspection runs (network part, and the active checks after the port scan).
    pub(crate) fn tls(&self) -> bool {
        self.source(SRC_TLS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel(keys: &[&str]) -> Option<Selection> {
        Selection::parse(&keys.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn stages_follow_the_chosen_items() {
        assert_eq!(sel(&[]), None);
        assert_eq!(sel(&["nope:x", "source:nope"]), None);
        let s = sel(&["source:otx_dns", "source:startpage"]).unwrap();
        assert_eq!(
            s.stage_ids(),
            ["search", "download", "meta", "analysis", "report"]
        );
        assert_eq!(s.first(), 0);
        assert!(!s.subdomains() && !s.tls());
        assert!(s.source("otx_dns") && !s.source("crt") && s.source("dns"));
        let s = sel(&["step:brute"]).unwrap();
        assert_eq!(s.stage_ids(), ["network", "report"]);
        assert_eq!(s.first(), pos("network"));
        assert!(s.step("brute") && !s.step("permute") && s.steps_only());
        assert!(s.source(SRC_SUBDOMAINS) && !s.source("ports") && !s.source("dns"));
        assert_eq!(s.slot(pos("report")), (1, 2));
        let s = sel(&["stage:network"]).unwrap();
        assert_eq!(s.stage_ids(), ["network", "report"]);
        assert!(s.step("permute") && !s.steps_only() && s.tls());
        let s = sel(&["source:ports", "source:wellknown"]).unwrap();
        assert_eq!(s.stage_ids(), ["ports", "recon", "report"]);
        assert!(!s.tls() && !s.source("recon") && s.source("wellknown"));
        let s = sel(&["stage:download"]).unwrap();
        assert_eq!(s.stage_ids(), ["download", "meta", "analysis", "report"]);
    }
}
