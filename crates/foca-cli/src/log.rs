//! CLI logging: with `RUST_LOG` set, tracing events are printed to stderr. The filter format
//! is a simplified env_logger syntax: `info`, `foca::source=debug,warn`, `foca=trace`.
//! Everything the engine subscriber would accept still goes to the ring buffer and
//! `<data>/logs/foca.log` (`foca_engine::logs::push`).

use std::fmt::Write as _;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// Parsed `RUST_LOG`: `target=level` rules (a rule without a target sets the default level).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    rules: Vec<(Option<String>, Level)>,
}

fn level(s: &str) -> Option<Level> {
    match s.trim().to_ascii_lowercase().as_str() {
        "error" => Some(Level::ERROR),
        "warn" | "warning" => Some(Level::WARN),
        "info" => Some(Level::INFO),
        "debug" => Some(Level::DEBUG),
        "trace" => Some(Level::TRACE),
        _ => None,
    }
}

impl Filter {
    pub fn parse(s: &str) -> Filter {
        let mut rules = Vec::new();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some((t, l)) => {
                    if let Some(l) = level(l) {
                        rules.push((Some(t.trim().to_string()), l));
                    }
                }
                None => match level(part) {
                    Some(l) => rules.push((None, l)),
                    // A bare target without a level enables everything for it, as in env_logger.
                    None => rules.push((Some(part.to_string()), Level::TRACE)),
                },
            }
        }
        Filter { rules }
    }

    /// Returns `true` if an event from `target` at level `l` passes (the longest matching target
    /// wins).
    pub fn allows(&self, target: &str, l: &Level) -> bool {
        let mut best: Option<(usize, Level)> = None;
        for (t, lv) in &self.rules {
            let len = match t {
                None => 0,
                Some(t) if target == t || target.starts_with(&format!("{t}::")) => t.len() + 1,
                Some(_) => continue,
            };
            if best.is_none_or(|(b, _)| len >= b) {
                best = Some((len, *lv));
            }
        }
        best.is_some_and(|(_, lv)| *l <= lv)
    }
}

struct Msg(String, String);

impl Visit for Msg {
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            let _ = write!(self.0, "{v:?}");
        } else {
            let _ = write!(self.1, " {}={v:?}", f.name());
        }
    }
    fn record_str(&mut self, f: &Field, v: &str) {
        if f.name() == "message" {
            self.0.push_str(v);
        } else {
            let _ = write!(self.1, " {}={v}", f.name());
        }
    }
}

struct CliSubscriber {
    stderr: Filter,
}

fn ring_allows(m: &Metadata<'_>) -> bool {
    if m.target().starts_with("foca") {
        *m.level() <= Level::DEBUG
    } else {
        *m.level() <= Level::WARN
    }
}

fn level_str(l: &Level) -> &'static str {
    match *l {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

impl Subscriber for CliSubscriber {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        ring_allows(m) || self.stderr.allows(m.target(), m.level())
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, e: &Event<'_>) {
        let mut v = Msg(String::new(), String::new());
        e.record(&mut v);
        let m = e.metadata();
        let text = v.0 + &v.1;
        if self.stderr.allows(m.target(), m.level()) {
            let t = time::OffsetDateTime::now_utc();
            eprintln!(
                "{:02}:{:02}:{:02}.{:03} {:5} {} {}",
                t.hour(),
                t.minute(),
                t.second(),
                t.millisecond(),
                level_str(m.level()).to_uppercase(),
                m.target(),
                text
            );
        }
        if ring_allows(m) {
            foca_engine::logs::push(level_str(m.level()), m.target(), text);
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// Installs the CLI subscriber when `RUST_LOG` is set (otherwise the engine installs its own
/// on open).
pub fn init() {
    let Ok(s) = std::env::var("RUST_LOG") else {
        return;
    };
    let f = Filter::parse(&s);
    if f.rules.is_empty() {
        return;
    }
    let _ = tracing::subscriber::set_global_default(CliSubscriber { stderr: f });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_log_filter() {
        let f = Filter::parse("warn,foca::source=debug");
        assert!(f.allows("foca::source", &Level::DEBUG));
        assert!(!f.allows("foca::source", &Level::TRACE));
        assert!(!f.allows("foca::scan", &Level::INFO));
        assert!(f.allows("hyper", &Level::WARN));
        let d = Filter::parse("debug");
        assert!(d.allows("foca::net", &Level::DEBUG));
        assert!(Filter::parse("bogus=xx").rules.is_empty());
        assert!(Filter::parse("foca").allows("foca::scan", &Level::TRACE));
    }
}
