//! User search rules ("YARA-lite"): built-in presets that can be switched on plus
//! the user's own regular expressions, stored in the project settings.
//!
//! ReDoS protection: the `regex` crate matches in linear time (no backtracking), and on top of
//! that every rule is bounded by the pattern length, the compiled program size, the lazy DFA
//! cache size and the nesting depth; scanning is bounded by the number of matches per rule and
//! per text. Patterns that match the empty string are rejected (they would match everywhere).

use foca_core::{api::SecretValue, Severity};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// Maximum pattern length, characters.
pub const MAX_PATTERN_LEN: usize = 512;
/// Maximum compiled program size per rule, bytes.
pub const MAX_COMPILED_SIZE: usize = 2 * 1024 * 1024;
/// Maximum lazy DFA cache per rule, bytes.
pub const MAX_DFA_SIZE: usize = 1024 * 1024;
/// Maximum nesting depth of groups/repetitions.
pub const MAX_NEST: u32 = 32;
/// Maximum number of user rules.
pub const MAX_RULES: usize = 64;
/// Maximum matches of one rule in one text.
pub const MAX_HITS_PER_RULE: usize = 50;
/// Maximum matches of all rules in one text.
pub const MAX_HITS_TOTAL: usize = 500;

/// A user rule as stored in the project settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserRule {
    /// Stable id (`[a-z0-9_-]`, up to 48 characters); part of the finding id.
    pub id: String,
    pub title: String,
    pub pattern: String,
    pub sev: Severity,
    pub enabled: bool,
    pub case_insensitive: bool,
    /// Legacy flag kept so older project settings round-trip; matches are always shown in
    /// full in the app (logs and the masked report option mask them).
    pub mask: bool,
}

impl Default for UserRule {
    fn default() -> Self {
        UserRule {
            id: String::new(),
            title: String::new(),
            pattern: String::new(),
            sev: Severity::Medium,
            enabled: true,
            case_insensitive: true,
            mask: true,
        }
    }
}

/// Project setting `analysis.rules`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    /// Enabled preset ids (see [`presets`]).
    pub presets: Vec<String>,
    pub rules: Vec<UserRule>,
}

/// A built-in rule pack.
#[derive(Debug, Clone, Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub rules: &'static [PresetRule],
}

#[derive(Debug, Clone, Serialize)]
pub struct PresetRule {
    pub id: &'static str,
    pub title: &'static str,
    pub pattern: &'static str,
    pub sev: Severity,
    pub mask: bool,
}

const fn pr(
    id: &'static str,
    title: &'static str,
    pattern: &'static str,
    sev: Severity,
    mask: bool,
) -> PresetRule {
    PresetRule {
        id,
        title,
        pattern,
        sev,
        mask,
    }
}

static PRESETS: &[Preset] = &[
    Preset {
        id: "ua-gov",
        title: "Документы госорганов Украины",
        description:
            "Реквизиты служебных документов: номера наказів, вихідні номери, інвентарні номери ДСК.",
        rules: &[
            pr(
                "ua-order",
                "Номер наказу/розпорядження",
                r"(?i)\b(?:наказ|розпорядження|постанова)\s+(?:від\s+\d{2}\.\d{2}\.\d{4}\s+)?№\s*\d{1,5}(?:[-/]\p{L}{1,6})?",
                Severity::Info,
                false,
            ),
            pr(
                "ua-outgoing",
                "Вихідний номер листа",
                r"(?i)\bвих(?:ідний|\.)\s*№\s*[\p{L}\d/.\-]{1,20}",
                Severity::Info,
                false,
            ),
            pr(
                "ua-dsk-inv",
                "Інвентарний номер ДСК",
                r"(?i)\bінв\.?\s*№\s*\d{1,6}\s*(?:дск|дсп)\b",
                Severity::High,
                false,
            ),
        ],
    },
    Preset {
        id: "credentials",
        title: "Учётные данные в тексте",
        description: "Пары «логин/пароль» в свободной форме на украинском, русском и английском.",
        rules: &[
            pr(
                "cred-login-pass",
                "Логин и пароль в тексте",
                r"(?i)\b(?:логін|логин|login|user(?:name)?|користувач)\s*[:=]\s*\S{2,64}\s*[,;/]?\s*(?:пароль|password|pass|pwd)\s*[:=]\s*\S{4,64}",
                Severity::Critical,
                true,
            ),
            pr(
                "cred-wifi",
                "Пароль Wi-Fi",
                r"(?i)\b(?:wi-?fi|ssid)\b[^\n]{0,60}?(?:пароль|password|ключ|key)\s*[:=\-]\s*\S{8,63}",
                Severity::High,
                true,
            ),
        ],
    },
    Preset {
        id: "infra",
        title: "Внутренняя инфраструктура",
        description: "UNC-пути, RDP/SSH-адреса с портами, имена контроллеров домена.",
        rules: &[
            pr(
                "infra-unc",
                "UNC-путь к сетевому ресурсу",
                r"\\\\[A-Za-z0-9][A-Za-z0-9.\-]{0,62}\\[^\s\\/:*?<>|]{1,80}",
                Severity::Low,
                false,
            ),
            pr(
                "infra-rdp",
                "Адрес удалённого доступа с портом",
                r"(?i)\b(?:rdp|ssh|vnc|anydesk|teamviewer)\b[^\n]{0,40}?\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?",
                Severity::Medium,
                false,
            ),
        ],
    },
    Preset {
        id: "crypto",
        title: "Криптовалютные кошельки",
        description: "Адреса Bitcoin (bech32), Ethereum и TRON.",
        rules: &[
            pr(
                "crypto-btc",
                "Адрес Bitcoin",
                r"\bbc1[ac-hj-np-z02-9]{25,59}\b",
                Severity::Low,
                true,
            ),
            pr(
                "crypto-eth",
                "Адрес Ethereum",
                r"\b0x[0-9a-fA-F]{40}\b",
                Severity::Low,
                true,
            ),
            pr(
                "crypto-trx",
                "Адрес TRON",
                r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b",
                Severity::Low,
                true,
            ),
        ],
    },
    Preset {
        id: "personal",
        title: "Персональные данные (свободная форма)",
        description:
            "Даты рождения, адреса регистрации и медицинские сведения рядом с ключевыми словами.",
        rules: &[
            pr(
                "pd-birth",
                "Дата рождения",
                r"(?i)\b(?:дата\s+народження|дата\s+рождения|date\s+of\s+birth|д\.\s*н\.)\s*[:\-]?\s*\d{2}[./]\d{2}[./]\d{4}",
                Severity::Medium,
                true,
            ),
            pr(
                "pd-address",
                "Адрес регистрации",
                r"(?i)\b(?:зареєстрован\p{L}*|місце\s+проживання|адреса\s+реєстрації)\s*[:\-]?\s*[^\n]{10,120}",
                Severity::Medium,
                true,
            ),
            pr(
                "pd-medical",
                "Медицинские сведения",
                r"(?i)\b(?:діагноз|диагноз|лікарняний|больничный|інвалідність|инвалидность)\b[^\n]{0,80}",
                Severity::High,
                true,
            ),
        ],
    },
];

/// Built-in presets.
pub fn presets() -> &'static [Preset] {
    PRESETS
}

/// A configuration error for the UI (`rule` is the rule id or `preset:<id>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleError {
    pub rule: String,
    pub message: String,
}

/// A match of a rule. `value` is masked in `Debug`/`Display`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleHit {
    /// `user:<id>` or `preset:<preset>:<id>`.
    pub rule: String,
    pub title: String,
    pub sev: Severity,
    pub value: SecretValue,
    pub start: usize,
    pub end: usize,
    pub location: String,
}

#[derive(Debug, Clone)]
struct Compiled {
    rule: String,
    title: String,
    sev: Severity,
    re: Regex,
}

/// A compiled, validated rule set.
#[derive(Debug, Clone, Default)]
pub struct RuleSet(Vec<Compiled>);

/// Compiles one pattern under the limits.
pub fn compile_pattern(pattern: &str, case_insensitive: bool) -> Result<Regex, String> {
    if pattern.trim().is_empty() {
        return Err("пустой шаблон".into());
    }
    if pattern.chars().count() > MAX_PATTERN_LEN {
        return Err(format!("шаблон длиннее {MAX_PATTERN_LEN} символов"));
    }
    let re = RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .size_limit(MAX_COMPILED_SIZE)
        .dfa_size_limit(MAX_DFA_SIZE)
        .nest_limit(MAX_NEST)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => "шаблон слишком сложный (лимит размера)".to_string(),
            regex::Error::Syntax(s) => {
                format!("синтаксис: {}", s.lines().last().unwrap_or("").trim())
            }
            _ => e.to_string(),
        })?;
    if re.is_match("") {
        return Err("шаблон совпадает с пустой строкой".into());
    }
    Ok(re)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 48
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl RuleSet {
    /// Validates the configuration and compiles enabled presets and rules. All problems are
    /// reported at once; disabled rules are validated too, so a broken rule cannot be saved.
    pub fn compile(cfg: &RulesConfig) -> Result<RuleSet, Vec<RuleError>> {
        let mut errs = Vec::new();
        let mut out = Vec::new();
        if cfg.rules.len() > MAX_RULES {
            errs.push(RuleError {
                rule: String::new(),
                message: format!("больше {MAX_RULES} правил"),
            });
        }
        for p in &cfg.presets {
            match PRESETS.iter().find(|x| x.id == p) {
                Some(pre) => {
                    for r in pre.rules {
                        match compile_pattern(r.pattern, false) {
                            Ok(re) => out.push(Compiled {
                                rule: format!("preset:{}:{}", pre.id, r.id),
                                title: r.title.to_string(),
                                sev: r.sev,
                                re,
                            }),
                            Err(m) => errs.push(RuleError {
                                rule: format!("preset:{p}"),
                                message: m,
                            }),
                        }
                    }
                }
                None => errs.push(RuleError {
                    rule: format!("preset:{p}"),
                    message: "неизвестный пресет".into(),
                }),
            }
        }
        let mut ids: Vec<&str> = Vec::new();
        for r in cfg.rules.iter().take(MAX_RULES) {
            let mut bad = |m: String| {
                errs.push(RuleError {
                    rule: r.id.clone(),
                    message: m,
                })
            };
            if !valid_id(&r.id) {
                bad("id: латиница в нижнем регистре, цифры, «-», «_», до 48 символов".into());
                continue;
            }
            if ids.contains(&r.id.as_str()) {
                bad("повторяющийся id".into());
                continue;
            }
            ids.push(&r.id);
            if r.title.trim().is_empty() || r.title.chars().count() > 120 {
                bad("название: от 1 до 120 символов".into());
            }
            match compile_pattern(&r.pattern, r.case_insensitive) {
                Ok(re) if r.enabled => out.push(Compiled {
                    rule: format!("user:{}", r.id),
                    title: r.title.trim().to_string(),
                    sev: r.sev,
                    re,
                }),
                Ok(_) => {}
                Err(m) => bad(m),
            }
        }
        if errs.is_empty() {
            Ok(RuleSet(out))
        } else {
            Err(errs)
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Runs all rules over `text`; a capture group named `v` (if present) is the value.
    pub fn scan(&self, text: &str, place: &str) -> Vec<RuleHit> {
        let mut out: Vec<RuleHit> = Vec::new();
        let multiline = text.contains('\n');
        for c in &self.0 {
            for (n, cap) in c.re.captures_iter(text).enumerate() {
                if n >= MAX_HITS_PER_RULE || out.len() >= MAX_HITS_TOTAL {
                    break;
                }
                let Some(m) = cap.name("v").or_else(|| cap.get(0)) else {
                    continue;
                };
                if m.as_str().trim().is_empty() {
                    continue;
                }
                let location = if multiline {
                    let line = text[..m.start()].matches('\n').count() + 1;
                    format!("{place}, строка {line}")
                } else {
                    place.to_string()
                };
                out.push(RuleHit {
                    rule: c.rule.clone(),
                    title: c.title.clone(),
                    sev: c.sev,
                    value: SecretValue::new(m.as_str().trim()),
                    start: m.start(),
                    end: m.end(),
                    location,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str, pattern: &str) -> UserRule {
        UserRule {
            id: id.into(),
            title: format!("Правило {id}"),
            pattern: pattern.into(),
            ..UserRule::default()
        }
    }

    #[test]
    fn presets_compile() {
        let cfg = RulesConfig {
            presets: presets().iter().map(|p| p.id.to_string()).collect(),
            rules: vec![],
        };
        let set = RuleSet::compile(&cfg).unwrap();
        assert_eq!(
            set.len(),
            presets().iter().map(|p| p.rules.len()).sum::<usize>()
        );
        let t = "Логін: test.user, пароль: Qwerty-12345\nНАКАЗ від 01.02.2026 № 15-ос\n\\\\FILESRV01\\Buh";
        let hits = set.scan(t, "текст");
        let ids: Vec<&str> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert!(
            ids.contains(&"preset:credentials:cred-login-pass"),
            "{ids:?}"
        );
        assert!(ids.contains(&"preset:ua-gov:ua-order"), "{ids:?}");
        assert!(ids.contains(&"preset:infra:infra-unc"), "{ids:?}");
        assert!(!format!("{hits:?}").contains("Qwerty-12345"));
    }

    #[test]
    fn user_rules_and_value_group() {
        let cfg = RulesConfig {
            presets: vec![],
            rules: vec![user("project-code", r"проєкт\s+(?P<v>[A-Z]{3}-\d{3})")],
        };
        let set = RuleSet::compile(&cfg).unwrap();
        let h = set.scan("Документ по ПРОЄКТ ABC-123 і проєкт XYZ-999", "x");
        assert_eq!(h.len(), 2, "case-insensitive by default");
        assert_eq!(h[0].value.expose(), "ABC-123");
        assert_eq!(h[0].rule, "user:project-code");
    }

    #[test]
    fn rejects_bad_rules() {
        let cfg = RulesConfig {
            presets: vec!["nope".into()],
            rules: vec![
                user("empty-match", r"a*"),
                user("syntax", r"(unclosed"),
                user("BadId", r"x"),
                user("long", &"a".repeat(MAX_PATTERN_LEN + 1)),
                user("huge", r"(?:\w{100}){100}"),
                user("deep", &format!("{}a{}", "(".repeat(40), ")".repeat(40))),
                user("dup", "x"),
                user("dup", "y"),
            ],
        };
        let errs = RuleSet::compile(&cfg).unwrap_err();
        let ids: Vec<&str> = errs.iter().map(|e| e.rule.as_str()).collect();
        for want in [
            "preset:nope",
            "empty-match",
            "syntax",
            "BadId",
            "long",
            "huge",
            "deep",
            "dup",
        ] {
            assert!(ids.contains(&want), "{want} not rejected: {errs:?}");
        }
    }

    #[test]
    fn redos_patterns_stay_linear() {
        // Classic catastrophic-backtracking patterns are linear in the regex crate.
        let cfg = RulesConfig {
            presets: vec![],
            rules: vec![user("evil", r"(a+)+$"), user("evil2", r"(a|aa)+b")],
        };
        let set = RuleSet::compile(&cfg).unwrap();
        let text = "a".repeat(200_000) + "!";
        let t = std::time::Instant::now();
        let hits = set.scan(&text, "x");
        assert!(t.elapsed().as_secs() < 5);
        assert!(hits.len() <= MAX_HITS_PER_RULE * 2);
        // Match cap.
        let set = RuleSet::compile(&RulesConfig {
            presets: vec![],
            rules: vec![user("digit", r"\d")],
        })
        .unwrap();
        assert_eq!(set.scan(&"1 ".repeat(10_000), "x").len(), MAX_HITS_PER_RULE);
    }

    #[test]
    fn config_roundtrip() {
        let j = serde_json::json!({"presets": ["crypto"], "rules": [{"id": "a", "title": "A", "pattern": "x+"}]});
        let cfg: RulesConfig = serde_json::from_value(j).unwrap();
        assert!(cfg.rules[0].enabled && cfg.rules[0].mask && cfg.rules[0].case_insensitive);
        assert_eq!(cfg.rules[0].sev, Severity::Medium);
        assert!(RuleSet::compile(&cfg).is_ok());
    }
}
