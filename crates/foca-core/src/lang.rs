//! Interface, report, playbook and alert language (`en` / `ru` / `uk`).

use serde::{Deserialize, Serialize};

/// Supported localization language.
///
/// Defaults to [`Lang::En`] so unknown device locales fall back to English.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Ru,
    #[serde(alias = "ua")]
    Uk,
}

impl Lang {
    /// Parses an explicit language code or name (`en`/`ru`/`uk`/`ua` and BCP 47 tags such as
    /// `uk-UA`, `ru_RU`, `en-GB`). Returns `None` for `"auto"`, empty strings or unsupported
    /// languages so callers can distinguish explicit user selection from fallback.
    pub fn parse(s: &str) -> Option<Self> {
        let low = s.trim().to_ascii_lowercase();
        match low.as_str() {
            "ru" | "rus" | "русский" => Some(Self::Ru),
            "uk" | "ua" | "ukr" | "українська" => Some(Self::Uk),
            "en" | "eng" | "english" => Some(Self::En),
            _ if low.contains('-') || low.contains('_') => {
                match low.split(['-', '_']).next().unwrap_or("") {
                    "ru" | "rus" => Some(Self::Ru),
                    "uk" | "ua" | "ukr" => Some(Self::Uk),
                    "en" | "eng" => Some(Self::En),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Normalizes a BCP 47 locale tag (`uk-UA`, `ru-RU`, `de-DE`, `pl-PL`, `ja-JP`, …) into a
    /// supported [`Lang`]: `uk*`/`ua*` → [`Lang::Uk`], `ru*` → [`Lang::Ru`], everything else
    /// (including `en*` and empty) → [`Lang::En`].
    pub fn from_bcp47(tag: &str) -> Self {
        let low = tag.trim().to_ascii_lowercase();
        let primary = low.split(['-', '_']).next().unwrap_or("");
        match primary {
            "uk" | "ua" | "ukr" | "українська" => Self::Uk,
            "ru" | "rus" | "русский" => Self::Ru,
            _ => Self::En,
        }
    }

    /// Parses a short code (`ru` / `uk` / `ua` / `en`) with [`Lang::En`] fallback.
    pub fn from_code(code: &str) -> Self {
        Self::from_bcp47(code)
    }

    /// Resolves a user setting (`"auto"` / `"en"` / `"ru"` / `"uk"` / `"ua"`) together with an
    /// optional device BCP 47 locale tag (`Locale.getDefault()` / `navigator.language`).
    pub fn resolve_setting(setting: Option<&str>, device_locale: Option<&str>) -> Self {
        if let Some(s) = setting {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("auto") {
                if let Some(lang) = Self::parse(trimmed) {
                    return lang;
                }
            }
        }
        device_locale.map(Self::from_bcp47).unwrap_or(Self::En)
    }

    /// Canonical BCP 47 code (`en`, `ru`, `uk`).
    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
            Self::Uk => "uk",
        }
    }

    /// Uppercase UI badge code (`EN`, `RU`, `UA`).
    pub fn ui(self) -> &'static str {
        match self {
            Self::En => "EN",
            Self::Ru => "RU",
            Self::Uk => "UA",
        }
    }

    /// All supported languages in canonical order (`en`, `ru`, `uk`).
    pub const ALL: [Self; 3] = [Self::En, Self::Ru, Self::Uk];
}

#[cfg(test)]
mod tests {
    use super::Lang;

    #[test]
    fn default_is_english() {
        assert_eq!(Lang::default(), Lang::En);
    }

    #[test]
    fn bcp47_maps_uk_ru_and_falls_back_to_en() {
        assert_eq!(Lang::from_bcp47("uk"), Lang::Uk);
        assert_eq!(Lang::from_bcp47("uk-UA"), Lang::Uk);
        assert_eq!(Lang::from_bcp47("uk_UA"), Lang::Uk);
        assert_eq!(Lang::from_bcp47("ua"), Lang::Uk);
        assert_eq!(Lang::from_bcp47("UA-UA"), Lang::Uk);

        assert_eq!(Lang::from_bcp47("ru"), Lang::Ru);
        assert_eq!(Lang::from_bcp47("ru-RU"), Lang::Ru);
        assert_eq!(Lang::from_bcp47("ru-KZ"), Lang::Ru);

        assert_eq!(Lang::from_bcp47("en"), Lang::En);
        assert_eq!(Lang::from_bcp47("en-US"), Lang::En);
        assert_eq!(Lang::from_bcp47("de-DE"), Lang::En);
        assert_eq!(Lang::from_bcp47("pl-PL"), Lang::En);
        assert_eq!(Lang::from_bcp47("ja-JP"), Lang::En);
        assert_eq!(Lang::from_bcp47(""), Lang::En);
    }

    #[test]
    fn parse_distinguishes_auto_and_unknown() {
        assert_eq!(Lang::parse("auto"), None);
        assert_eq!(Lang::parse("de-DE"), None);
        assert_eq!(Lang::parse("UA"), Some(Lang::Uk));
        assert_eq!(Lang::parse("uk-UA"), Some(Lang::Uk));
        assert_eq!(Lang::parse("RU"), Some(Lang::Ru));
        assert_eq!(Lang::parse("en-GB"), Some(Lang::En));
    }

    #[test]
    fn resolve_setting_prefers_explicit_over_device() {
        assert_eq!(Lang::resolve_setting(Some("auto"), Some("uk-UA")), Lang::Uk);
        assert_eq!(Lang::resolve_setting(Some("auto"), Some("ru-RU")), Lang::Ru);
        assert_eq!(Lang::resolve_setting(Some("auto"), Some("de-DE")), Lang::En);
        assert_eq!(Lang::resolve_setting(Some("ru"), Some("uk-UA")), Lang::Ru);
        assert_eq!(Lang::resolve_setting(Some("UA"), Some("en-US")), Lang::Uk);
        assert_eq!(Lang::resolve_setting(None, None), Lang::En);
    }

    #[test]
    fn serde_roundtrip_and_ua_alias() {
        assert_eq!(serde_json::from_str::<Lang>("\"en\"").unwrap(), Lang::En);
        assert_eq!(serde_json::from_str::<Lang>("\"ru\"").unwrap(), Lang::Ru);
        assert_eq!(serde_json::from_str::<Lang>("\"uk\"").unwrap(), Lang::Uk);
        assert_eq!(serde_json::from_str::<Lang>("\"ua\"").unwrap(), Lang::Uk);
        assert_eq!(serde_json::to_string(&Lang::Uk).unwrap(), "\"uk\"");
        assert_eq!(Lang::Uk.ui(), "UA");
        assert_eq!(Lang::Uk.code(), "uk");
    }
}
