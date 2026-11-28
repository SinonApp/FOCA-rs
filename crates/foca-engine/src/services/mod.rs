//! Self-contained services the engine plugs in: localization, logging, OCR, plugins, signature
//! bundles, licenses, the AI provider protocol, auto-resume policy, the in-app update, the automatic signature check and the report
//! builder.

pub(crate) mod ai;
pub(crate) mod ai_text;
pub mod i18n;
pub mod licenses;
pub mod logs;
pub(crate) mod mobile;
pub mod ocr;
pub mod plugins;
#[cfg(feature = "report")]
pub(crate) mod report;
pub mod resume;
pub mod selfupdate;
pub mod sigauto;
pub mod sigbundle;
