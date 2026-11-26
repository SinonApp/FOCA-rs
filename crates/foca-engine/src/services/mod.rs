//! Self-contained services the engine plugs in: localization, logging, OCR, plugins, signature
//! bundles, licenses, the AI provider protocol, auto-resume policy and the report builder.

pub(crate) mod ai;
pub(crate) mod ai_text;
pub mod i18n;
pub mod licenses;
pub mod logs;
pub mod ocr;
pub mod plugins;
#[cfg(feature = "report")]
pub(crate) mod report;
pub mod resume;
pub mod sigbundle;
