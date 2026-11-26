//! Embedded third-party licenses catalog (`crates/foca-engine/data/licenses.json`), generated and
//! verified by `qa/gen-licenses.py --check`, exposed to the UI via IPC `licenses_get {}`.

use std::sync::OnceLock;

use serde_json::Value;

pub(crate) fn licenses_data() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../../data/licenses.json"))
            .expect("valid crates/foca-engine/data/licenses.json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_licenses_catalog_is_complete_and_foss_clean() {
        let v = licenses_data();
        assert_eq!(v["schema"], "foca-licenses/v1");
        assert_eq!(v["app_license"], "GPL-3.0");
        assert_eq!(v["repository"], "https://github.com/SinonApp/FOCA-rs");

        let crates = v["rust_crates"].as_array().expect("rust_crates");
        assert!(crates.len() >= 500, "expected 500+ Rust crates");
        assert!(crates.iter().any(|c| c["direct"] == true));
        assert!(
            !crates.iter().any(|c| c["name"] == "lopdf"),
            "lopdf is not a dependency"
        );

        let android = v["android_libs"].as_array().expect("android_libs");
        assert!(!android.is_empty());
        for a in android {
            if a["proprietary"] == true {
                assert_eq!(
                    a["flavor"], "play",
                    "proprietary Android dep {} must be play-only",
                    a["name"]
                );
            }
        }

        let texts = v["license_texts"].as_array().expect("license_texts");
        assert!(texts.len() >= 9);
        assert!(texts.iter().any(|t| t["id"] == "GPL-3.0"));
        assert!(texts.iter().any(|t| t["id"] == "SIL OFL 1.1"));
        assert!(texts.iter().any(|t| t["id"] == "Unicode-3.0"));
    }
}
