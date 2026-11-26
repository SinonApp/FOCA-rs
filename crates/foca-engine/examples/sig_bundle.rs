//! Maintainer tool: builds and signs the signature bundle published at the update feed
//! (`foca_engine::sigbundle::DEFAULT_FEED_URL`) from the data in `crates/foca-analysis/signatures`.
//!
//! The signing key is never stored in the repository. See `docs/dev/signature-bundles.md`.
//!
//! ```text
//! cargo run -p foca-engine --example sig_bundle -- build --key <seed file> --out signatures.bundle
//!     [--version 2026.11.27] [--released 2026-11-27] [--allow-foreign-key]
//! cargo run -p foca-engine --example sig_bundle -- verify <bundle file>
//! cargo run -p foca-engine --example sig_bundle -- gen-key <new seed file>
//! ```
//!
//! A seed file holds the 32-byte Ed25519 seed as 64 hex characters.

use std::process::ExitCode;

use foca_engine::sigbundle;

fn read_seed(path: &str) -> Result<[u8; 32], String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let hex = raw.trim();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "{path}: expected 64 hex characters (a 32-byte Ed25519 seed)"
        ));
    }
    hex32(hex)
}

/// 64 hex characters to 32 bytes.
fn hex32(hex: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let pair = hex.get(i * 2..i * 2 + 2).ok_or("short hex")?;
        *b = u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn build(args: &[String]) -> Result<(), String> {
    let key = arg(args, "--key").ok_or("--key <seed file> is required")?;
    let out = arg(args, "--out").ok_or("--out <bundle file> is required")?;
    let seed = read_seed(&key)?;
    let pk = sigbundle::pubkey_hex_of_seed(&seed).map_err(|e| e.message)?;
    if pk != sigbundle::official_pubkey_hex() && !args.iter().any(|a| a == "--allow-foreign-key") {
        return Err(format!(
            "the key does not match the public key built into the app ({}); \
             the app would reject this bundle (pass --allow-foreign-key for a test bundle)",
            sigbundle::official_pubkey_hex()
        ));
    }
    let today = time::OffsetDateTime::now_utc().date();
    let released = arg(args, "--released").unwrap_or_else(|| {
        format!(
            "{:04}-{:02}-{:02}",
            today.year(),
            u8::from(today.month()),
            today.day()
        )
    });
    let mut bundle = sigbundle::bundle_from_builtin("", &released);
    let catalog = bundle
        .kev_catalog
        .as_ref()
        .map(|c| c.version.clone())
        .unwrap_or_default();
    bundle.version = arg(args, "--version").unwrap_or(catalog);
    sigbundle::sign_bundle_with_seed(&mut bundle, &seed).map_err(|e| e.message)?;
    sigbundle::verify_bundle(&bundle, &hex32(&pk)?).map_err(|e| e.message)?;
    let json = serde_json::to_string(&bundle).map_err(|e| e.to_string())?;
    std::fs::write(&out, json).map_err(|e| format!("{out}: {e}"))?;
    println!(
        "{out}: version {} released {} · {} KEV items · sha256 {}",
        bundle.version,
        bundle.released_at,
        bundle.kev_additions.len(),
        bundle.sha256
    );
    Ok(())
}

fn verify(args: &[String]) -> Result<(), String> {
    let path = args.get(1).ok_or("verify <bundle file>")?;
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let bundle: sigbundle::SigBundleV1 = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    sigbundle::verify_bundle(&bundle, &sigbundle::official_pubkey_bytes())
        .map_err(|e| format!("{}: {}", e.code, e.message))?;
    println!(
        "{path}: signature OK for the built-in key, version {}",
        bundle.version
    );
    Ok(())
}

fn gen_key(args: &[String]) -> Result<(), String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let path = args.get(1).ok_or("gen-key <new seed file>")?;
    if std::path::Path::new(path).exists() {
        return Err(format!("{path} already exists"));
    }
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| "no system randomness".to_string())?;
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(path, format!("{hex}\n")).map_err(|e| format!("{path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let pk = sigbundle::pubkey_hex_of_seed(&seed).map_err(|e| e.message)?;
    println!("seed written to {path} (keep it offline)");
    println!("public key: {pk}");
    println!("to trust it, put these bytes into OFFICIAL_ED25519_PUBKEY in sigbundle.rs:");
    let bytes: Vec<String> = hex32(&pk)?.iter().map(|b| format!("0x{b:02x}")).collect();
    println!("[{}]", bytes.join(", "));
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("build") => build(&args),
        Some("verify") => verify(&args),
        Some("gen-key") => gen_key(&args),
        _ => Err(
            "usage: sig_bundle build --key <seed> --out <file> | verify <file> | gen-key <file>"
                .into(),
        ),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sig_bundle: {e}");
            ExitCode::FAILURE
        }
    }
}
