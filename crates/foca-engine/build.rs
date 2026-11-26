//! Embeds the build commit for the Debug tab (`app_info.commit`): `FOCA_GIT_HASH` from the environment, or `git rev-parse`.
fn main() {
    println!("cargo:rerun-if-env-changed=FOCA_GIT_HASH");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    let hash = std::env::var("FOCA_GIT_HASH")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "--short=9", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        });
    if let Some(h) = hash {
        println!("cargo:rustc-env=FOCA_GIT_HASH={h}");
    }
}
