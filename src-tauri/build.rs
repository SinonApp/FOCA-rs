fn main() {
    // App commands are declared explicitly: the capability allows only `foca` (allow-foca).
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["foca"])),
    )
    .expect("tauri-build");
}
