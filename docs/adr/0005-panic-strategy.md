# ADR-0005: `panic = "unwind"` in Release Builds

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted
- Context: The release profile previously lived in `src-tauri/Cargo.toml` with `panic = "abort"` (for a smaller `.so`).
  After `src-tauri` was added to the root workspace, member profiles are ignored: the release profile moved to the root
  `Cargo.toml` and is now shared by both the APK and the CLI. `foca-meta` parses untrusted files from external websites
  (OOXML, PDF, OLE2, EXIF…) and catches parser panics (`catch_unwind` in `foca-meta/src/lib.rs`), converting them into
  per-document errors. With `abort`, `catch_unwind` cannot catch panics: a single corrupted PDF from a web archive kills
  the entire process: both the scan and the UI. The native bridge also catches panics in event handlers (`bridge.rs`,
  worker thread).
- Decision: Use `panic = "unwind"` (keeping `lto = "thin"`, `opt-level = "s"`, `strip`, and `codegen-units = 4` as
  before).
- Cost: The `.so` binary grows by a few percent due to unwind tables; runtime performance impact is negligible.
- Why not `abort`: Resilience against malformed files outweighs binary size, that is FOCA's primary workload (thousands
  of untrusted documents per scan). Although a crash report is still written under `abort` (the panic hook writes
  `rust_panic.txt`), the in-progress scan would be lost.
- Verification: A malformed document in `foca-meta` tests produces an error rather than crashing; the APK runs the exact
  same code.
