//! Writes the synthetic cleaning/hygiene fixtures (PDF with incremental revisions, PDF with
//! object/xref streams, encrypted PDF, ODT with full metadata).
//!
//! Usage: `cargo run -p foca-meta --example make_hygiene_fixtures -- crates/foca-meta/tests/fixtures/hygiene`
//! All data is fictional; the same generators are used directly by `tests/hygiene.rs`.

#[path = "../tests/hygiene_gen/mod.rs"]
mod hygiene_gen;

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).map_or_else(
        || PathBuf::from("crates/foca-meta/tests/fixtures/hygiene"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&dir)?;
    for (name, bytes) in [
        ("revisions.pdf", hygiene_gen::pdf_revisions()),
        ("objstm.pdf", hygiene_gen::pdf_objstm()),
        ("encrypted.pdf", hygiene_gen::pdf_encrypted()),
        ("full.odt", hygiene_gen::odt_full()),
    ] {
        std::fs::write(dir.join(name), bytes)?;
        println!("{}", dir.join(name).display());
    }
    Ok(())
}
