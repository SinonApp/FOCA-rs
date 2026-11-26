//! Safe ZIP reading (OOXML/ODF): entry count limit, shared decompression budget, and reads
//! bounded by the actual rather than the declared size.

use std::io::{Cursor, Read};

use zip::ZipArchive;

use crate::{Ctx, MetaError};

/// Central-directory information about an entry.
pub struct EntryInfo {
    /// Declared uncompressed size.
    pub size: u64,
    pub encrypted: bool,
    pub modified: Option<zip::DateTime>,
}

pub struct SafeZip<'a> {
    archive: ZipArchive<Cursor<&'a [u8]>>,
    names: Vec<String>,
}

impl<'a> SafeZip<'a> {
    pub fn open(bytes: &'a [u8], max_entries: usize) -> Result<Self, MetaError> {
        let archive = crate::guard("zip", || {
            ZipArchive::new(Cursor::new(bytes)).map_err(|e| MetaError::malformed("zip", e))
        })?;
        if archive.len() > max_entries {
            return Err(MetaError::TooManyEntries(format!(
                "{} записей в архиве",
                archive.len()
            )));
        }
        let names = archive
            .file_names()
            .filter_map(Result::ok)
            .map(|c| c.into_owned())
            .collect();
        Ok(SafeZip { archive, names })
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Reads a whole entry, charging its bytes against the budget. Returns `Ok(None)` if the entry
    /// is missing, encrypted or corrupt (not fatal).
    ///
    /// # Errors
    ///
    /// Returns [`MetaError`] if the decompression budget is exhausted.
    pub fn read(&mut self, name: &str, ctx: &Ctx) -> Result<Option<Vec<u8>>, MetaError> {
        self.read_limited(name, ctx.remaining(), ctx)
            .map(|o| o.map(|(v, _)| v))
    }

    /// Reads at most `cap` bytes of an entry (for format and signature detection).
    pub fn read_prefix(
        &mut self,
        name: &str,
        cap: u64,
        ctx: &Ctx,
    ) -> Result<Option<Vec<u8>>, MetaError> {
        let cap = cap.min(ctx.remaining());
        let mut file = match self.archive.by_name(name) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        let mut buf = Vec::new();
        let _ = (&mut file).take(cap).read_to_end(&mut buf);
        ctx.spend(buf.len() as u64)?;
        Ok(Some(buf))
    }

    fn read_limited(
        &mut self,
        name: &str,
        cap: u64,
        ctx: &Ctx,
    ) -> Result<Option<(Vec<u8>, u64)>, MetaError> {
        let mut file = match self.archive.by_name(name) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        let declared = file.size();
        if declared > cap {
            let _ = ctx.spend(cap);
            return Err(MetaError::ZipBomb(format!(
                "{name}: заявлено {declared} байт, бюджет {cap}"
            )));
        }
        let mut buf = Vec::with_capacity(declared.min(1 << 20) as usize);
        // read one byte past the budget to catch a forged declared size
        let res = (&mut file)
            .take(cap.saturating_add(1))
            .read_to_end(&mut buf);
        if buf.len() as u64 > cap {
            let _ = ctx.spend(cap);
            return Err(MetaError::ZipBomb(format!(
                "{name}: распаковано больше бюджета {cap}"
            )));
        }
        ctx.spend(buf.len() as u64)?;
        if res.is_err() && buf.is_empty() {
            return Ok(None);
        }
        Ok(Some((buf, declared)))
    }

    /// Returns the archive comment.
    pub fn comment(&self) -> &[u8] {
        self.archive.comment()
    }

    /// Returns entry information from the central directory without decompressing it.
    pub fn info(&mut self, name: &str) -> Option<EntryInfo> {
        let i = self.archive.index_for_name(name)?;
        let f = self.archive.by_index_raw(i).ok()?;
        Some(EntryInfo {
            size: f.size(),
            encrypted: f.encrypted(),
            modified: f.last_modified(),
        })
    }

    /// Returns the declared size of an entry, if present.
    pub fn size(&mut self, name: &str) -> Option<u64> {
        self.archive.by_name(name).ok().map(|f| f.size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{extract, Limits};
    use std::cell::Cell;
    use std::io::Write;

    #[test]
    fn bomb_drains_budget_and_epub_propagates_error() {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("META-INF/container.xml", opts).unwrap();
            zw.write_all(
                br#"<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>"#,
            )
            .unwrap();
            zw.start_file("OEBPS/content.opf", opts).unwrap();
            zw.write_all(&vec![b'A'; 4096]).unwrap();
            zw.finish().unwrap();
        }
        let limits = Limits {
            max_unzipped_total: 1024,
            ..Limits::default()
        };
        let budget = Cell::new(limits.max_unzipped_total);
        let ctx = Ctx::standalone(&limits, &budget);
        let mut z = SafeZip::open(&buf, limits.max_entries).unwrap();
        let err = z.read("OEBPS/content.opf", &ctx).unwrap_err();
        assert!(matches!(err, MetaError::ZipBomb(_)));
        assert_eq!(ctx.remaining(), 0);

        let epub_err = extract(&buf, Some("book.epub"), &limits).unwrap_err();
        assert!(matches!(epub_err, MetaError::ZipBomb(_)));
    }
}
