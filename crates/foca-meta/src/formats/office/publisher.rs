//! Microsoft Publisher (`.pub`, OLE2): property sets (authors, company, dates, application)
//! through the OLE parser, plus the Publisher version from the `Quill/QuillSub/CONTENTS`
//! stream header.

use std::io::{Cursor, Read};

use foca_core::{DocFormat, Metadata};

use crate::{Ctx, MetaError};

pub fn extract(bytes: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = crate::formats::office::ole::extract(bytes, DocFormat::Pub, ctx)?;
    let head = crate::guard("pub", || {
        let mut cf = cfb::CompoundFile::open(Cursor::new(bytes))
            .map_err(|e| MetaError::malformed("pub", e))?;
        let Ok(mut s) = cf.open_stream("/Quill/QuillSub/CONTENTS") else {
            return Ok(None);
        };
        let mut buf = Vec::new();
        let _ = (&mut s).take(16).read_to_end(&mut buf);
        Ok(Some(buf))
    })?;
    if let Some(h) = head {
        // "CHNKINK " followed by the container version
        if h.starts_with(b"CHNKINK ") {
            if let Some(v) = crate::util::rd_u16le(&h, 10) {
                meta.fields
                    .insert("pub:quill_version".into(), v.to_string());
            }
        }
    }
    Ok(meta)
}

/// Returns `true` if the OLE root names belong to a Publisher document.
pub(crate) fn is_pub(names: &[String]) -> bool {
    names.iter().any(|n| n == "Quill") && names.iter().any(|n| n == "Contents" || n == "Escher")
}
