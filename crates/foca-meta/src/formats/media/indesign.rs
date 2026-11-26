//! Adobe InDesign (`.indd`, `.indt`): the master-page header (byte order) and the embedded XMP
//! packet (`<?xpacket ... ?>` / `<x:xmpmeta>`): creator tool, dates, document and instance
//! IDs, history and the metadata of placed files where present.

use foca_core::{DocFormat, Metadata};

use crate::util::find;
use crate::{xmp, Ctx, MetaError};

/// InDesign database GUID `0606EDF5-D81D-46E5-BD31-EFE7FE74B71D`.
pub(crate) const MAGIC: [u8; 16] = [
    0x06, 0x06, 0xED, 0xF5, 0xD8, 0x1D, 0x46, 0xE5, 0xBD, 0x31, 0xEF, 0xE7, 0xFE, 0x74, 0xB7, 0x1D,
];

/// Maximum size of one XMP packet.
const MAX_PACKET: usize = 8 << 20;
/// Maximum number of XMP packets inspected.
const MAX_PACKETS: usize = 16;

/// Returns the XMP packets (`<x:xmpmeta ...>...</x:xmpmeta>`) found in `b`.
pub(crate) fn xmp_packets(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0;
    while out.len() < MAX_PACKETS {
        let Some(start) = find(b, b"<x:xmpmeta", pos) else {
            break;
        };
        let Some(end) = find(b, b"</x:xmpmeta>", start) else {
            break;
        };
        let end = end + b"</x:xmpmeta>".len();
        if end - start <= MAX_PACKET {
            out.push(&b[start..end]);
        }
        pos = end;
    }
    out
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    if !b.starts_with(&MAGIC) {
        return Err(MetaError::malformed("indd", "bad header"));
    }
    let mut meta = Metadata::new(DocFormat::Indd);
    if b.get(16..24) == Some(b"DOCUMENT") {
        let order = match b.get(24) {
            Some(1) => "little_endian",
            Some(2) => "big_endian",
            _ => "unknown",
        };
        meta.fields.insert("indd:byte_order".into(), order.into());
    } else {
        meta.warnings
            .push("INDD: master page without DOCUMENT".into());
    }
    let packets = xmp_packets(b);
    meta.stats
        .insert("xmp_packets".into(), packets.len() as u64);
    for (i, p) in packets.iter().enumerate() {
        let map = xmp::parse(p, ctx);
        if map.is_empty() {
            continue;
        }
        if i == 0 {
            xmp::apply(&mut meta, &map, "xmp");
        } else {
            // later packets: placed images and snippets; keep only their creator tools
            if let Some(t) = map.get("xmp:CreatorTool") {
                Metadata::add_unique(&mut meta.software, t);
            }
        }
    }
    Ok(meta)
}
