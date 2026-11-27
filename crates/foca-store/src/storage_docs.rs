//! Storage documents belong to the site that linked them (analysis view of the documents).

use std::collections::BTreeMap;

use foca_core::api::DocProvenance;
use foca_core::Document;

/// Host of a page URL (`https://Site.example:8443/a` → `site.example`); `None` without a host.
fn page_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let auth = rest.split(['/', '?', '#']).next()?;
    let host = auth.rsplit('@').next()?.split(':').next()?.trim();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// A file downloaded from external storage (Google Drive, OneDrive, Dropbox...) belongs to the
/// in-scope site that linked it: its host becomes the linking page's host (or the host of the
/// document that linked it), never the provider's. `prov` maps download URLs to provenance.
pub(crate) fn attribute_storage(
    docs: &mut [&mut Document],
    prov: &BTreeMap<String, DocProvenance>,
) {
    let host_by_id: BTreeMap<u64, Option<String>> =
        docs.iter().map(|d| (d.id, d.host.clone())).collect();
    for d in docs.iter_mut() {
        let Some(p) = d.url.as_ref().and_then(|u| prov.get(u)) else {
            continue;
        };
        if p.storage.is_none() {
            continue;
        }
        let site = match p.kind.as_str() {
            "doc" => p
                .from_doc
                .and_then(|i| host_by_id.get(&i).cloned().flatten()),
            _ => page_host(&p.from),
        };
        if let Some(h) = site {
            d.host = Some(h);
        }
    }
}
