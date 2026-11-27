//! Public files on external storage linked from in-scope pages.
//!
//! Many organisations publish their documents on Google Drive, Google Docs, OneDrive, Dropbox or
//! SharePoint and only link them from their own site. Such a linked file is a target document:
//! the crawler records the link with the in-scope page that showed it ([`StorageLink`]), and the
//! download stage fetches exactly that item through the provider's public download or export URL.
//! Nothing else on the storage host is browsed: a folder link lists only that folder's files,
//! capped per folder and in total.
//!
//! Google Docs, Sheets and Slides have no original file: Google renders an export, so its
//! metadata describes Google's converter, not the author ([`StorageLink::exported`]).
//!
//! Provider base URLs live in [`StorageEndpoints`] so tests point them at a local server.

use serde::{Deserialize, Serialize};
use url::Url;

/// Storage provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    GoogleDrive,
    GoogleDocs,
    OneDrive,
    Dropbox,
    SharePoint,
}

impl Provider {
    /// Stable id used in provenance and the request journal.
    pub fn id(self) -> &'static str {
        match self {
            Provider::GoogleDrive => "gdrive",
            Provider::GoogleDocs => "gdocs",
            Provider::OneDrive => "onedrive",
            Provider::Dropbox => "dropbox",
            Provider::SharePoint => "sharepoint",
        }
    }
}

/// What a storage link points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A single file, downloaded as is.
    File,
    /// A Google Docs/Sheets/Slides document exported by Google.
    Export,
    /// A public folder: its listing gives file links.
    Folder,
}

/// A recognised storage link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageLink {
    pub provider: Provider,
    pub kind: ItemKind,
    /// Provider item id (Drive/Docs id, or the share URL for providers without one).
    pub id: String,
    /// The link as found on the page.
    pub link: String,
    /// Public download, export or folder listing URL.
    pub fetch: String,
    /// Expected extension when the URL has none (exports: `docx`, `xlsx`, `pptx`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
}

impl StorageLink {
    /// The file is a Google export: its metadata is Google's, not the author's.
    pub fn exported(&self) -> bool {
        self.kind == ItemKind::Export
    }
}

/// Base URLs of the providers (tests point them at a local server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEndpoints {
    pub drive: String,
    pub docs: String,
    pub onedrive_api: String,
    /// Host suffix of SharePoint tenants (`sharepoint.com`).
    pub sharepoint_suffix: String,
    /// Extra host names recognised per provider (tests: `drive.storage.test`).
    pub aliases: Vec<(String, Provider)>,
}

impl Default for StorageEndpoints {
    fn default() -> Self {
        StorageEndpoints {
            drive: "https://drive.google.com".into(),
            docs: "https://docs.google.com".into(),
            onedrive_api: "https://api.onedrive.com".into(),
            sharepoint_suffix: "sharepoint.com".into(),
            aliases: Vec::new(),
        }
    }
}

/// Default number of files taken from one public folder.
pub const FOLDER_FILES: usize = 200;
/// Default number of files taken from all folders of a scan.
pub const FOLDER_TOTAL: usize = 1000;

fn host_of(base: &str) -> String {
    Url::parse(base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default()
}

fn trim_base(b: &str) -> &str {
    b.trim_end_matches('/')
}

/// A Drive/Docs id: URL-safe base64 alphabet, at least 10 characters.
fn drive_id(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() >= 10
        && s.len() <= 120
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .then(|| s.to_string())
}

/// Hosts each provider serves from, including redirects of a download (for the passive hop list).
pub fn provider_hosts(p: Provider, ep: &StorageEndpoints) -> Vec<String> {
    let mut v: Vec<String> = match p {
        Provider::GoogleDrive | Provider::GoogleDocs => vec![
            "google.com".into(),
            "googleusercontent.com".into(),
            host_of(&ep.drive),
            host_of(&ep.docs),
        ],
        Provider::OneDrive => vec![
            "1drv.ms".into(),
            "onedrive.live.com".into(),
            "1drv.com".into(),
            "live.com".into(),
            host_of(&ep.onedrive_api),
        ],
        Provider::Dropbox => vec!["dropbox.com".into(), "dropboxusercontent.com".into()],
        Provider::SharePoint => vec![ep.sharepoint_suffix.clone()],
    };
    v.extend(
        ep.aliases
            .iter()
            .filter(|(_, ap)| *ap == p)
            .map(|(h, _)| h.clone()),
    );
    v.retain(|h| !h.is_empty());
    v.sort();
    v.dedup();
    v
}

fn provider_of(host: &str, ep: &StorageEndpoints) -> Option<Provider> {
    if let Some((_, p)) = ep.aliases.iter().find(|(h, _)| h == host) {
        return Some(*p);
    }
    if host == host_of(&ep.drive) || host == "drive.google.com" {
        return Some(Provider::GoogleDrive);
    }
    if host == host_of(&ep.docs) || host == "docs.google.com" {
        return Some(Provider::GoogleDocs);
    }
    if host == "1drv.ms" || host == "onedrive.live.com" {
        return Some(Provider::OneDrive);
    }
    if host == "dropbox.com" || host == "www.dropbox.com" {
        return Some(Provider::Dropbox);
    }
    let sp = ep.sharepoint_suffix.as_str();
    if !sp.is_empty() && host.ends_with(&format!(".{sp}")) {
        return Some(Provider::SharePoint);
    }
    None
}

/// URL-safe base64 without padding (OneDrive share ids).
fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn query(u: &Url, key: &str) -> Option<String> {
    u.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn google_drive(u: &Url, ep: &StorageEndpoints) -> Option<StorageLink> {
    let segs: Vec<&str> = u.path_segments()?.filter(|s| !s.is_empty()).collect();
    let drive = trim_base(&ep.drive);
    let (kind, id) = match segs.as_slice() {
        ["file", "d", id, ..] => (ItemKind::File, drive_id(id)?),
        ["open"] | ["uc"] => (ItemKind::File, drive_id(&query(u, "id")?)?),
        ["drive", "folders", id, ..]
        | ["drive", "u", _, "folders", id, ..]
        | ["drive", "mobile", "folders", id, ..] => (ItemKind::Folder, drive_id(id)?),
        ["folderview"] | ["embeddedfolderview"] => (ItemKind::Folder, drive_id(&query(u, "id")?)?),
        _ => return None,
    };
    let fetch = match kind {
        ItemKind::Folder => format!("{drive}/embeddedfolderview?id={id}"),
        _ => {
            let rk = query(u, "resourcekey")
                .map(|k| format!("&resourcekey={k}"))
                .unwrap_or_default();
            format!("{drive}/uc?export=download&id={id}{rk}")
        }
    };
    Some(StorageLink {
        provider: Provider::GoogleDrive,
        kind,
        id,
        link: u.to_string(),
        fetch,
        ext: None,
    })
}

fn google_docs(u: &Url, ep: &StorageEndpoints) -> Option<StorageLink> {
    let segs: Vec<&str> = u.path_segments()?.filter(|s| !s.is_empty()).collect();
    // `/document/u/0/d/<id>` and `/document/d/<id>`; published `/d/e/<id>` copies are skipped
    let (app, rest) = segs.split_first()?;
    let rest: Vec<&str> = match rest {
        ["u", _, tail @ ..] => tail.to_vec(),
        tail => tail.to_vec(),
    };
    let id = match rest.as_slice() {
        ["d", "e", ..] => return None,
        ["d", id, ..] => drive_id(id)?,
        _ => return None,
    };
    let docs = trim_base(&ep.docs);
    let (fetch, ext) = match *app {
        "document" => (format!("{docs}/document/d/{id}/export?format=docx"), "docx"),
        "spreadsheets" => (
            format!("{docs}/spreadsheets/d/{id}/export?format=xlsx"),
            "xlsx",
        ),
        "presentation" => (format!("{docs}/presentation/d/{id}/export/pptx"), "pptx"),
        // forms and drawings carry no document
        _ => return None,
    };
    Some(StorageLink {
        provider: Provider::GoogleDocs,
        kind: ItemKind::Export,
        id,
        link: u.to_string(),
        fetch,
        ext: Some(ext.into()),
    })
}

fn onedrive(u: &Url, ep: &StorageEndpoints) -> Option<StorageLink> {
    let host = u.host_str()?.to_ascii_lowercase();
    // short links and personal share links; `onedrive.live.com/` without an item is a home page
    if host != "1drv.ms" && query(u, "resid").is_none() && query(u, "id").is_none() {
        return None;
    }
    if host == "1drv.ms" && u.path().len() < 4 {
        return None;
    }
    // folder share links (`1drv.ms/f/...`) are not listed: their contents need the API
    if host == "1drv.ms" && u.path().starts_with("/f/") {
        return None;
    }
    let link = u.to_string();
    let fetch = format!(
        "{}/v1.0/shares/u!{}/root/content",
        trim_base(&ep.onedrive_api),
        b64url(link.as_bytes())
    );
    Some(StorageLink {
        provider: Provider::OneDrive,
        kind: ItemKind::File,
        id: link.clone(),
        link,
        fetch,
        ext: None,
    })
}

fn dropbox(u: &Url) -> Option<StorageLink> {
    let p = u.path();
    // files: `/s/<key>/<name>`, `/scl/fi/<key>/<name>`; folders (`/sh/`, `/scl/fo/`) are zips of
    // everything inside and are not fetched
    if !(p.starts_with("/s/") || p.starts_with("/scl/fi/")) {
        return None;
    }
    let mut fetch = u.clone();
    let pairs: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| k != "dl" && k != "raw")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    fetch
        .query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair("dl", "1");
    fetch.set_fragment(None);
    Some(StorageLink {
        provider: Provider::Dropbox,
        kind: ItemKind::File,
        id: u.path().to_string(),
        link: u.to_string(),
        fetch: fetch.to_string(),
        ext: None,
    })
}

fn sharepoint(u: &Url) -> Option<StorageLink> {
    // sharing links: `/:b:/s/site/<token>`, `/:w:/g/personal/...`; `:f:` is a folder
    let first = u.path_segments()?.next()?;
    let kind = first.strip_prefix(':')?.strip_suffix(':')?;
    if kind == "f" || kind.is_empty() || kind.len() > 2 {
        return None;
    }
    let mut fetch = u.clone();
    fetch.set_fragment(None);
    if query(u, "download").is_none() {
        fetch.query_pairs_mut().append_pair("download", "1");
    }
    Some(StorageLink {
        provider: Provider::SharePoint,
        kind: ItemKind::File,
        id: u.path().to_string(),
        link: u.to_string(),
        fetch: fetch.to_string(),
        ext: None,
    })
}

/// Recognises a link to a public storage item.
pub fn parse_storage(u: &Url, ep: &StorageEndpoints) -> Option<StorageLink> {
    let host = u.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    match provider_of(&host, ep)? {
        Provider::GoogleDrive => google_drive(u, ep).or_else(|| google_docs(u, ep)),
        Provider::GoogleDocs => google_docs(u, ep).or_else(|| google_drive(u, ep)),
        Provider::OneDrive => onedrive(u, ep),
        Provider::Dropbox => dropbox(u),
        Provider::SharePoint => sharepoint(u),
    }
}

/// Returns `true` if the URL is on a known storage host (recognised item or not).
pub fn is_storage_host(u: &Url, ep: &StorageEndpoints) -> bool {
    u.host_str()
        .is_some_and(|h| provider_of(&h.trim_end_matches('.').to_ascii_lowercase(), ep).is_some())
}

/// A file listed in a public Drive folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntry {
    pub id: String,
    pub name: Option<String>,
}

fn decode_html(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// Parses the public folder view (`embeddedfolderview?id=`): file entries in page order and
/// subfolder ids. Each entry block has `id="entry-<ID>"`, a link to `/file/d/<ID>/...` (files)
/// or `/drive/folders/<ID>` (subfolders) and a `flip-entry-title` with the name.
pub fn parse_folder_listing(html: &str) -> (Vec<FolderEntry>, Vec<String>) {
    let mut files: Vec<FolderEntry> = Vec::new();
    let mut folders: Vec<String> = Vec::new();
    let mut rest = html;
    let push_folder = |folders: &mut Vec<String>, id: String| {
        if !folders.contains(&id) {
            folders.push(id);
        }
    };
    while let Some(p) = rest.find("href=\"") {
        let after = &rest[p + 6..];
        let Some(end) = after.find('"') else { break };
        let href = decode_html(&after[..end]);
        rest = &after[end..];
        let path = href.split(['?', '#']).next().unwrap_or("");
        if let Some(i) = path.find("/file/d/") {
            let id = path[i + 8..].split('/').next().unwrap_or("");
            if let Some(id) = drive_id(id) {
                if !files.iter().any(|f| f.id == id) {
                    // the title follows the link inside the same entry block
                    let name = rest
                        .find("flip-entry-title\">")
                        .filter(|&t| rest[..t].find("href=\"").is_none())
                        .and_then(|t| {
                            let s = &rest[t + 18..];
                            s.find('<').map(|e| decode_html(s[..e].trim()))
                        })
                        .filter(|n| !n.is_empty());
                    files.push(FolderEntry { id, name });
                }
            }
        } else if let Some(i) = path.find("/folders/") {
            let id = path[i + 9..].split('/').next().unwrap_or("");
            if let Some(id) = drive_id(id) {
                push_folder(&mut folders, id);
            }
        }
    }
    (files, folders)
}

/// Builds the file link for an id listed in a folder.
pub fn drive_file(id: &str, ep: &StorageEndpoints) -> Option<StorageLink> {
    let u = Url::parse(&format!("{}/file/d/{id}/view", trim_base(&ep.drive))).ok()?;
    google_drive(&u, ep)
}

/// File name from a `Content-Disposition` header (`filename*=UTF-8''...` wins over `filename=`).
pub fn disposition_name(v: &str) -> Option<String> {
    let mut plain = None;
    for part in v.split(';').map(str::trim) {
        let lower = part.to_ascii_lowercase();
        if let Some(x) = lower.strip_prefix("filename*=") {
            let raw = &part[part.len() - x.len()..];
            let enc = raw.rsplit("''").next().unwrap_or(raw).trim_matches('"');
            let name = crate::filter::percent_decode(enc);
            if !name.trim().is_empty() {
                return Some(clean_name(&name));
            }
        } else if lower.starts_with("filename=") {
            let raw = part[9..].trim().trim_matches('"');
            if !raw.is_empty() {
                plain = Some(clean_name(raw));
            }
        }
    }
    plain
}

/// Keeps a file name safe for display and storage: no path separators or control characters.
fn clean_name(s: &str) -> String {
    let n: String = s
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(s)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    n.trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<StorageLink> {
        parse_storage(&Url::parse(s).unwrap(), &StorageEndpoints::default())
    }

    const ID: &str = "1AbCdEfGhIjKlMnOpQrStUvWxYz012345";

    #[test]
    fn google_drive_files_and_folders() {
        for link in [
            format!("https://drive.google.com/file/d/{ID}/view?usp=sharing"),
            format!("https://drive.google.com/open?id={ID}"),
            format!("https://drive.google.com/uc?id={ID}&export=download"),
        ] {
            let s = p(&link).unwrap_or_else(|| panic!("{link}"));
            assert_eq!(s.provider, Provider::GoogleDrive);
            assert_eq!(s.kind, ItemKind::File);
            assert_eq!(s.id, ID);
            assert_eq!(
                s.fetch,
                format!("https://drive.google.com/uc?export=download&id={ID}")
            );
            assert!(!s.exported());
        }
        let s = p(&format!(
            "https://drive.google.com/file/d/{ID}/view?resourcekey=0-abc"
        ))
        .unwrap();
        assert!(s.fetch.ends_with("&resourcekey=0-abc"));
        for link in [
            format!("https://drive.google.com/drive/folders/{ID}?usp=sharing"),
            format!("https://drive.google.com/drive/u/1/folders/{ID}"),
        ] {
            let s = p(&link).unwrap();
            assert_eq!(s.kind, ItemKind::Folder);
            assert_eq!(
                s.fetch,
                format!("https://drive.google.com/embeddedfolderview?id={ID}")
            );
        }
        assert!(p("https://drive.google.com/").is_none());
        assert!(p("https://drive.google.com/file/d/short/view").is_none());
    }

    #[test]
    fn google_docs_are_exports() {
        let d = p(&format!(
            "https://docs.google.com/document/d/{ID}/edit?usp=sharing"
        ))
        .unwrap();
        assert!(d.exported());
        assert_eq!(d.ext.as_deref(), Some("docx"));
        assert_eq!(
            d.fetch,
            format!("https://docs.google.com/document/d/{ID}/export?format=docx")
        );
        let s = p(&format!(
            "https://docs.google.com/spreadsheets/u/0/d/{ID}/htmlview"
        ))
        .unwrap();
        assert_eq!(s.ext.as_deref(), Some("xlsx"));
        let sl = p(&format!("https://docs.google.com/presentation/d/{ID}/pub")).unwrap();
        assert!(sl.fetch.ends_with("/export/pptx"));
        assert!(p(&format!("https://docs.google.com/forms/d/{ID}/viewform")).is_none());
        assert!(p(&format!("https://docs.google.com/document/d/e/{ID}/pub")).is_none());
        // a Docs link given on the Drive host still works
        assert!(p(&format!("https://drive.google.com/document/d/{ID}/edit")).is_some());
    }

    #[test]
    fn onedrive_dropbox_sharepoint() {
        let o = p("https://1drv.ms/b/s!AkL3x9Example").unwrap();
        assert_eq!(o.provider, Provider::OneDrive);
        assert_eq!(
            o.fetch,
            format!(
                "https://api.onedrive.com/v1.0/shares/u!{}/root/content",
                b64url(b"https://1drv.ms/b/s!AkL3x9Example")
            )
        );
        assert!(p("https://onedrive.live.com/?cid=ABC&resid=ABC!123&authkey=x").is_some());
        assert!(p("https://onedrive.live.com/about/").is_none());
        assert!(p("https://1drv.ms/f/s!AkFolder").is_none());
        let d = p("https://www.dropbox.com/scl/fi/k3y/report.pdf?rlkey=r1&dl=0").unwrap();
        assert_eq!(
            d.fetch,
            "https://www.dropbox.com/scl/fi/k3y/report.pdf?rlkey=r1&dl=1"
        );
        assert!(p("https://www.dropbox.com/s/abc/plan.docx")
            .unwrap()
            .fetch
            .ends_with("?dl=1"));
        assert!(p("https://www.dropbox.com/sh/folder/xyz").is_none());
        let s = p("https://tenant.sharepoint.com/:b:/s/site/EaBcDeF?e=x1").unwrap();
        assert_eq!(s.provider, Provider::SharePoint);
        assert!(s.fetch.ends_with("e=x1&download=1"));
        assert!(p("https://tenant.sharepoint.com/:f:/s/site/EaBc").is_none());
        assert!(p("https://tenant.sharepoint.com/sites/home").is_none());
    }

    #[test]
    fn b64url_matches_reference() {
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn aliases_route_to_test_hosts() {
        let ep = StorageEndpoints {
            drive: "http://drive.storage.test:8080".into(),
            docs: "http://docs.storage.test:8080".into(),
            aliases: vec![("box.storage.test".into(), Provider::Dropbox)],
            ..Default::default()
        };
        let u = Url::parse(&format!("http://drive.storage.test:8080/file/d/{ID}/view")).unwrap();
        let s = parse_storage(&u, &ep).unwrap();
        assert_eq!(
            s.fetch,
            format!("http://drive.storage.test:8080/uc?export=download&id={ID}")
        );
        let u = Url::parse("http://box.storage.test/s/k/a.pdf").unwrap();
        assert!(parse_storage(&u, &ep).is_some());
        assert!(provider_hosts(Provider::Dropbox, &ep).contains(&"box.storage.test".to_string()));
        assert!(is_storage_host(&u, &ep));
    }

    #[test]
    fn folder_listing_fixture() {
        let html = include_str!("../tests/fixtures/storage/folder_view.html");
        let (files, folders) = parse_folder_listing(html);
        let ids: Vec<&str> = files.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "1FileAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "1FileBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "1FileCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            ]
        );
        assert_eq!(files[0].name.as_deref(), Some("Annual report 2025.pdf"));
        assert_eq!(files[2].name.as_deref(), Some("Budget & plan.xlsx"));
        assert_eq!(
            folders,
            vec!["1SubFolderDDDDDDDDDDDDDDDDDDDDDDD".to_string()]
        );
        let f = drive_file(ids[1], &StorageEndpoints::default()).unwrap();
        assert!(f.fetch.ends_with(ids[1]));
    }

    #[test]
    fn content_disposition_names() {
        assert_eq!(
            disposition_name("attachment; filename=\"Plan 2026.pdf\"").as_deref(),
            Some("Plan 2026.pdf")
        );
        assert_eq!(
            disposition_name(
                "attachment; filename=\"x.pdf\"; filename*=UTF-8''%D0%9F%D0%BB%D0%B0%D0%BD.pdf"
            )
            .as_deref(),
            Some("План.pdf")
        );
        assert_eq!(
            disposition_name("inline; filename=\"../../etc/passwd\"").as_deref(),
            Some("passwd")
        );
        assert_eq!(disposition_name("inline"), None);
    }
}
