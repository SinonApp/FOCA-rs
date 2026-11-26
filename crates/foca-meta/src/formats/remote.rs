//! RDP and Citrix ICA files: servers, gateways, accounts, domains, passwords and paths (as in FOCA).

use foca_core::{DocFormat, Metadata, PersonRole, SecretRef};

use crate::util::{decode_text, truncate};

fn strip_port(addr: &str) -> &str {
    let a = addr.trim();
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    if a.matches(':').count() == 1 {
        a.split(':').next().unwrap_or(a)
    } else {
        a
    }
}

fn add_account(meta: &mut Metadata, value: &str, source: &str) {
    let v = value.trim();
    if let Some((dom, user)) = v.split_once('\\') {
        meta.fields
            .insert(format!("{source}:domain"), dom.to_string());
        meta.add_person(user, PersonRole::Account, source);
    } else {
        meta.add_person(v, PersonRole::Account, source);
    }
}

fn add_path_field(meta: &mut Metadata, key: &str, v: &str) {
    meta.fields.insert(key.to_string(), truncate(v, 1024));
}

pub fn extract_rdp(b: &[u8]) -> Metadata {
    let mut meta = Metadata::new(DocFormat::Rdp);
    let text = decode_text(b);
    for line in text.lines().take(10_000) {
        let mut it = line.trim().splitn(3, ':');
        let (Some(key), Some(_ty), Some(val)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let k = key.trim().to_ascii_lowercase();
        let v = val.trim();
        if v.is_empty() {
            continue;
        }
        match k.as_str() {
            "full address" | "alternate full address" | "gatewayhostname" | "kdcproxyname" => {
                meta.add_server(strip_port(v), &format!("rdp:{k}"));
            }
            "username" => add_account(&mut meta, v, "rdp:username"),
            "domain" => {
                meta.fields.insert("rdp:domain".into(), v.to_string());
            }
            "password" | "password 51" | "clearpassword" => {
                meta.secrets.push(SecretRef {
                    kind: format!("rdp_{}", k.replace(' ', "_")),
                    value: truncate(v, 4096),
                    source: format!("rdp:{k}"),
                });
                continue;
            }
            "alternate shell" | "remoteapplicationprogram" => {
                let exe = v.rsplit(['\\', '/']).next().unwrap_or(v);
                Metadata::add_unique(&mut meta.software, exe);
            }
            _ => {}
        }
        add_path_field(&mut meta, &format!("rdp:{k}"), v);
    }
    meta
}

pub fn extract_ica(b: &[u8]) -> Metadata {
    let mut meta = Metadata::new(DocFormat::Ica);
    let text = decode_text(b);
    let mut section = String::new();
    for line in text.lines().take(10_000) {
        let l = line.trim();
        if l.starts_with('[') && l.ends_with(']') {
            section = l[1..l.len() - 1].to_string();
            continue;
        }
        let Some((key, val)) = l.split_once('=') else {
            continue;
        };
        let k = key.trim().to_ascii_lowercase();
        let v = val.trim();
        if v.is_empty() || v == "*" {
            continue;
        }
        let field = format!("ica:{section}.{}", key.trim());
        if k.starts_with("address")
            || k.starts_with("httpbrowseraddress")
            || k.starts_with("tcpbrowseraddress")
            || k.starts_with("sslproxyhost")
        {
            for a in v.split(',') {
                let h = strip_port(a);
                if !h.is_empty() && h != "*" {
                    meta.add_server(h, &field);
                }
            }
        } else if k.starts_with("username") {
            add_account(&mut meta, v, "ica:username");
        } else if k.starts_with("clearpassword") || k.starts_with("password") {
            meta.secrets.push(SecretRef {
                kind: format!("ica_{k}"),
                value: truncate(v, 4096),
                source: field,
            });
            continue;
        } else if k.starts_with("initialprogram") {
            let exe = v
                .trim_start_matches('#')
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(v);
            Metadata::add_unique(&mut meta.software, exe);
        }
        meta.fields.insert(field, truncate(v, 1024));
    }
    meta
}
