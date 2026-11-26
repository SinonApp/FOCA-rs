//! Live smoke run (not a test): `cargo run -p foca-recon --example live -- python.org testfire.net`.
//! Fetches the home page, favicon and up to 2 external scripts via `NetClient` (scope = the
//! given hosts), runs `analyze_site` and prints the numbers. grep.app is queried for the
//! first host.

use std::sync::Arc;

use foca_core::Scope;
use foca_net::{Access, MemorySink, NetClient, NetConfig, NetRequest};
use foca_recon::report::{FaviconInput, ScriptInput};
use foca_recon::tech::PageInput;
use foca_recon::{analyze_site, grepapp, ReconInput};

async fn get(c: &NetClient, url: &str) -> Option<(Vec<(String, String)>, Vec<u8>, String)> {
    let r = c
        .send(NetRequest::get(url, "recon", Access::TouchesTarget).ok()?)
        .await
        .ok()?;
    let h = r
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let final_url = r.url().to_string();
    let b = r.bytes_limited(4 << 20).await.ok()?;
    Some((h, b, final_url))
}

#[tokio::main]
async fn main() {
    let hosts: Vec<String> = std::env::args().skip(1).collect();
    let (scope, _) = Scope::from_lines(&hosts.join("\n"), "");
    let net = NetClient::new(NetConfig::default(), scope, Arc::new(MemorySink::default())).unwrap();
    for h in &hosts {
        let mut got = None;
        for scheme in ["https", "http"] {
            got = get(&net, &format!("{scheme}://{h}/")).await;
            if got.is_some() {
                break;
            }
        }
        let Some((headers, body, final_url)) = got else {
            println!("{h}: главная не скачалась (https и http)");
            continue;
        };
        let html = String::from_utf8_lossy(&body).to_string();
        let page = PageInput {
            url: final_url.clone(),
            headers,
            html,
        };
        let mut input = ReconInput {
            target: h.clone(),
            pages: vec![page],
            ..Default::default()
        };
        let pre = analyze_site(&input);
        let fav = pre.icon_links.first().map(|l| l.url.clone());
        if let Some(f) = fav {
            if let Some((_, bytes, u)) = get(&net, &f).await {
                input.favicon = Some(FaviconInput { url: u, bytes });
            }
        }
        for s in pre
            .script_candidates
            .iter()
            .filter(|s| s.contains(h.as_str()))
            .take(2)
        {
            if let Some((_, b, u)) = get(&net, s).await {
                input.scripts.push(ScriptInput {
                    url: u,
                    body: String::from_utf8_lossy(&b).to_string(),
                });
            }
        }
        let r = analyze_site(&input);
        let eps: usize = r.js.iter().map(|j| j.endpoints.len()).sum();
        let secrets: usize = r.js.iter().map(|j| j.secrets.len()).sum();
        println!("== {h} ({final_url})");
        println!(
            "favicon: {:?}",
            r.favicon
                .as_ref()
                .map(|f| (f.url.clone(), f.hash.mmh3, f.hash.size))
        );
        println!(
            "tech {}: {}",
            r.technologies.len(),
            r.technologies
                .iter()
                .map(|t| format!(
                    "{}{}{}",
                    t.name,
                    t.version
                        .as_ref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default(),
                    if t.outdated.is_some() {
                        " (устар.)"
                    } else {
                        ""
                    }
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "analytics: {:?}",
            r.analytics_ids
                .iter()
                .map(|a| format!("{}:{}", a.kind, a.id))
                .collect::<Vec<_>>()
        );
        println!(
            "js файлов {} (+inline), эндпоинтов {eps}, секретов {secrets}",
            input.scripts.len()
        );
        for j in &r.js {
            for s in &j.secrets {
                println!("  секрет {} {} строка {}", s.kind, s.masked, s.line);
            }
            for e in j
                .endpoints
                .iter()
                .filter(|e| e.kind == "api" || e.kind == "graphql")
                .take(5)
            {
                println!("  api {}", e.raw);
            }
        }
        println!(
            "бакетов {}: {:?}",
            r.buckets.len(),
            r.buckets.iter().map(|b| b.name.clone()).collect::<Vec<_>>()
        );
        println!(
            "находок {}: {:?}",
            r.findings.len(),
            r.findings
                .iter()
                .map(|f| f.title.clone())
                .collect::<Vec<_>>()
        );
    }
    if let Some(h) = hosts.first() {
        match grepapp::search(&net, grepapp::DEFAULT_BASE, h, 1).await {
            Ok(g) => println!(
                "grep.app {h}: total {}, hits {}, repos {:?}",
                g.total,
                g.hits.len(),
                g.repos.iter().take(5).collect::<Vec<_>>()
            ),
            Err(e) => println!("grep.app {h}: {e}"),
        }
    }
}
