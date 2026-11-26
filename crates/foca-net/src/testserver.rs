//! Minimal tokio HTTP/1.1 server for offline tests (source fixtures, redirects, lying
//! Content-Length, delays). Not for production: every response uses `Connection: close`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A received request.
#[derive(Debug, Clone)]
pub struct TestRequest {
    pub method: String,
    /// Path with query (`/cdx/search/cdx?url=...`).
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl TestRequest {
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    pub fn query(&self, k: &str) -> Option<String> {
        let q = self.target.split_once('?')?.1;
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.into_owned())
    }
}

/// A canned response.
#[derive(Debug, Clone, Default)]
pub struct TestResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Streams this many zero bytes without Content-Length (until the connection closes).
    pub stream_len: Option<u64>,
    pub delay: Option<Duration>,
    /// Do not add Content-Length automatically.
    pub no_length: bool,
}

impl TestResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        TestResponse {
            status: 200,
            body: body.into(),
            ..Default::default()
        }
    }

    pub fn status(status: u16) -> Self {
        TestResponse {
            status,
            ..Default::default()
        }
    }

    pub fn redirect(status: u16, to: &str) -> Self {
        TestResponse::status(status).header("Location", to)
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub fn delay(mut self, d: Duration) -> Self {
        self.delay = Some(d);
        self
    }
}

pub type Handler = Arc<dyn Fn(&TestRequest) -> TestResponse + Send + Sync>;

pub struct TestServer {
    pub(crate) addr: SocketAddr,
    log: Arc<Mutex<Vec<TestRequest>>>,
}

impl TestServer {
    pub async fn start(
        handler: impl Fn(&TestRequest) -> TestResponse + Send + Sync + 'static,
    ) -> TestServer {
        Self::start_on("127.0.0.1:0", handler).await
    }

    pub async fn start_on(
        bind: &str,
        handler: impl Fn(&TestRequest) -> TestResponse + Send + Sync + 'static,
    ) -> TestServer {
        let l = TcpListener::bind(bind).await.expect("bind");
        let addr = l.local_addr().expect("addr");
        let log = Arc::new(Mutex::new(Vec::new()));
        let h: Handler = Arc::new(handler);
        let lg = log.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let h = h.clone();
                let lg = lg.clone();
                tokio::spawn(async move {
                    let _ = serve(s, h, lg).await;
                });
            }
        });
        TestServer { addr, log }
    }

    /// `http://127.0.0.1:port`
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The local port the server listens on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn requests(&self) -> Vec<TestRequest> {
        self.log.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn hits(&self, path: &str) -> usize {
        self.requests().iter().filter(|r| r.path() == path).count()
    }
}

fn reason(s: u16) -> &'static str {
    match s {
        200 => "OK",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

async fn serve(
    mut s: TcpStream,
    h: Handler,
    log: Arc<Mutex<Vec<TestRequest>>>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let cl: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < cl {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    let req = TestRequest {
        method: method.clone(),
        target,
        headers,
        body,
    };
    if let Ok(mut g) = log.lock() {
        g.push(req.clone());
    }
    let resp = h(&req);
    if let Some(d) = resp.delay {
        tokio::time::sleep(d).await;
    }
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\n",
        resp.status,
        reason(resp.status)
    );
    let has_cl = resp
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    for (k, v) in &resp.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if resp.stream_len.is_none() && !has_cl && !resp.no_length {
        out.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    }
    out.push_str("\r\n");
    s.write_all(out.as_bytes()).await?;
    if method == "HEAD" {
        return s.shutdown().await;
    }
    if let Some(n) = resp.stream_len {
        let chunk = vec![0u8; 16 * 1024];
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len() as u64) as usize;
            s.write_all(&chunk[..k]).await?;
            left -= k as u64;
        }
    } else {
        s.write_all(&resp.body).await?;
    }
    s.shutdown().await
}
