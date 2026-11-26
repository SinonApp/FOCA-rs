//! Network layer errors.

use foca_core::ScopeDenied;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    /// A request to a host outside the scope (or excluded) was blocked before any network call.
    #[error("вне скоупа: {host} ({reason})")]
    OutOfScope { host: String, reason: String },
    /// An active operation outside the active stage of a scan (passive or standard profile).
    #[error("активная операция запрещена: {0}")]
    ActiveDenied(ScopeDenied),
    #[error("отменено")]
    Cancelled,
    #[error("таймаут")]
    Timeout,
    #[error("HTTP {0}")]
    Status(u16),
    /// The body exceeds the limit (the stream is cut off; Content-Length is not trusted).
    #[error("превышен лимит размера {limit} байт")]
    TooLarge { limit: u64 },
    #[error("слишком много редиректов")]
    TooManyRedirects,
    #[error("неверный URL: {0}")]
    BadUrl(String),
    #[error("DNS: {0}")]
    Dns(String),
    #[error("сеть: {0}")]
    Request(String),
    #[error("прокси: {0}")]
    Proxy(String),
    #[error("разбор ответа: {0}")]
    Parse(String),
    #[error("ввод-вывод: {0}")]
    Io(String),
    #[error("нужен ключ API: {0}")]
    NoKey(String),
}

impl NetError {
    /// Returns a short code for the log and the UI.
    pub fn code(&self) -> &'static str {
        match self {
            NetError::OutOfScope { .. } => "out_of_scope",
            NetError::ActiveDenied(_) => "not_active_phase",
            NetError::Cancelled => "cancelled",
            NetError::Timeout => "timeout",
            NetError::Status(_) => "http_status",
            NetError::TooLarge { .. } => "too_large",
            NetError::TooManyRedirects => "too_many_redirects",
            NetError::BadUrl(_) => "bad_url",
            NetError::Dns(_) => "dns",
            NetError::Request(_) => "network",
            NetError::Proxy(_) => "proxy",
            NetError::Parse(_) => "parse",
            NetError::Io(_) => "io",
            NetError::NoKey(_) => "nokey",
        }
    }

    /// Returns `true` if the request was blocked by scope policy rather than by a network error.
    pub fn is_scope_denial(&self) -> bool {
        matches!(
            self,
            NetError::OutOfScope { .. } | NetError::ActiveDenied(_)
        )
    }

    /// Returns `true` if the error is transient and worth retrying.
    pub fn is_transient(&self) -> bool {
        match self {
            NetError::Timeout | NetError::Request(_) => true,
            NetError::Status(s) => matches!(s, 408 | 425 | 429 | 500 | 502 | 503 | 504),
            _ => false,
        }
    }
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::TimedOut {
            NetError::Timeout
        } else {
            NetError::Io(e.to_string())
        }
    }
}
