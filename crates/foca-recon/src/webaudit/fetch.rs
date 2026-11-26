//! Response helpers shared by the probes that contact the target (web audit, API docs,
//! methods, source maps).

use foca_net::{NetError, NetResponse};

/// Reads at most `limit` bytes of a body; returns `(bytes, truncated)` instead of failing on
/// larger bodies.
pub(crate) async fn read_capped(
    mut r: NetResponse,
    limit: u64,
) -> Result<(Vec<u8>, bool), NetError> {
    let limit = limit as usize;
    let mut out = Vec::new();
    while let Some(c) = r.chunk().await? {
        if out.len() + c.len() > limit {
            let room = limit - out.len();
            out.extend_from_slice(&c[..room]);
            r.abort();
            return Ok((out, true));
        }
        out.extend_from_slice(&c);
    }
    Ok((out, false))
}

/// Returns `true` for errors that deny the whole host (scope, active stage, cancellation).
pub(crate) fn host_denied(e: &NetError) -> bool {
    matches!(
        e,
        NetError::OutOfScope { .. } | NetError::ActiveDenied(_) | NetError::Cancelled
    )
}
