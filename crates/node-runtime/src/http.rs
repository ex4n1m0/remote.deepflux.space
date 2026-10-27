//! HTTPS agent helper (QA hotfix 2026-10-24).
//!
//! ureq's `native-tls` feature is an *adapter*: it is never used by the
//! crate-level convenience calls (`ureq::post` etc.) or by a bare
//! `AgentBuilder` — the connector must be set explicitly. Every HTTPS
//! caller in this workspace goes through [`https_agent`], so schannel TLS
//! is actually configured (the account client's first production use
//! surfaced this: "no TLS backend is configured").

use std::sync::Arc;
use std::time::Duration;

/// A `ureq` agent with schannel (native-tls) TLS + timeout + UA.
pub fn https_agent(timeout: Duration, user_agent: &str) -> ureq::Agent {
    let connector = native_tls::TlsConnector::new().expect("schannel TlsConnector");
    ureq::AgentBuilder::new()
        .tls_connector(Arc::new(connector))
        .timeout(timeout)
        .user_agent(user_agent)
        .build()
}

/// A streaming variant for long bodies (downloads): per-I/O timeouts
/// only, deliberately NO overall timeout — [`https_agent`]'s request
/// timeout would abort a multi-minute transfer mid-body. A stalled
/// server still errors out via the read timeout; healthy streams run
/// as long as they need.
pub fn https_agent_io(connect: Duration, io: Duration, user_agent: &str) -> ureq::Agent {
    let connector = native_tls::TlsConnector::new().expect("schannel TlsConnector");
    ureq::AgentBuilder::new()
        .tls_connector(Arc::new(connector))
        .timeout_connect(connect)
        .timeout_read(io)
        .timeout_write(io)
        .user_agent(user_agent)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_builds_with_a_tls_connector() {
        // Construction alone pins the fix (a bare AgentBuilder builds too,
        // so this is a smoke, not a TLS proof; real proof = live probe).
        let _agent = https_agent(Duration::from_secs(5), "test");
        let _streaming = https_agent_io(Duration::from_secs(5), Duration::from_secs(30), "test");
    }
}
