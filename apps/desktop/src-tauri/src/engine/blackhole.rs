//! Test-only ICE chaos for the E2E connect-failure case (M6; mirrors the
//! m5 rig's `--blackhole-candidates` wrapper, `crates/node-runtime/
//! examples/m2_rig.rs`): rewrite every REMOTE candidate's port to the
//! discard port (9) before the ICE agent sees it. Signaling works;
//! connectivity checks can never land — the "signaling ok, ICE dead"
//! direct-only failure class (symmetric NAT / UDP blocked, invariant 4)
//! without needing a WFP filter on loopback sockets.
//!
//! Product code never sets [`crate::engine::EngineConfig::
//! blackhole_remote_candidates`]; the shell has no path to it.

use transport_webrtc::{
    Channel, ReceivedFrame, Transport, TransportError, TransportEvent, VideoFrame,
};

pub struct BlackholeCandidates {
    inner: Box<dyn Transport>,
    /// How many remote candidates were rewritten (surfaced in tests).
    pub rewritten: std::sync::atomic::AtomicU64,
}

impl BlackholeCandidates {
    pub fn new(inner: impl Transport + 'static) -> Self {
        Self {
            inner: Box::new(inner),
            rewritten: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// `candidate:<foundation> <component> <proto> <priority> <addr>
    /// <port> typ ...` — the port is the 6th field (index 5); port 9 is
    /// the discard port, the faithful "firewall drops UDP toward the
    /// peer" while the address stays real. (The m5 rig's wrapper of the
    /// same name rewrites index 4 — the address — under a comment
    /// claiming the port; same cell outcome, its committed matrix
    /// evidence stands. This wrapper implements the documented intent.)
    fn rewrite(candidate: &str) -> String {
        let mut fields = candidate.split(' ').map(str::to_owned).collect::<Vec<_>>();
        if fields.len() >= 6 && fields[0].starts_with("candidate:") {
            fields[5] = "9".to_owned();
        }
        fields.join(" ")
    }
}

impl Transport for BlackholeCandidates {
    fn compose_offer(&mut self) -> Result<String, TransportError> {
        self.inner.compose_offer()
    }
    fn compose_answer(&mut self, offer_sdp: &str) -> Result<String, TransportError> {
        self.inner.compose_answer(offer_sdp)
    }
    fn apply_answer(&mut self, answer_sdp: &str) -> Result<(), TransportError> {
        self.inner.apply_answer(answer_sdp)
    }
    fn add_remote_candidate(
        &mut self,
        candidate: &str,
        sdp_mid: Option<&str>,
        sdp_mline_index: Option<u16>,
    ) -> Result<(), TransportError> {
        let rewritten = Self::rewrite(candidate);
        self.rewritten
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .add_remote_candidate(&rewritten, sdp_mid, sdp_mline_index)
    }
    fn send(&mut self, channel: Channel, bytes: &[u8]) -> Result<(), TransportError> {
        self.inner.send(channel, bytes)
    }
    fn poll(&mut self) -> Option<TransportEvent> {
        self.inner.poll()
    }
    fn send_video(&mut self, frame: VideoFrame) -> Result<(), TransportError> {
        self.inner.send_video(frame)
    }
    fn poll_video(&mut self) -> Option<ReceivedFrame> {
        self.inner.poll_video()
    }
    fn restart_ice(&mut self) -> Result<(), TransportError> {
        self.inner.restart_ice()
    }
    fn close(&mut self) {
        self.inner.close()
    }
    // `stats` and the queue-gauge accessors intentionally use the trait
    // defaults (absent): the wrapper exists only to break ICE, and the
    // engine's sampling treats stats failure as "no sample" (same
    // tolerance the m5 rig's udpblocked cell used).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_the_port_field_only() {
        let candidate =
            "candidate:842163049 1 udp 1677729535 192.168.1.42 53122 typ host generation 0";
        assert_eq!(
            BlackholeCandidates::rewrite(candidate),
            "candidate:842163049 1 udp 1677729535 192.168.1.42 9 typ host generation 0"
        );
        // Malformed input passes through untouched (the ICE agent fails it
        // typed, as it would any garbage candidate).
        assert_eq!(BlackholeCandidates::rewrite("garbage"), "garbage");
    }
}
