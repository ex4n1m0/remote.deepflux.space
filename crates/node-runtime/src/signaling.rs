//! Signaling transport for the node runtime.
//!
//! The session machines mint fully-formed [`SignalingEnvelope`]s
//! (`Action::Send`); a signaling adapter only moves them between nodes.
//! Two implementations:
//!
//! * [`SignalingHub`] — in-memory direct routing for tests: envelopes land
//!   in the target device's inbox immediately (the harness controls when
//!   the target polls, so scenarios stay deterministic).
//! * [`FileSignaling`] — the M2 manual adapter (RD-006): one JSONL stream
//!   per direction (`c2h.jsonl`, `h2c.jsonl`) in a shared directory,
//!   atomic line appends, offset-tracked incremental reads, protocol
//!   version checks, and a 1 MiB-per-drain bound (invariant 3). This is
//!   the spike rig's envelope format, now routed **through** the session
//!   machines instead of direct transport calls — the same envelope shapes
//!   the M3 Vercel service will forward.
//!
//! Service-directed envelopes (`Register`, `Heartbeat` →
//! `SIGNALING_SERVICE_ID`) are swallowed and counted by both adapters:
//! the file adapter *is* the service stand-in, and the node self-injects
//! the `Registered` ack after a successful `Register` write (see
//! `node::Node::pump`).

use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::timers::MachineKind;
use protocol::signaling::{
    DeviceId, SIGNALING_SERVICE_ID, SignalingEnvelope, ensure_signaling_version,
};

/// One inbound envelope plus the machine (host/controller role) that sent
/// it — the runtime's `MachineRef`. Needed because `Disconnect` routing is
/// sender-role-dependent (a host hanging up informs the peer's controller
/// machine and vice versa), exactly like the `World` harness in
/// `crates/session/tests/two_peers.rs`.
#[derive(Debug, Clone)]
pub struct InboundEnvelope {
    pub from_machine: MachineKind,
    pub envelope: SignalingEnvelope,
}

/// The signaling boundary a node talks to. `Send` but polling-based: the
/// node's pump thread calls [`SignalingIo::poll_incoming`] on its own
/// cadence — no callbacks into the machines from I/O.
pub trait SignalingIo: Send {
    /// Enqueue one outbound envelope. `from_machine` names the machine
    /// that minted it (or the runtime for locally gathered ICE
    /// candidates).
    fn send(
        &mut self,
        from_machine: MachineKind,
        envelope: SignalingEnvelope,
    ) -> Result<(), String>;
    /// Take envelopes addressed to this node that arrived since the last
    /// poll. Delivery is at-least-once; the machines dedupe by
    /// `message_id` (re-delivery is a no-op — pinned by the World-parity
    /// tests).
    fn poll_incoming(&mut self) -> Vec<InboundEnvelope>;
    /// Envelopes swallowed as service-directed (Register/Heartbeat).
    fn service_swallowed(&self) -> u64;
    /// Human-readable channel description for diagnostics (no secrets).
    fn describe(&self) -> String;
}

// ---------------------------------------------------------------------------
// In-memory hub (tests, in-process rigs)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct HubInner {
    inboxes: Vec<(DeviceId, Mutex<VecDeque<InboundEnvelope>>)>,
    service: u64,
    /// Service-directed envelopes retained for assertions (bounded).
    service_box: VecDeque<SignalingEnvelope>,
    /// Every peer-directed send, for `World.sent`-style assertions
    /// (bounded).
    sent_log: VecDeque<(DeviceId, MachineKind, SignalingEnvelope)>,
}

impl HubInner {
    fn inbox(&self, device: &str) -> Option<&Mutex<VecDeque<InboundEnvelope>>> {
        self.inboxes
            .iter()
            .find(|(id, _)| id == device)
            .map(|(_, q)| q)
    }
}

/// Direct-routing signaling fabric for in-process tests. Create one hub,
/// attach one [`HubEndpoint`] per device, route by `to_device_id`.
#[derive(Clone)]
pub struct SignalingHub {
    inner: Arc<Mutex<HubInner>>,
}

impl SignalingHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner::default())),
        }
    }

    /// Register a device and get its endpoint.
    pub fn attach(self, device: &str) -> HubEndpoint {
        let mut inner = self.inner.lock().expect("hub lock");
        if inner.inbox(device).is_none() {
            inner
                .inboxes
                .push((device.to_owned(), Mutex::new(VecDeque::new())));
        }
        HubEndpoint {
            device: device.to_owned(),
            hub: Arc::clone(&self.inner),
        }
    }

    /// How many envelopes the "service" swallowed (Register/Heartbeat).
    pub fn service_swallowed(&self) -> u64 {
        self.inner.lock().expect("hub lock").service
    }

    /// Re-deliver an envelope to `target`'s inbox verbatim (duplicate
    /// delivery probe — mirrors `World::redeliver`; the machines' dedupe
    /// must no-op it).
    pub fn redeliver(&self, target: &str, inbound: InboundEnvelope) {
        let inner = self.inner.lock().expect("hub lock");
        if let Some(queue) = inner.inbox(target) {
            queue.lock().expect("inbox lock").push_back(inbound);
        }
    }

    /// Every peer-directed envelope sent through the hub so far, with the
    /// sending device and machine (mirrors `World.sent`; bounded ring of
    /// 512 so a long test cannot grow it without limit).
    pub fn sent_log(&self) -> Vec<(String, MachineKind, SignalingEnvelope)> {
        self.inner
            .lock()
            .expect("hub lock")
            .sent_log
            .iter()
            .map(|(device, machine, envelope)| (device.clone(), *machine, envelope.clone()))
            .collect()
    }

    /// Service-directed envelopes seen so far (bounded ring of 64).
    pub fn service_envelopes(&self) -> Vec<SignalingEnvelope> {
        self.inner
            .lock()
            .expect("hub lock")
            .service_box
            .iter()
            .cloned()
            .collect()
    }
}

impl Default for SignalingHub {
    fn default() -> Self {
        Self::new()
    }
}

/// One device's attachment to a [`SignalingHub`].
pub struct HubEndpoint {
    device: DeviceId,
    hub: Arc<Mutex<HubInner>>,
}

impl SignalingIo for HubEndpoint {
    fn send(
        &mut self,
        from_machine: MachineKind,
        envelope: SignalingEnvelope,
    ) -> Result<(), String> {
        let mut inner = self.hub.lock().expect("hub lock");
        if envelope.to_device_id == SIGNALING_SERVICE_ID {
            inner.service += 1;
            if inner.service_box.len() >= 64 {
                inner.service_box.pop_front();
            }
            inner.service_box.push_back(envelope);
            return Ok(());
        }
        {
            let log = &mut inner.sent_log;
            if log.len() >= 512 {
                log.pop_front();
            }
            log.push_back((self.device.clone(), from_machine, envelope.clone()));
        }
        match inner.inbox(&envelope.to_device_id) {
            Some(queue) => {
                queue
                    .lock()
                    .expect("inbox lock")
                    .push_back(InboundEnvelope {
                        from_machine,
                        envelope,
                    });
                Ok(())
            }
            None => Err(format!("unknown target device {:?}", envelope.to_device_id)),
        }
    }

    fn poll_incoming(&mut self) -> Vec<InboundEnvelope> {
        let inner = self.hub.lock().expect("hub lock");
        let Some(queue) = inner.inbox(&self.device) else {
            return Vec::new();
        };
        let mut queue = queue.lock().expect("inbox lock");
        std::mem::take(&mut *queue).into_iter().collect()
    }

    fn service_swallowed(&self) -> u64 {
        self.hub.lock().expect("hub lock").service
    }

    fn describe(&self) -> String {
        format!("hub({})", self.device)
    }
}

// ---------------------------------------------------------------------------
// Manual file-based signaling (the M2 rig's adapter)
// ---------------------------------------------------------------------------

/// Per-drain read bound: a hostile or corrupted stream cannot make the
/// reader allocate without limit (invariant 3).
const DRAIN_READ_BYTES: usize = 1 << 20;

/// Which direction this adapter serves. One file per direction; a process
/// running a single role (the rig) owns one adapter. `Register`/
/// `Heartbeat` never reach a file (service-directed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalingDirection {
    /// Controller → host: `c2h.jsonl`.
    ControllerToHost,
    /// Host → controller: `h2c.jsonl`.
    HostToController,
}

impl SignalingDirection {
    fn file_name(self) -> &'static str {
        match self {
            SignalingDirection::ControllerToHost => "c2h.jsonl",
            SignalingDirection::HostToController => "h2c.jsonl",
        }
    }

    /// The direction that delivers to a host-role node.
    pub fn toward_host(self) -> bool {
        matches!(self, SignalingDirection::ControllerToHost)
    }
}

/// File-based manual signaling. Append one JSON line per envelope to the
/// outbound stream; incrementally read the inbound stream. Partial
/// trailing lines (a concurrent append) are retained until complete.
pub struct FileSignaling {
    dir: PathBuf,
    direction: SignalingDirection,
    out_path: PathBuf,
    in_path: PathBuf,
    in_offset: u64,
    service_swallowed: u64,
    sent: u64,
    received: u64,
    parse_skipped: u64,
}

impl FileSignaling {
    /// Create the adapter for `direction`. The outbound file is truncated
    /// (this process is the only writer of its stream); the inbound file
    /// is read from offset 0 — the signaling directory must be fresh per
    /// rig run (the run wrapper creates one).
    pub fn new(dir: &Path, direction: SignalingDirection) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("signal dir: {e}"))?;
        let out_path = dir.join(direction.file_name());
        let in_name = match direction {
            SignalingDirection::ControllerToHost => "h2c.jsonl",
            SignalingDirection::HostToController => "c2h.jsonl",
        };
        let in_path = dir.join(in_name);
        // Truncate only our own outbound stream.
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&out_path)
            .map_err(|e| format!("truncate {}: {e}", out_path.display()))?;
        Ok(Self {
            dir: dir.to_owned(),
            direction,
            out_path,
            in_path,
            in_offset: 0,
            service_swallowed: 0,
            sent: 0,
            received: 0,
            parse_skipped: 0,
        })
    }

    pub fn direction(&self) -> SignalingDirection {
        self.direction
    }

    pub fn outbound_path(&self) -> &Path {
        &self.out_path
    }

    pub fn counters(&self) -> (u64, u64, u64) {
        (self.sent, self.received, self.parse_skipped)
    }

    /// Read newly appended, complete, version-checked lines. Works over
    /// bytes so a torn multi-byte character cannot skew the offset; a
    /// trailing partial line is retained (offset stays at its start) and
    /// parsed once its newline arrives. Deduplication is *not* done here
    /// on `message_id` — re-delivered duplicates must reach the machine so
    /// its bounded dedupe log proves the no-op contract.
    fn drain_inbound(&mut self) -> Vec<SignalingEnvelope> {
        let Ok(mut file) = std::fs::OpenOptions::new().read(true).open(&self.in_path) else {
            return Vec::new();
        };
        let Ok(_) = file.seek(SeekFrom::Start(self.in_offset)) else {
            return Vec::new();
        };
        let mut chunk = vec![0u8; DRAIN_READ_BYTES];
        let Ok(n) = file.read(&mut chunk) else {
            return Vec::new();
        };
        if n == 0 {
            return Vec::new();
        }
        let bytes = &chunk[..n];
        // Consume only up to (and including) the last newline; a trailing
        // partial line stays unread for the next drain.
        let complete = match bytes.iter().rposition(|&b| b == b'\n') {
            Some(last_nl) => &bytes[..=last_nl],
            None => &[],
        };
        self.in_offset += complete.len() as u64;
        let text = String::from_utf8_lossy(complete);
        let mut out = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<SignalingEnvelope>(line) {
                Ok(envelope) => {
                    if ensure_signaling_version(envelope.protocol_version).is_err() {
                        self.parse_skipped += 1;
                        continue;
                    }
                    // Never deliver service-directed output to the machine
                    // (defensive; the streams are per direction so this
                    // cannot normally happen).
                    if envelope.to_device_id == SIGNALING_SERVICE_ID {
                        self.parse_skipped += 1;
                        continue;
                    }
                    out.push(envelope);
                }
                Err(_) => {
                    self.parse_skipped += 1;
                }
            }
        }
        self.received += out.len() as u64;
        out
    }
}

impl SignalingIo for FileSignaling {
    fn send(
        &mut self,
        _from_machine: MachineKind,
        envelope: SignalingEnvelope,
    ) -> Result<(), String> {
        if envelope.to_device_id == SIGNALING_SERVICE_ID {
            self.service_swallowed += 1;
            return Ok(());
        }
        // One write + flush per envelope; readers tolerate partial lines.
        let line = serde_json::to_string(&envelope)
            .map_err(|e| format!("envelope serialize (metadata only): {e}"))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.out_path)
            .map_err(|e| format!("open {}: {e}", self.out_path.display()))?;
        writeln!(file, "{line}").map_err(|e| format!("append: {e}"))?;
        file.flush().map_err(|e| format!("flush: {e}"))?;
        self.sent += 1;
        Ok(())
    }

    fn poll_incoming(&mut self) -> Vec<InboundEnvelope> {
        // The inbound stream is the opposite direction, so every line was
        // minted by the peer's single active machine — the direction
        // determines the sender role. A ControllerToHost adapter (writes
        // c2h) reads h2c: its inbound envelopes come from the host.
        let from_machine = if self.direction.toward_host() {
            MachineKind::Host
        } else {
            MachineKind::Controller
        };
        self.drain_inbound()
            .into_iter()
            .map(|envelope| InboundEnvelope {
                from_machine,
                envelope,
            })
            .collect()
    }

    fn service_swallowed(&self) -> u64 {
        self.service_swallowed
    }

    fn describe(&self) -> String {
        format!(
            "file({} out={}, in={})",
            self.dir.display(),
            self.out_path
                .file_name()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default(),
            self.in_path
                .file_name()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timers::MachineKind;
    use protocol::signaling::{SIGNALING_PROTOCOL_VERSION, SignalingBody};

    fn env(from: &str, to: &str, id: &str) -> SignalingEnvelope {
        SignalingEnvelope {
            protocol_version: SIGNALING_PROTOCOL_VERSION,
            message_id: id.to_owned(),
            session_id: Some("s".to_owned()),
            from_device_id: from.to_owned(),
            to_device_id: to.to_owned(),
            timestamp_ms: 0,
            body: SignalingBody::Heartbeat,
        }
    }

    #[test]
    fn hub_routes_by_device_and_swallows_service_traffic() {
        let hub = SignalingHub::new();
        let mut a = hub.clone().attach("device-a");
        let mut b = hub.clone().attach("device-b");
        a.send(MachineKind::Host, env("device-a", "device-b", "m1"))
            .unwrap();
        a.send(
            MachineKind::Host,
            env("device-a", SIGNALING_SERVICE_ID, "m2"),
        )
        .unwrap();
        let inbound_b = b.poll_incoming();
        assert_eq!(inbound_b.len(), 1);
        assert_eq!(inbound_b[0].envelope.message_id, "m1");
        assert_eq!(inbound_b[0].from_machine, MachineKind::Host);
        assert!(b.poll_incoming().is_empty());
        assert_eq!(hub.service_swallowed(), 1);
        let service = hub.service_envelopes();
        assert_eq!(service.len(), 1);
        assert!(matches!(service[0].body, SignalingBody::Heartbeat));
        assert!(
            a.send(MachineKind::Host, env("device-a", "nobody", "m3"))
                .is_err()
        );
    }

    #[test]
    fn file_signaling_round_trip_and_duplicate_lines() {
        let dir = std::env::temp_dir().join(format!("rd-sig-test-{}", std::process::id()));
        let mut c2h = FileSignaling::new(&dir, SignalingDirection::ControllerToHost).unwrap();
        let mut h2c = FileSignaling::new(&dir, SignalingDirection::HostToController).unwrap();

        let envelope = env("rig-controller", "rig-host", "c-1");
        c2h.send(MachineKind::Controller, envelope.clone()).unwrap();
        // Duplicate-signaling probe: verbatim re-delivery (same message_id).
        c2h.send(MachineKind::Controller, envelope.clone()).unwrap();
        // Service-directed envelopes never hit the file.
        c2h.send(
            MachineKind::Controller,
            env("rig-controller", SIGNALING_SERVICE_ID, "c-svc"),
        )
        .unwrap();
        assert_eq!(c2h.service_swallowed(), 1);

        assert!(
            c2h.poll_incoming().is_empty(),
            "own direction: nothing inbound yet"
        );
        let got = h2c.poll_incoming();
        assert_eq!(got.len(), 2, "duplicates are delivered; machines dedupe");
        assert_eq!(got[0].envelope.message_id, "c-1");
        assert_eq!(got[1].envelope.message_id, "c-1");
        assert_eq!(
            got[0].from_machine,
            MachineKind::Controller,
            "c2h lines are controller-minted"
        );
        assert!(h2c.poll_incoming().is_empty(), "offset tracking");
        assert_eq!(h2c.counters().2, 0);

        // Reverse direction.
        h2c.send(MachineKind::Host, env("rig-host", "rig-controller", "h-1"))
            .unwrap();
        let got = c2h.poll_incoming();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].envelope.message_id, "h-1");
        assert_eq!(
            got[0].from_machine,
            MachineKind::Host,
            "the h2c writer is the host machine"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_signaling_rejects_bad_versions_and_partial_lines_wait() {
        let dir = std::env::temp_dir().join(format!("rd-sig-test2-{}", std::process::id()));
        let mut host = FileSignaling::new(&dir, SignalingDirection::HostToController).unwrap();
        let in_path = dir.join("c2h.jsonl");

        let mut bad = env("x", "y", "bad-version");
        bad.protocol_version = SIGNALING_PROTOCOL_VERSION + 1;
        std::fs::write(&in_path, serde_json::to_string(&bad).unwrap() + "\n").unwrap();
        assert!(host.poll_incoming().is_empty());
        assert_eq!(host.counters().2, 1, "version-rejected line skipped");

        // A torn (partial) line stays unread until the newline arrives
        // (appended, like a concurrent writer mid-append).
        let whole = env("x", "y", "torn");
        let line = serde_json::to_string(&whole).unwrap();
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&in_path)
                .unwrap();
            file.write_all(line.as_bytes()).unwrap();
        }
        assert!(host.poll_incoming().is_empty());
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&in_path)
                .unwrap();
            file.write_all(b"\n").unwrap();
        }
        let got = host.poll_incoming();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].envelope.message_id, "torn");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
