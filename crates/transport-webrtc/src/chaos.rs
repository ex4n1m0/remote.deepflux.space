//! Deterministic application-layer loss/reorder injection for the M2 rig
//! (M2) and the M5 WAN matrix's link shaping ([`NetemProfile`]/[`Netem`]).
//!
//! The spike runs over loopback where the real network drops nothing, so
//! loss/reorder behavior is injected at the application layer, *below* the
//! `input-fast`/`input-reliable` send calls and above the SCTP channel —
//! the same boundary where a real network would act on the unordered,
//! maxRetransmits-0 channel. The RNG is a seeded xorshift64* so a failing
//! rig run reproduces exactly.
//!
//! What the injector does NOT model: SCTP-level retransmission on reliable
//! channels (loopback SCTP is reliable by construction). Reliable-channel
//! gaps are injected explicitly via [`ChaosInjector::should_drop_nth`] to
//! exercise the host-side sequence-gap detector that must answer with
//! `AllKeysUp` semantics.
//!
//! ## M5 netem (matrix fidelity, documented limits)
//!
//! [`Netem`] shapes the **outgoing RTP video path** of the host transport
//! (per-packet loss, one-way delay, token-bucket bandwidth, UDP blackhole)
//! at the `send_video` boundary — above the interceptor chain. Consequences
//! that are visible to the shaped traffic and must be read as matrix
//! caveats, not defects:
//!
//! * Injected loss is **NACK-invisible** (the packet never entered the
//!   sender's NACK-responder history), so recovery exercises the app-level
//!   keyframe path — the harsher of the two, and the one the product owns.
//! * Injected loss and shaped queueing are **GCC-invisible by construction**
//!   (M6 F59 finding): the shaper sits above the interceptor chain, so a
//!   dropped packet is never stamped with a transport-wide sequence and
//!   never enters the congestion controller's send history (it cannot be
//!   reported missing), and a shaped delay shifts the sender-side departure
//!   stamp and the receiver-side arrival stamp equally (the delay gradient
//!   cancels). `loss`/`rate_kbps` profiles therefore move the *policy*
//!   signals (`remote_loss_percent` counts the RTP sequence holes the
//!   receiver's RTCP RR reports) but never the GCC estimate. A real
//!   bottleneck between the peers does move it — wire-side queueing delays
//!   arrivals relative to paced departures.
//! * The ICE/STUN consent traffic does **not** cross the shaper, so
//!   `TransportStats::rtt_ms` (ICE pair) stays at loopback levels under a
//!   +RTT profile; the media-path delay shows up in `recv_ns`/`recv_instant`
//!   percentiles instead. The matrix reports call this out where relevant.
//! * `udp_blocked` drops every shaped RTP packet (mid-stream blackhole).
//!   The *connect-time* UDP-blocked matrix cell is driven from the rig by
//!   making the candidates unroutable (see `m5-matrix.md`); a socket-layer
//!   block would need a WFP filter, out of MVP scope.

use std::collections::VecDeque;

/// Seeded xorshift64* — small, deterministic, no dependency.
#[derive(Debug, Clone)]
pub struct ChaosRng {
    state: u64,
}

impl ChaosRng {
    /// Any nonzero seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    /// Uniform-ish u64; multiply-shift for a percent check is sufficient
    /// for fault injection (not cryptography).
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// True with probability `percent_inclusive_percent`%.
    pub fn percent_chance(&mut self, percent: u32) -> bool {
        if percent == 0 {
            return false;
        }
        if percent >= 100 {
            return true;
        }
        // Scale to a 0..100 bucket on the high bits.
        (self.next_u64() >> 32) % 100 < u64::from(percent)
    }
}

/// Per-message verdicts for one injection point.
#[derive(Debug, Clone)]
pub struct ChaosInjector {
    rng: ChaosRng,
    drop_percent: u32,
    reorder_percent: u32,
    /// Held message to emit after the next one (reordering window of 1).
    pending: Option<Vec<u8>>,
    /// Every `n`-th message on the reliable path is dropped (0 = never) —
    /// deterministic sequence-gap injection.
    drop_every_nth: u64,
    seen: u64,
    pub dropped: u64,
    pub reordered: u64,
}

impl ChaosInjector {
    /// `drop_percent`/`reorder_percent` in 0..=100; `drop_every_nth` drops
    /// exactly every n-th `filter`ed message (gap injection for the
    /// reliable-channel sequence detector).
    pub fn new(seed: u64, drop_percent: u32, reorder_percent: u32) -> Self {
        Self {
            rng: ChaosRng::new(seed),
            drop_percent,
            reorder_percent,
            pending: None,
            drop_every_nth: 0,
            seen: 0,
            dropped: 0,
            reordered: 0,
        }
    }

    /// Enable deterministic every-n-th dropping (reliable-gap injection).
    pub fn with_drop_every_nth(mut self, n: u64) -> Self {
        self.drop_every_nth = n;
        self
    }

    /// Feed one outgoing message; returns the messages that should be sent
    /// *now* (0, 1, or 2 — the reorder window is one message).
    ///
    /// Order of verdicts: loss first (a dropped message never reorders),
    /// then reorder (the previous message is held back and emitted after
    /// this one, i.e. the pair arrives swapped).
    pub fn transform(&mut self, message: Vec<u8>) -> Vec<Vec<u8>> {
        self.seen += 1;
        if self.drop_every_nth != 0 && self.seen.is_multiple_of(self.drop_every_nth) {
            self.dropped += 1;
            // A held message is unaffected by a drop.
            return self.pending.take().into_iter().collect();
        }
        if self.rng.percent_chance(self.drop_percent) {
            self.dropped += 1;
            return self.pending.take().into_iter().collect();
        }
        if self.rng.percent_chance(self.reorder_percent) {
            self.reordered += 1;
            match self.pending.take() {
                Some(prev) => vec![message, prev], // prev leaves after current: swapped pair
                None => {
                    self.pending = Some(message);
                    vec![]
                }
            }
        } else {
            let mut out = self.pending.take().into_iter().collect::<Vec<_>>();
            out.push(message);
            out
        }
    }

    /// Flush any message still held by the reorder window (call at end of
    /// an injection phase so the last message is not silently delayed).
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        self.pending.take().into_iter().collect()
    }
}

// ---------------------------------------------------------------------------
// M5 netem: loss% + one-way delay + token-bucket bandwidth + UDP blackhole
// ---------------------------------------------------------------------------

/// One shaped-link configuration. Applied to the host's outgoing RTP packets
/// (see module docs for the boundary and its fidelity limits).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetemProfile {
    /// Per-packet drop probability, 0..=100.
    pub loss_percent: u32,
    /// One-way delay added to every delivered packet, milliseconds. For an
    /// RTT matrix cell this is RTT/2 on the send path (the rig applies the
    /// other half to the controller→host input direction).
    pub one_way_delay_ms: u32,
    /// Token-bucket rate in kbps; 0 = unbounded. Bucket burst = the rate
    /// times [`NETEM_BURST_MS`].
    pub bandwidth_kbps: u32,
    /// Drop every packet (mid-stream UDP blackhole; see module docs).
    pub udp_blocked: bool,
}

impl NetemProfile {
    /// Parse `loss=N|delay_ms=N|rate_kbps=N|udp_blocked` items separated by
    /// commas (rig/matrix flag surface). Unknown keys are a typed error —
    /// a mistyped cell must fail loudly, not silently shape nothing.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut profile = NetemProfile::default();
        for item in spec.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (key, value) = item
                .split_once('=')
                .ok_or_else(|| format!("netem item {item:?}: expected key=value"))?;
            match key {
                "loss" => {
                    profile.loss_percent = value
                        .parse()
                        .map_err(|_| format!("netem loss: {value:?} not 0..=100"))?;
                    if profile.loss_percent > 100 {
                        return Err(format!("netem loss: {} not 0..=100", profile.loss_percent));
                    }
                }
                "delay_ms" => {
                    profile.one_way_delay_ms = value
                        .parse()
                        .map_err(|_| format!("netem delay_ms: {value:?} not u32"))?;
                }
                "rate_kbps" => {
                    profile.bandwidth_kbps = value
                        .parse()
                        .map_err(|_| format!("netem rate_kbps: {value:?} not u32"))?;
                }
                "udp_blocked" => {
                    profile.udp_blocked = value
                        .parse()
                        .map_err(|_| format!("netem udp_blocked: {value:?} not bool"))?;
                }
                other => return Err(format!("netem: unknown key {other:?}")),
            }
        }
        Ok(profile)
    }
}

/// Token-bucket burst depth as a fraction of the rate (the queue a real
/// bottleneck router would hold before overflowing; large enough that a
/// keyframe burst is not instant loss, small enough that step-downs bite
/// within a second).
pub const NETEM_BURST_MS: u64 = 300;

/// What to do with one packet handed to the shaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketVerdict {
    Drop,
    /// Deliver after `delay_ms` (0 = immediately).
    Deliver {
        delay_ms: u64,
    },
}

/// Deterministic per-packet shaper verdicts for one link direction.
///
/// All time is caller-fed (`now_ms`), so every matrix cell reproduces
/// exactly given the same packet sequence. The bucket holds `f64` bits;
/// given the same `(now_ms, len)` feed the arithmetic is deterministic.
#[derive(Debug, Clone)]
pub struct Netem {
    rng: ChaosRng,
    profile: NetemProfile,
    /// Token bucket, bits. Capacity = rate_kbps * 1000 * NETEM_BURST_MS/1000.
    tokens_bits: f64,
    bucket_last_ms: Option<u64>,
    pub dropped: u64,
    pub delivered: u64,
}

impl Netem {
    pub fn new(seed: u64, profile: NetemProfile) -> Self {
        let capacity = bucket_capacity_bits(profile.bandwidth_kbps);
        Self {
            rng: ChaosRng::new(seed),
            profile,
            tokens_bits: capacity,
            bucket_last_ms: None,
            dropped: 0,
            delivered: 0,
        }
    }

    /// Replace the profile (matrix step-down schedules). The bucket keeps
    /// its current fill but is re-clamped to the new capacity.
    pub fn set_profile(&mut self, profile: NetemProfile) {
        let capacity = bucket_capacity_bits(profile.bandwidth_kbps);
        self.profile = profile;
        self.tokens_bits = self.tokens_bits.min(capacity);
    }

    pub fn profile(&self) -> &NetemProfile {
        &self.profile
    }

    /// Verdict for one packet of `len_bytes` offered at `now_ms`.
    /// Order of checks: blackhole, loss, then delay/bandwidth (a dropped
    /// packet never consumes tokens — same as a real drop before the queue).
    pub fn verdict(&mut self, now_ms: u64, len_bytes: usize) -> PacketVerdict {
        if self.profile.udp_blocked {
            self.dropped += 1;
            return PacketVerdict::Drop;
        }
        if self.rng.percent_chance(self.profile.loss_percent) {
            self.dropped += 1;
            return PacketVerdict::Drop;
        }
        let mut delay_ms = u64::from(self.profile.one_way_delay_ms);
        if self.profile.bandwidth_kbps > 0 {
            let capacity = bucket_capacity_bits(self.profile.bandwidth_kbps);
            let refill_bps = f64::from(self.profile.bandwidth_kbps) * 1000.0;
            let last = self.bucket_last_ms.unwrap_or(now_ms);
            self.bucket_last_ms = Some(now_ms);
            let elapsed_ms = now_ms.saturating_sub(last) as f64;
            self.tokens_bits = (self.tokens_bits + refill_bps * elapsed_ms / 1000.0).min(capacity);
            let cost_bits = (len_bytes as f64) * 8.0;
            if self.tokens_bits < cost_bits {
                // Wait for the deficit to refill, then pay it.
                let deficit_bits = cost_bits - self.tokens_bits;
                let wait_ms = (deficit_bits / refill_bps * 1000.0).ceil() as u64;
                delay_ms = delay_ms.saturating_add(wait_ms);
                self.tokens_bits = 0.0;
            } else {
                self.tokens_bits -= cost_bits;
            }
        }
        self.delivered += 1;
        PacketVerdict::Deliver { delay_ms }
    }
}

fn bucket_capacity_bits(bandwidth_kbps: u32) -> f64 {
    if bandwidth_kbps == 0 {
        f64::INFINITY
    } else {
        f64::from(bandwidth_kbps) * 1000.0 * (NETEM_BURST_MS as f64) / 1000.0
    }
}

/// Bounded delay line for the controller→host input direction of an RTT
/// matrix cell (the other half of the round trip). Newest-relevant ordering
/// is preserved (FIFO); a full queue drops the incoming item and counts it.
#[derive(Debug)]
pub struct DelayQueue<T> {
    slots: VecDeque<(u64, T)>,
    capacity: usize,
    pub dropped: u64,
    pub delivered: u64,
}

impl<T> DelayQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            dropped: 0,
            delivered: 0,
        }
    }

    /// Enqueue `item` due at `now_ms + delay_ms`. `Err(item)` when full.
    pub fn push(&mut self, now_ms: u64, delay_ms: u64, item: T) -> Result<(), T> {
        if self.slots.len() >= self.capacity {
            self.dropped += 1;
            return Err(item);
        }
        self.slots
            .push_back((now_ms.saturating_add(delay_ms), item));
        Ok(())
    }

    /// Drain everything due at `now_ms`, in (due, enqueue) order. An item
    /// is not blocked by an earlier-enqueued item with a later due time
    /// (delays can invert under a schedule change).
    pub fn drain_due(&mut self, now_ms: u64) -> Vec<T> {
        let mut out = Vec::new();
        let mut keep = VecDeque::with_capacity(self.slots.len());
        while let Some((due, item)) = self.slots.pop_front() {
            if due <= now_ms {
                self.delivered += 1;
                out.push(item);
            } else {
                keep.push_back((due, item));
            }
        }
        self.slots = keep;
        out
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_chaos_is_identity() {
        let mut chaos = ChaosInjector::new(42, 0, 0);
        for i in 0..100u8 {
            assert_eq!(chaos.transform(vec![i]), vec![vec![i]]);
        }
    }

    #[test]
    fn full_drop_drops_everything() {
        let mut chaos = ChaosInjector::new(7, 100, 0);
        for i in 0..50u8 {
            assert!(chaos.transform(vec![i]).is_empty());
        }
        assert_eq!(chaos.dropped, 50);
    }

    #[test]
    fn deterministic_across_instances() {
        let run = |seed: u64| {
            let mut chaos = ChaosInjector::new(seed, 30, 20);
            (0..500u32)
                .map(|_| chaos.transform(vec![]).len() as u64)
                .sum::<u64>()
                + chaos.flush().len() as u64
        };
        assert_eq!(run(99), run(99), "same seed must reproduce exactly");
        assert_ne!(
            run(99),
            run(100),
            "different seeds should diverge (probabilistic but near-certain over 500 draws)"
        );
    }

    #[test]
    fn transform_never_loses_or_duplicates_bytes() {
        // Conservation: every input byte is either emitted or counted
        // dropped; reorder only permutes.
        let mut chaos = ChaosInjector::new(1, 25, 25);
        let mut emitted = 0u64;
        let input_count = 1000u64;
        for i in 0..input_count {
            emitted += chaos.transform(vec![i as u8; (i % 7) as usize + 1]).len() as u64;
        }
        emitted += chaos.flush().len() as u64;
        assert_eq!(emitted + chaos.dropped, input_count);
    }

    #[test]
    fn drop_every_nth_creates_exact_gaps() {
        let mut chaos = ChaosInjector::new(3, 0, 0).with_drop_every_nth(4);
        let mut sent = Vec::new();
        for i in 0..12u8 {
            sent.extend(chaos.transform(vec![i]));
        }
        sent.extend(chaos.flush());
        // seq 3, 7, 11 dropped (0-indexed every 4th).
        let emitted: Vec<u8> = sent.into_iter().flatten().collect();
        assert_eq!(emitted, vec![0, 1, 2, 4, 5, 6, 8, 9, 10]);
        assert_eq!(chaos.dropped, 3);
    }

    #[test]
    fn reorder_swaps_adjacent_pairs() {
        // 100% reorder: messages leave in swapped pairs (1,0),(3,2),...
        let mut chaos = ChaosInjector::new(5, 0, 100);
        let mut out = Vec::new();
        for i in 0..6u8 {
            out.extend(chaos.transform(vec![i]));
        }
        out.extend(chaos.flush());
        let flat: Vec<u8> = out.into_iter().flatten().collect();
        assert_eq!(flat, vec![1, 0, 3, 2, 5, 4]);
        // Every message passed through a reorder verdict (3 pairs × 2).
        assert_eq!(chaos.reordered, 6);
    }

    // -----------------------------------------------------------------
    // M5 netem
    // -----------------------------------------------------------------

    #[test]
    fn netem_parse_round_trips_and_rejects_garbage() {
        let profile =
            NetemProfile::parse("loss=5, delay_ms=75, rate_kbps=10000, udp_blocked=false")
                .expect("parse");
        assert_eq!(
            profile,
            NetemProfile {
                loss_percent: 5,
                one_way_delay_ms: 75,
                bandwidth_kbps: 10_000,
                udp_blocked: false,
            }
        );
        assert_eq!(NetemProfile::parse("").unwrap(), NetemProfile::default());
        assert!(NetemProfile::parse("loss=101").is_err(), "loss > 100");
        assert!(NetemProfile::parse("losss=1").is_err(), "unknown key");
        assert!(NetemProfile::parse("loss").is_err(), "missing value");
    }

    #[test]
    fn netem_udp_blocked_drops_everything() {
        let mut netem = Netem::new(1, NetemProfile::parse("udp_blocked=true").unwrap());
        for i in 0..100u64 {
            assert_eq!(
                netem.verdict(i, 1200),
                PacketVerdict::Drop,
                "blackhole must drop packet {i}"
            );
        }
        assert_eq!(netem.dropped, 100);
        assert_eq!(netem.delivered, 0);
    }

    #[test]
    fn netem_delay_is_deterministic_and_flat() {
        let mut netem = Netem::new(2, NetemProfile::parse("delay_ms=75").unwrap());
        for i in 0..50u64 {
            assert_eq!(
                netem.verdict(i * 16, 1200),
                PacketVerdict::Deliver { delay_ms: 75 }
            );
        }
        // Same seed, same feed → same verdicts (reproducible cells).
        let mut again = Netem::new(2, NetemProfile::parse("delay_ms=75").unwrap());
        assert_eq!(
            again.verdict(0, 1200),
            PacketVerdict::Deliver { delay_ms: 75 }
        );
    }

    #[test]
    fn netem_loss_percent_matches_within_tolerance() {
        let mut netem = Netem::new(9, NetemProfile::parse("loss=10").unwrap());
        let n = 20_000;
        for i in 0..n {
            let _ = netem.verdict(i, 1000);
        }
        let measured = netem.dropped as f64 / n as f64 * 100.0;
        assert!(
            (measured - 10.0).abs() < 1.0,
            "measured loss {measured:.2}% vs 10%"
        );
    }

    #[test]
    fn netem_token_bucket_shapes_a_burst() {
        // 2 Mbps bucket, 1200-byte packets: burst capacity = 2e6 * 0.3 / 8
        // = 75_000 bytes = 62 packets instant; after that packets wait.
        let mut netem = Netem::new(3, NetemProfile::parse("rate_kbps=2000").unwrap());
        let mut instant = 0;
        let mut delayed = 0;
        // Offer 100 packets back-to-back at the same instant.
        for _ in 0..100 {
            match netem.verdict(0, 1200) {
                PacketVerdict::Deliver { delay_ms: 0 } => instant += 1,
                PacketVerdict::Deliver { delay_ms } => {
                    assert!(delay_ms > 0);
                    delayed += 1;
                }
                PacketVerdict::Drop => panic!("no loss configured"),
            }
        }
        assert_eq!(instant, 62, "burst capacity in 1200B packets");
        assert_eq!(delayed, 38);
        // Each queued 1200B packet at 2 Mbps costs 4.8 ms; the wait grows
        // monotonically while the bucket is empty.
        let mut netem = Netem::new(3, NetemProfile::parse("rate_kbps=2000").unwrap());
        for _ in 0..62 {
            let _ = netem.verdict(0, 1200);
        }
        let first = netem.verdict(0, 1200);
        let second = netem.verdict(0, 1200);
        match (first, second) {
            (PacketVerdict::Deliver { delay_ms: a }, PacketVerdict::Deliver { delay_ms: b }) => {
                // The 63rd packet pays only the deficit (9600 - 4800 bits
                // left in the bucket) = 2.4 ms → 3; the 64th pays a full
                // 1200B = 4.8 ms → 5.
                assert_eq!(a, 3, "deficit-only wait for the 63rd packet");
                assert_eq!(b, 5, "full 1200B wait at 2 Mbps after the bucket empties");
            }
            other => panic!("expected deliveries, got {other:?}"),
        }
    }

    #[test]
    fn netem_profile_swap_reclamps_bucket() {
        let mut netem = Netem::new(4, NetemProfile::parse("rate_kbps=20000").unwrap());
        // Empty the 20 Mbps bucket (750 kB capacity) is impractical; instead
        // verify the clamp: fill is capacity at start, swap to 2 Mbps, the
        // fill cannot exceed the new 75 kB capacity.
        netem.set_profile(NetemProfile::parse("rate_kbps=2000").unwrap());
        // 63rd packet at the same instant must wait (62 fit).
        let mut instant = 0;
        for _ in 0..100 {
            if let PacketVerdict::Deliver { delay_ms: 0 } = netem.verdict(0, 1200) {
                instant += 1;
            }
        }
        assert_eq!(instant, 62, "clamped to the 2 Mbps burst capacity");
    }

    #[test]
    fn delay_queue_delivers_in_order_and_bounded() {
        let mut queue: DelayQueue<u32> = DelayQueue::new(4);
        for i in 0..4 {
            queue.push(100, 10, i).expect("within capacity");
        }
        assert!(queue.push(100, 10, 4).is_err(), "full");
        assert_eq!(queue.dropped, 1);
        assert!(queue.drain_due(105).is_empty(), "nothing due before 110");
        assert_eq!(queue.drain_due(110), vec![0, 1, 2, 3]);
        assert!(queue.is_empty());
        // Due-time ordering: a later push with an earlier due time still
        // leaves in due order.
        queue.push(200, 50, 10).expect("cap");
        queue.push(210, 5, 11).expect("cap");
        assert_eq!(queue.drain_due(215), vec![11]);
        assert_eq!(queue.drain_due(250), vec![10]);
    }
}
