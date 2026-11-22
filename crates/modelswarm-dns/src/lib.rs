//! MSP outbound DNS (owner directive 2026-10-19): every hostname the node
//! resolves for an OUTBOUND connection answers via DNS-over-HTTPS at
//! Cloudflare's `1.1.1.1` — bootstrap-free (the endpoint is an IP, so the
//! resolver never needs the resolver) and TLS-protected (a plain UDP/53
//! redirect to 1.1.1.1 can still be observed or spoofed on-path; DoH
//! cannot). Applied to the HTTP clients that leave the machine: tracker
//! API, Hugging Face artifact downloads, cloud API peers, the advisory
//! plane. Loopback-only clients (the llama.cpp sidecar) and the swarm's
//! QUIC dials (IP-literal multiaddrs) resolve nothing and are untouched.
//!
//! Honesty rules: any DoH failure (timeout, blocked, malformed) falls
//! back to the OPERATING SYSTEM resolver and the failure is counted —
//! degraded resolution is never silent. `MSP_DNS=system` disables DoH
//! entirely (diagnostics); `MSP_DOH_URL` overrides the endpoint (any
//! RFC 8484 server; default `https://1.1.1.1/dns-query`).
//!
//! Cache: per-hostname answers cached for a clamped 5 minutes — a cold
//! lookup costs one HTTPS round-trip to 1.1.1.1 (~10–40 ms typical), a
//! warm one is local.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Default DoH endpoint: Cloudflare at the IP literal — no bootstrap.
pub const DEFAULT_DOH_URL: &str = "https://1.1.1.1/dns-query";

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Builds the process-wide resolver the node's outbound clients share.
/// See the module docs for the env switches.
pub fn resolver() -> Arc<DohResolver> {
    Arc::new(DohResolver::from_env())
}

/// Applies the shared resolver to a client builder (the one-liner every
/// outbound client uses).
pub fn apply(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder.dns_resolver(resolver())
}

pub struct DohResolver {
    inner: Arc<Inner>,
}

struct Inner {
    url: String,
    /// `None` = system-resolver mode (`MSP_DNS=system`).
    doh: Option<reqwest::Client>,
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
    fallbacks: AtomicU64,
}

impl DohResolver {
    pub fn from_env() -> Self {
        let url = std::env::var("MSP_DOH_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_DOH_URL.to_string());
        let doh = if std::env::var("MSP_DNS")
            .map(|v| v.eq_ignore_ascii_case("system"))
            .unwrap_or(false)
        {
            None
        } else {
            Some(
                reqwest::Client::builder()
                    .timeout(QUERY_TIMEOUT)
                    .build()
                    .expect("DoH client builds"),
            )
        };
        Self {
            inner: Arc::new(Inner {
                url,
                doh,
                cache: Mutex::new(HashMap::new()),
                fallbacks: AtomicU64::new(0),
            }),
        }
    }

    /// How many resolutions degraded to the system resolver (telemetry
    /// surface — a growing number means DoH is being blocked).
    pub fn fallback_count(&self) -> u64 {
        self.inner.fallbacks.load(Ordering::Relaxed)
    }
}

impl Resolve for DohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            // IP literals never need DNS (and must not be sent to a
            // resolver — some DoH servers refuse them).
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(sockets(&[ip]));
            }
            // Warm cache.
            {
                let cache = inner.cache.lock().expect("dns cache lock");
                if let Some((ips, until)) = cache.get(&host) {
                    if Instant::now() < *until {
                        return Ok(sockets(ips));
                    }
                }
            }
            // DoH, then the honest system fallback.
            let resolved = match query_doh(&inner, &host).await {
                Some(ips) if !ips.is_empty() => ips,
                _ => {
                    inner.fallbacks.fetch_add(1, Ordering::Relaxed);
                    system_resolve(&host).await.unwrap_or_default()
                }
            };
            if resolved.is_empty() {
                return Err("dns: no addresses".into());
            }
            inner
                .cache
                .lock()
                .expect("dns cache lock")
                .insert(host, (resolved.clone(), Instant::now() + CACHE_TTL));
            Ok(sockets(&resolved))
        })
    }
}

fn sockets(ips: &[IpAddr]) -> Addrs {
    Box::new(
        ips.iter()
            .map(|ip| SocketAddr::new(*ip, 0))
            .collect::<Vec<_>>()
            .into_iter(),
    )
}

async fn query_doh(inner: &Inner, host: &str) -> Option<Vec<IpAddr>> {
    let client = inner.doh.as_ref()?;
    let a = query_one(client, &inner.url, host, QTYPE_A).await?;
    let aaaa = query_one(client, &inner.url, host, QTYPE_AAAA)
        .await
        .unwrap_or_default();
    let mut ips = a;
    ips.extend(aaaa);
    Some(ips)
}

async fn query_one(
    client: &reqwest::Client,
    url: &str,
    host: &str,
    qtype: u16,
) -> Option<Vec<IpAddr>> {
    let wire = encode_query(host, qtype)?;
    let response = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire)
        .send()
        .await
        .ok()?;
    let body = response.bytes().await.ok()?;
    parse_answers(&body)
}

async fn system_resolve(host: &str) -> Option<Vec<IpAddr>> {
    tokio::net::lookup_host((host.to_string(), 0))
        .await
        .ok()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
}

// ---- RFC 1035 wireformat (encode query, parse answers) -------------------

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

fn encode_query(host: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(host.len() + 18);
    // Header: id 0, RD=1, one question.
    out.extend_from_slice(&[
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for label in host.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len()).ok()?;
        if len == 0 || label.len() > 63 {
            return None;
        }
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]); // IN
    Some(out)
}

/// Parses A/AAAA answers out of a DNS response (CNAME chains yield the
/// terminal records the resolver included; anything unparseable = None,
/// which the caller turns into the system fallback).
fn parse_answers(wire: &[u8]) -> Option<Vec<IpAddr>> {
    if wire.len() < 12 {
        return None;
    }
    let rcode = wire[3] & 0x0f;
    if rcode != 0 {
        return None;
    }
    let questions = u16::from_be_bytes([wire[4], wire[5]]);
    let answers = u16::from_be_bytes([wire[6], wire[7]]);
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(wire, pos)?;
        pos = pos.checked_add(4)?;
    }
    let mut ips = Vec::new();
    for _ in 0..answers {
        pos = skip_name(wire, pos)?;
        if wire.len() < pos + 10 {
            return None;
        }
        let rtype = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        let rdlength = u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
        pos += 10;
        if wire.len() < pos + rdlength {
            return None;
        }
        match (rtype, rdlength) {
            (QTYPE_A, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                wire[pos],
                wire[pos + 1],
                wire[pos + 2],
                wire[pos + 3],
            ))),
            (QTYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&wire[pos..pos + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }
    Some(ips)
}

/// Skips a (possibly compressed) domain name; returns the offset after it.
fn skip_name(wire: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumped = false;
    let mut end = 0usize;
    let mut hops = 0;
    while pos < wire.len() {
        let len = wire[pos] as usize;
        if len & 0xc0 == 0xc0 {
            if wire.len() < pos + 2 {
                return None;
            }
            if !jumped {
                end = pos + 2;
                jumped = true;
            }
            // The pointer's 14-bit offset is ABSOLUTE from the message
            // start (RFC 1035 4.1.4) - no header adjustment.
            pos = (((wire[pos] & 0x3f) as usize) << 8) | wire[pos + 1] as usize;
            hops += 1;
            if hops > 16 {
                return None;
            }
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        pos = pos.checked_add(1 + len)?;
        if pos > wire.len() {
            return None;
        }
    }
    if jumped {
        Some(end)
    } else {
        Some(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encodes_canonical_shape() {
        let wire = encode_query("huggingface.co", QTYPE_A).expect("encodes");
        assert_eq!(&wire[2..4], &[0x01, 0x00], "RD set, no opcode");
        assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 1, "one question");
        // labels: 11"huggingface" 2"co" 0
        assert_eq!(wire[12], 11);
        assert_eq!(&wire[13..24], b"huggingface");
        assert_eq!(wire[24], 2);
        assert_eq!(&wire[25..27], b"co");
        assert_eq!(wire[27], 0);
        assert_eq!(&wire[28..30], &[0, QTYPE_A as u8]);
        assert_eq!(&wire[30..32], &[0, 1], "class IN");
    }

    #[test]
    fn answers_parse_with_compression_and_cname_skipping() {
        // Hand-built response: 1 question (a.b), 2 answers — a CNAME
        // (pointer-compressed name) then an A record for the same
        // compressed qname, rdata 1.2.3.4.
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0, 0, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
        let qname_at = wire.len();
        for label in ["a", "b"] {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        wire.extend_from_slice(&[0x00, QTYPE_A as u8, 0x00, 0x01]); // type A, class IN
                                                                    // Answer 1: CNAME for (compressed) qname -> "c" + pointer to ".b".
        wire.extend_from_slice(&pointer(qname_at));
        wire.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60, 0, 4]); // CNAME IN ttl 60
        wire.push(1);
        wire.push(b'c');
        wire.extend_from_slice(&pointer(qname_at + 2)); // ".b" suffix
                                                        // Answer 2: A record (compressed qname) -> 1.2.3.4.
        wire.extend_from_slice(&pointer(qname_at));
        wire.extend_from_slice(&[0, QTYPE_A as u8, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let ips = parse_answers(&wire).expect("parses");
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    fn pointer(offset: usize) -> [u8; 2] {
        [0xc0 | ((offset >> 8) as u8 & 0x3f), offset as u8]
    }

    #[test]
    fn rcode_failures_and_short_wires_return_none() {
        let mut wire = vec![0u8; 12];
        wire[3] = 0x03; // NXDOMAIN
        assert!(parse_answers(&wire).is_none());
        assert!(parse_answers(&wire[..8]).is_none());
    }

    #[test]
    fn oversize_labels_refuse_to_encode() {
        let host = "a".repeat(70);
        assert!(encode_query(&host, QTYPE_A).is_none());
    }

    /// Live check (owner-local, network-gated): 1.1.1.1 answers for a
    /// well-known host (the honest diagnostic — the fallback count is
    /// PRINTED, not asserted: a blocked-DoH network is a finding, not a
    /// test failure).
    #[tokio::test]
    #[ignore = "network"]
    async fn live_doh_resolves_huggingface() {
        use std::str::FromStr as _;
        let r = DohResolver::from_env();
        let name = reqwest::dns::Name::from_str("huggingface.co").expect("name parses");
        let addrs: Vec<SocketAddr> = r
            .resolve(name)
            .await
            .expect("resolves (DoH or system fallback)")
            .collect();
        assert!(!addrs.is_empty(), "addresses returned");
        println!(
            "resolved huggingface.co -> {:?} (system fallbacks so far: {})",
            addrs,
            r.fallback_count()
        );
    }
}
