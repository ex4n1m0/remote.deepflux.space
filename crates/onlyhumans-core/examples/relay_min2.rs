//! Minimal libp2p relay v2 reproduction, two-process variant.
//!   cargo run -p onlyhumans_core --example relay_min2 -- relay            (server)
//!   cargo run -p onlyhumans_core --example relay_min2 -- client <addr>    (reserver)
//!
//! Server prints its listen address and exits on Ctrl-C; client reserves and
//! prints the outcome. Mirrors the official relay-server/dcutr examples.

use futures::prelude::*;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, identity, noise, ping, relay, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
use std::time::Duration;

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

#[derive(NetworkBehaviour)]
struct ClientBehaviour {
    relay_client: relay::client::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "relay" => run_relay().await,
        "client" => {
            let addr: Multiaddr = std::env::args()
                .nth(2)
                .expect("client needs the relay address")
                .parse()?;
            run_client(addr).await
        }
        _ => anyhow::bail!("usage: relay_min2 relay | client <relay-addr-with-/p2p/id>"),
    }
}

async fn run_relay() -> anyhow::Result<()> {
    let key = identity::Keypair::generate_ed25519();
    let relay_peer_id = PeerId::from(key.public());
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), Default::default()),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "relay-min2/1".to_string(),
                key.public(),
            )),
        })?
        .build();
    swarm.listen_on(
        Multiaddr::empty()
            .with(Protocol::from("127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()))
            .with(Protocol::Tcp(0)),
    )?;
    loop {
        match swarm.select_next_some().await {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                println!("RELAY_ADDR={address}/p2p/{relay_peer_id}");
            }
            libp2p::swarm::SwarmEvent::Behaviour(
                RelayBehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                // Official relay-server pattern: learn our external address,
                // which auto-enables the HOP service.
                swarm.add_external_address(info.observed_addr.clone());
                println!("relay: external address learned: {}", info.observed_addr);
            }
            _ => {}
        }
    }
}

async fn run_client(relay_addr: Multiaddr) -> anyhow::Result<()> {
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| ClientBehaviour {
            relay_client,
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "relay-min2/1".to_string(),
                key.public(),
            )),
        })?
        .build();

    // Direct dial first (official pattern: identify exchange both ways).
    swarm.dial(relay_addr.clone())?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut reserved = false;
    loop {
        tokio::select! {
            ev = swarm.select_next_some() => {
                match &ev {
                    libp2p::swarm::SwarmEvent::Behaviour(
                        ClientBehaviourEvent::Identify(identify::Event::Received { .. })) if !reserved => {
                        println!("client: identify exchange done, requesting reservation");
                        swarm.listen_on(relay_addr.clone().with(Protocol::P2pCircuit))?;
                        reserved = true;
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(
                        ClientBehaviourEvent::RelayClient(
                            relay::client::Event::ReservationReqAccepted { .. })) => {
                        println!("SUCCESS: reservation accepted");
                        return Ok(());
                    }
                    other => println!("client: {other:?}"),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                println!("TIMEOUT: no reservation within 30s");
                return Ok(());
            }
        }
    }
}
