//! Minimal libp2p relay v2 reproduction, independent of the OnlyHumans node.
//! cargo run -p onlyhumans_core --example relay_min
//!
//! relay swarm (server Enable, fixed port) + client swarm (listen_on circuit).
//! Expected: client prints `ReservationReqAccepted`.

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
    // ---- relay ----
    let relay_key = identity::Keypair::generate_ed25519();
    let relay_id = PeerId::from(relay_key.public());
    let mut relay = SwarmBuilder::with_existing_identity(relay_key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| RelayBehaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), Default::default()),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "relay-min/1".to_string(),
                key.public(),
            )),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
        .build();
    relay.listen_on(Multiaddr::empty()
        .with(Protocol::from("127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()))
        .with(Protocol::Tcp(0)))?;

    let mut relay_addr = None;
    loop {
        if let libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } =
            relay.select_next_some().await
        {
            relay_addr = Some(address);
            break;
        }
    }
    let relay_addr = relay_addr.unwrap();
    println!("relay listening on {relay_addr} (peer {relay_id})");

    // ---- client ----
    let client_key = identity::Keypair::generate_ed25519();
    let mut client = SwarmBuilder::with_existing_identity(client_key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| ClientBehaviour {
            relay_client,
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "relay-min/1".to_string(),
                key.public(),
            )),
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
        .build();

    // Official pattern: dial the relay directly first so both sides learn
    // addresses via the identify exchange.
    client.dial(
        relay_addr
            .clone()
            .with(Protocol::P2p(relay_id)),
    )?;
    // Wait for the identify exchange before reserving.
    let deadline0 = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        tokio::select! {
            ev = client.select_next_some() => {
                if let libp2p::swarm::SwarmEvent::Behaviour(
                    ClientBehaviourEvent::Identify(identify::Event::Received { .. })) = &ev
                {
                    println!("client: identify exchange done");
                    break;
                }
            }
            _ = tokio::time::sleep_until(deadline0) => break,
        }
    }
    // Relay side: record observed addresses as external (enables HOP).
    let deadline1 = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        tokio::select! {
            ev = relay.select_next_some() => {
                if let libp2p::swarm::SwarmEvent::Behaviour(
                    RelayBehaviourEvent::Identify(identify::Event::Received { info, .. })) = &ev
                {
                    relay.add_external_address(info.observed_addr.clone());
                    println!("relay: learned external address {}", info.observed_addr);
                }
            }
            _ = tokio::time::sleep_until(deadline1) => break,
        }
    }

    let circuit = relay_addr
        .clone()
        .with(Protocol::P2p(relay_id))
        .with(Protocol::P2pCircuit);
    println!("client listening on circuit {circuit}");
    client.listen_on(circuit)?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut client = client;
    let mut relay = relay;
    let mut done = false;
    while !done {
        tokio::select! {
            ev = client.select_next_some() => {
                match &ev {
                    libp2p::swarm::SwarmEvent::Behaviour(
                        ClientBehaviourEvent::RelayClient(
                            relay::client::Event::ReservationReqAccepted { .. })) => {
                        println!("SUCCESS: client ReservationReqAccepted: {ev:?}");
                        done = true;
                    }
                    other => println!("client: {other:?}"),
                }
            }
            ev = relay.select_next_some() => {
                println!("relay: {ev:?}");
            }
            _ = tokio::time::sleep_until(deadline) => {
                println!("TIMEOUT: no reservation accepted within 20s");
                done = true;
            }
        }
    }
    Ok(())
}
