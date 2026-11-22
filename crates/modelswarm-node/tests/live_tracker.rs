//! Live-network probe (ignored by default; run with -- --ignored):
//! verifies the BUILT CLIENT's HTTPS path against the production tracker:
//! health, verified catalog fetch, and active-profile parsing.

use modelswarm_identity::InstallationIdentity;
use modelswarm_tracker_api::TrackerClient;
use std::sync::Arc;

#[tokio::test]
#[ignore = "hits production modelswarm.deepflux.space"]
async fn production_catalog_verifies_over_https() {
    let identity = Arc::new(InstallationIdentity::from_bytes(&[7u8; 32]));
    let tracker = TrackerClient::new("https://modelswarm.deepflux.space", identity);
    let health = tracker.health().await.expect("health over https");
    assert_eq!(health["status"], "ok");

    let catalog = modelswarm_node::catalog::active_profiles(&tracker)
        .await
        .expect("verified catalog");
    assert!(!catalog.is_empty(), "at least one active profile");
    for p in &catalog {
        println!("{} -> {}", p.display_name, p.profile_id);
    }
}

// Wire-compatibility harness (the structural fix for the TS<->Rust bug
// class; two such bugs shipped and were only found live 2026-10-07:
// query-string path signing + null-body GET digest). Env-gated against
// PRODUCTION with a throwaway identity, it exercises EVERY signed route
// the desktop uses, in order: enroll -> register -> heartbeat -> lookup.
// Any envelope/schema drift between the Rust client and the TS tracker
// fails here first, not in users' logs.

use modelswarm_node::load_or_create_identity;
use modelswarm_telemetry::Telemetry;

#[tokio::test]
#[ignore = "hits production modelswarm.deepflux.space (MSP_LIVE=1 to opt in)"]
async fn signed_flow_enroll_register_heartbeat_lookup() {
    if std::env::var("MSP_LIVE").as_deref() != Ok("1") {
        eprintln!("set MSP_LIVE=1 to run the production wire harness");
        return;
    }
    let base =
        std::env::var("MSP_TRACKER").unwrap_or_else(|_| "https://modelswarm.deepflux.space".into());
    let dir = std::env::temp_dir().join("msp-wire-harness");
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    let sink = modelswarm_telemetry::FileSink::open(&logs.join("harness.jsonl")).unwrap();
    let telemetry = Telemetry::with_sink(Box::new(sink));
    let identity = load_or_create_identity(&dir, &telemetry).unwrap();
    let tracker = TrackerClient::new(base, std::sync::Arc::new(identity.clone()));

    // 1) Enroll (production auto-approves under the device cap).
    let start = tracker.device_start().await.expect("device_start");
    let code = start["deviceCode"]
        .as_str()
        .expect("deviceCode")
        .to_string();
    let mut token = None;
    for _ in 0..15 {
        if let Ok(done) = tracker.device_complete(&code).await {
            token = done["token"].as_str().map(str::to_string);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    tracker.set_session(token.expect("auto-approval grants the session"));
    println!("enrolled: session granted");

    // 2) Register a peer entry (placeholder address, one real profile).
    let profile = std::env::var("MSP_LIVE_PROFILE").unwrap_or_else(|_| {
        "msp1:fc5a30ae36257718afbd1062f2920b47576eed72ee8d172eac35248034b2dcbe".into()
    });
    let peer_id = identity.peer_id(); // valid ADR-020 multihash derivation
    let runtime = serde_json::json!({
        "name": "llama.cpp",
        "build": "353c4aab423bff5cb6dc0e1d32e41a447990ab3d69a411b7f58ff48187c91a03",
    });
    let reg = tracker
        .register(
            &peer_id,
            &["/ip4/0.0.0.0/tcp/0".to_string()],
            std::slice::from_ref(&profile),
            1,
            runtime,
        )
        .await
        .expect("register (signed POST with session)");
    println!("registered: {}", reg);

    // 3) Heartbeat the lease.
    let lease_id = reg["leaseId"]
        .as_str()
        .expect("leaseId in register response")
        .to_string();
    let hb = tracker
        .heartbeat(&lease_id, std::slice::from_ref(&profile), 1, 0, false)
        .await
        .expect("heartbeat (signed POST)");
    println!("heartbeat ok: lease expires {}", hb.lease_expires_at);

    // 3b) ADR-038 §3.3 + §6.2(7) wire-compat lockstep, heartbeat-field
    //     half: every successful heartbeat also mints one relay admission
    //     ticket server-side (the TS route mints from the AUTHENTICATED
    //     identity + the registered lease row, never client input). Here
    //     the Rust client parses the SAME bytes with the frozen
    //     `from_wire`, verifies the Ed25519 signature against the SAME
    //     pinned hub key the §5 lease check uses, and asserts the ADR-020
    //     binding pair equals the harness identity exactly as the relay's
    //     §3.4 checks 7-8 would bind it — the cross-language surface where
    //     a TS/Rust derivation drift would otherwise ship invisibly. The
    //     additive deploy-order tolerance (OLD tracker, field absent;
    //     tracker deploys first) is pinned tracker-api-side by
    //     `heartbeat_response_relay_ticket_deploy_skew_tolerance`; against
    //     THIS tracker the field must be present — an empty string here
    //     means the deployed tracker predates ticket minting or the wire
    //     name drifted, and either is exactly the bug class this harness
    //     exists to catch.
    #[cfg(feature = "libp2p-backend")]
    {
        use modelswarm_eligibility::relay_ticket::RelayAdmissionTicket;
        assert!(
            !hb.relay_ticket.is_empty(),
            "heartbeat response must carry relayTicket (ADR-038 §3.3)"
        );
        let (ticket, signature) = RelayAdmissionTicket::from_wire(&hb.relay_ticket)
            .expect("the TS-minted relayTicket parses under the frozen Rust from_wire (canonical bytes, exact field set, 600 s TTL)");
        let ticket_hub_hex = std::env::var("MSP_HUB_PUBLIC_KEY_HEX").unwrap_or_else(|_| {
            include_str!("../../../protocol/keys/hub-public.hex")
                .trim()
                .to_string()
        });
        let ticket_hub_bytes: [u8; 32] = hex::decode(&ticket_hub_hex)
            .expect("hub key hex parses")
            .try_into()
            .expect("32-byte hub key");
        let ticket_hub =
            ed25519_dalek::VerifyingKey::from_bytes(&ticket_hub_bytes).expect("hub verifying key");
        ticket
            .verify(&signature, &ticket_hub, time::OffsetDateTime::now_utc())
            .expect(
                "the TS-minted ticket verifies against the pinned hub key (ADR-038 §3.4 check 5)",
            );
        assert_eq!(
            ticket.peer_id, peer_id,
            "the ticket binds the registered peer row (ADR-038 §3.4 check 7)"
        );
        assert_eq!(
            ticket.installation_id,
            identity.installation_id(),
            "the ticket's installation_id re-derives from the authenticated identity (ADR-038 §3.4 check 8 / ADR-020)"
        );
        println!(
            "heartbeat relayTicket: TS-minted, Rust-verified, identity-bound (ADR-038 §6.2(7))"
        );
    }

    // 4) Roster lookup — the call that exposed BOTH wire bugs (signed GET
    //    with query string + empty-body digest).
    let peers = tracker
        .lookup(&profile, 10)
        .await
        .expect("lookup (signed GET)");
    assert!(!peers.is_empty(), "our harness peer must be on the roster");
    let found = peers.iter().any(|p| p.peer_id == peer_id);
    assert!(found, "harness peer visible via lookup");

    // 5) Earn a consume lease the honest way and verify the issued token
    //    through the REAL serving gate — the exact chain whose
    //    2026-10-08 breakage (issuance response shape + missing
    //    lease_expires_at) shipped invisibly through both green suites.
    //    Timings are synthesized here: the tracker cannot observe the
    //    requesting peer's engine; the desktop reports real ones.
    #[cfg(feature = "libp2p-backend")]
    {
        let ch = tracker
            .challenge_start(&lease_id, &profile)
            .await
            .expect("challenge_start (signed POST)");
        let challenge_id = ch["challengeId"].as_str().expect("challengeId").to_string();
        tracker
            .challenge_complete(&lease_id, &profile, &challenge_id, 1_200, 1_500)
            .await
            .expect("challenge_complete (signed POST)");
        let issued = tracker
            .request_lease(&lease_id, &profile)
            .await
            .expect("request_lease parses the TS issuance response (token field)");
        let hub_hex = std::env::var("MSP_HUB_PUBLIC_KEY_HEX").unwrap_or_else(|_| {
            include_str!("../../../protocol/keys/hub-public.hex")
                .trim()
                .to_string()
        });
        let policy =
            modelswarm_node::serving::LeasePolicy::from_hex(&hub_hex).expect("hub key hex parses");
        policy
            .check(&issued.lease, &profile, &peer_id)
            .expect("TS-issued lease passes the Rust ADR-026 serving gate");
        println!("lease earned + verified through the production gate");
    }

    // 6) Drain the lease so the census is not polluted.
    let _ = tracker.drain(&lease_id).await;
    println!("wire harness: enroll/register/heartbeat/lookup/lease-earn/drain ALL verified");
}
