//! Measures, against the real iroh crate, the transport claims the spec relies on.
//! Everything binds to loopback with relays and address lookup disabled, so nothing
//! leaves this machine.
//!
//!   1. A connection from an endpoint not on the allowlist is closed before the
//!      application sees it, and the bytes it sent are never read.
//!   2. An allowed peer gets through, and the remote id seen by the application is
//!      the peer's real id.
//!   3. An unknown ALPN is refused.
//!   4. Impersonation: a client that knows the allowed peer's public id but not its
//!      secret key is seen under its own id, so it fails the allowlist.
//!   5. A wrong server key fails the client's dial (the id is what is authenticated).
//!   6. keylog stays off by default: SSLKEYLOGFILE set in the environment does not
//!      make iroh write TLS secrets.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{
    AfterHandshakeOutcome, Connection, EndpointHooks, VarInt, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use tokio::time::timeout;

const ALPN: &[u8] = b"apikeybin/xfer/1";
const OTHER_ALPN: &[u8] = b"something/else/1";

#[derive(Debug)]
struct Allowlist {
    allowed: HashSet<EndpointId>,
}

impl EndpointHooks for Allowlist {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if self.allowed.contains(&conn.remote_id()) {
            AfterHandshakeOutcome::accept()
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(403),
                reason: b"nope".to_vec(),
            }
        }
    }
}

async fn local_endpoint(sk: SecretKey, alpns: Vec<Vec<u8>>) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .secret_key(sk)
        .alpns(alpns)
        .bind()
        .await
        .expect("bind")
}

fn loopback_addr(ep: &Endpoint) -> EndpointAddr {
    let mut addr = EndpointAddr::new(ep.id());
    for s in ep.bound_sockets() {
        let mut s = s;
        if s.ip().is_unspecified() {
            s.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
        }
        if s.is_ipv4() {
            addr = addr.with_ip_addr(s);
        }
    }
    addr
}

#[tokio::main]
async fn main() {
    let dir = std::env::temp_dir().join(format!("iroh-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmp");
    let keylog = dir.join("keylog.txt");
    // SAFETY: single-threaded at this point in the probe; nothing else reads env yet.
    unsafe { std::env::set_var("SSLKEYLOGFILE", &keylog) };

    let sk_recv = SecretKey::generate();
    let sk_allowed = SecretKey::generate();
    let sk_stranger = SecretKey::generate();

    let mut allowed = HashSet::new();
    allowed.insert(sk_allowed.public());

    let receiver = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .secret_key(sk_recv.clone())
        .alpns(vec![ALPN.to_vec()])
        .hooks(Allowlist { allowed })
        .bind()
        .await
        .expect("bind receiver");
    let recv_addr = loopback_addr(&receiver);
    println!("receiver id {} sockets {:?}", receiver.id(), receiver.bound_sockets());

    let accepted: Arc<tokio::sync::Mutex<Vec<(EndpointId, Vec<u8>)>>> = Default::default();
    let rx_task = {
        let receiver = receiver.clone();
        let accepted = accepted.clone();
        tokio::spawn(async move {
            while let Some(incoming) = receiver.accept().await {
                let accepted = accepted.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let who = conn.remote_id();
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                        accepted.lock().await.push((who, Vec::new()));
                        return;
                    };
                    let data = recv.read_to_end(1024).await.unwrap_or_default();
                    let _ = send.write_all(b"ack").await;
                    let _ = send.finish();
                    accepted.lock().await.push((who, data));
                    conn.closed().await;
                });
            }
        })
    };

    // -- 1 + 4: strangers, including one claiming nothing but its own key.
    let stranger = local_endpoint(sk_stranger.clone(), vec![]).await;
    let c = timeout(Duration::from_secs(5), stranger.connect(recv_addr.clone(), ALPN)).await;
    let mut stranger_outcome = String::new();
    match c {
        Ok(Ok(conn)) => {
            // The handshake may complete from the client's view; the close follows.
            let r = async {
                let (mut s, _r) = conn.open_bi().await?;
                s.write_all(b"secret-offer-from-stranger").await?;
                s.finish()?;
                Ok::<_, Box<dyn std::error::Error>>(())
            }
            .await;
            let reason = timeout(Duration::from_secs(5), conn.closed()).await;
            stranger_outcome = format!("connected_then write={r:?} closed={reason:?}");
        }
        Ok(Err(e)) => stranger_outcome = format!("connect_err {e}"),
        Err(_) => stranger_outcome.push_str("connect_timeout"),
    }
    println!("[1] stranger: {stranger_outcome}");

    // -- 2: the allowed peer.
    let allowed_ep = local_endpoint(sk_allowed.clone(), vec![]).await;
    let conn = allowed_ep.connect(recv_addr.clone(), ALPN).await.expect("allowed connect");
    let (mut s, mut r) = conn.open_bi().await.expect("open_bi");
    s.write_all(b"hello-from-allowed").await.expect("write");
    s.finish().expect("finish");
    let reply = timeout(Duration::from_secs(5), r.read_to_end(16)).await.expect("timeout").expect("read");
    println!("[2] allowed peer reply: {:?}", String::from_utf8_lossy(&reply));
    println!("[2] client sees remote id == receiver id: {}", conn.remote_id() == receiver.id());
    conn.close(VarInt::from_u32(0), b"bye");

    // -- 3: unknown ALPN.
    let alpn_try = timeout(Duration::from_secs(5), allowed_ep.connect(recv_addr.clone(), OTHER_ALPN)).await;
    println!("[3] unknown ALPN: {}", match alpn_try {
        Ok(Ok(_)) => "CONNECTED (bad)".to_string(),
        Ok(Err(e)) => format!("refused: {e}"),
        Err(_) => "timeout".to_string(),
    });

    // -- 5: dial the right socket under the wrong identity.
    let wrong = SecretKey::generate().public();
    let mut bad_addr = EndpointAddr::new(wrong);
    for a in recv_addr.ip_addrs() {
        bad_addr = bad_addr.with_ip_addr(*a);
    }
    let wrong_try = timeout(Duration::from_secs(5), allowed_ep.connect(bad_addr, ALPN)).await;
    println!("[5] wrong server id at the right address: {}", match wrong_try {
        Ok(Ok(_)) => "CONNECTED (bad)".to_string(),
        Ok(Err(e)) => format!("refused: {e}"),
        Err(_) => "timeout (no connection)".to_string(),
    });

    tokio::time::sleep(Duration::from_millis(400)).await;

    let seen = accepted.lock().await.clone();
    let stranger_id = sk_stranger.public();
    let allowed_id = sk_allowed.public();
    let saw_stranger = seen.iter().any(|(id, _)| *id == stranger_id);
    let saw_allowed = seen.iter().find(|(id, _)| *id == allowed_id);
    let stranger_bytes_read = seen.iter().any(|(_, d)| d.windows(6).any(|w| w == b"secret"));
    println!("[1] application saw the stranger's connection: {saw_stranger}");
    println!("[1] application read the stranger's bytes: {stranger_bytes_read}");
    println!("[2] application saw allowed peer with data: {:?}",
        saw_allowed.map(|(_, d)| String::from_utf8_lossy(d).to_string()));

    // -- 6: keylog.
    let keylog_written = keylog.exists() && std::fs::metadata(&keylog).map(|m| m.len() > 0).unwrap_or(false);
    println!("[6] SSLKEYLOGFILE set, keylog written: {keylog_written}");

    let ok = !saw_stranger
        && !stranger_bytes_read
        && saw_allowed.is_some_and(|(_, d)| d == b"hello-from-allowed")
        && !keylog_written;
    println!("RESULT {}", if ok { "PASS" } else { "FAIL" });

    rx_task.abort();
    allowed_ep.close().await;
    stranger.close().await;
    receiver.close().await;
    let _ = std::fs::remove_dir_all(&dir);
    std::process::exit(if ok { 0 } else { 1 });
}
