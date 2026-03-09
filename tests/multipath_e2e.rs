use std::sync::Arc;

use handshacke::transport::{
    multipath::{MultipathConnection, PathMetadata, RoutingPolicy, SchedulerPolicy},
    Connection,
};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration};

const MAGIC: [u8; 4] = *b"MPTH";
const VERSION: u8 = 1;
const FLAG_DATA: u8 = 0x01;

fn build_frame(seq: u64, path_id: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(28 + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.push(path_id);
    out.push(0);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn multipath_redundant_deduplicates_payload() {
    let sender0 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sender1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recv0 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recv1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let mut tx = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
    tx.add_path(
        Connection::Wan(sender0.clone(), recv0.local_addr().unwrap()),
        PathMetadata::default(),
    );
    tx.add_path(
        Connection::Wan(sender1.clone(), recv1.local_addr().unwrap()),
        PathMetadata::default(),
    );

    let mut rx = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
    rx.add_path(
        Connection::Wan(recv0.clone(), sender0.local_addr().unwrap()),
        PathMetadata::default(),
    );
    rx.add_path(
        Connection::Wan(recv1.clone(), sender1.local_addr().unwrap()),
        PathMetadata::default(),
    );

    tx.send_multipath(b"hello-redundant", &RoutingPolicy::All)
        .await
        .unwrap();

    let mut buf = [0u8; 128];
    let (n, _) = rx.recv_multipath(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello-redundant");

    // Duplicate from second path should not be surfaced as a second app payload.
    let second = timeout(Duration::from_millis(250), rx.recv_multipath(&mut buf)).await;
    assert!(second.is_err());
}

#[tokio::test]
async fn multipath_reorders_out_of_order_frames() {
    let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recv0 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recv1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let mut rx = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
    rx.add_path(
        Connection::Wan(recv0.clone(), sender.local_addr().unwrap()),
        PathMetadata::default(),
    );
    rx.add_path(
        Connection::Wan(recv1.clone(), sender.local_addr().unwrap()),
        PathMetadata {
            active: false,
            ..PathMetadata::default()
        },
    );

    let p1 = build_frame(1, 0, FLAG_DATA, b"second");
    let p0 = build_frame(0, 0, FLAG_DATA, b"first");

    sender
        .send_to(&p1, recv0.local_addr().unwrap())
        .await
        .unwrap();
    sleep(Duration::from_millis(20)).await;
    sender
        .send_to(&p0, recv0.local_addr().unwrap())
        .await
        .unwrap();

    let mut buf = [0u8; 128];
    let (n1, _) = rx.recv_multipath(&mut buf).await.unwrap();
    assert_eq!(&buf[..n1], b"first");

    let (n2, _) = timeout(Duration::from_millis(250), rx.recv_multipath(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n2], b"second");
}

#[tokio::test]
async fn multipath_uses_backup_when_primary_inactive() {
    let sender0 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sender1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recv0 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recv1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let mut tx = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
    tx.add_path(
        Connection::Wan(sender0.clone(), recv0.local_addr().unwrap()),
        PathMetadata {
            active: false,
            ..PathMetadata::default()
        },
    );
    tx.add_path(
        Connection::Wan(sender1.clone(), recv1.local_addr().unwrap()),
        PathMetadata::default(),
    );

    let mut rx = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
    rx.add_path(
        Connection::Wan(recv0.clone(), sender0.local_addr().unwrap()),
        PathMetadata {
            active: false,
            ..PathMetadata::default()
        },
    );
    rx.add_path(
        Connection::Wan(recv1.clone(), sender1.local_addr().unwrap()),
        PathMetadata::default(),
    );

    tx.send_with_fallback(b"failover-path").await.unwrap();

    let mut buf = [0u8; 128];
    let (n, path_idx) = rx.recv_multipath(&mut buf).await.unwrap();
    assert_eq!(path_idx, 1);
    assert_eq!(&buf[..n], b"failover-path");
}
