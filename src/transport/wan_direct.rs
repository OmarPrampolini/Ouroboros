//! Direct WAN transport: UPnP → NAT-PMP → PCP
//!
//! Extracted from original wan.rs for dual-mode architecture.
//! PCP (RFC 6887) implementation for modern NATs.

use rand::{Rng, RngCore};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use thiserror::Error;
use tokio::net::UdpSocket;

// PCP Constants
const PCP_PORT: u16 = 5351;
const PCP_VERSION: u8 = 2;
const PCP_OPCODE_MAP: u8 = 1;
const PCP_PROTOCOL_UDP: u8 = 17;
const PCP_MULTICAST_IPV4: &str = "224.0.0.1";
const PCP_DEFAULT_TIMEOUT_MS: u64 = 2000;

#[derive(Debug, Error)]
pub enum WanDirectError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("task join failed: {0}")]
    Join(String),
    #[error("WAN mapping unsuccessful (UPnP/NAT-PMP/PCP)")]
    MappingUnsuccessful,
    #[error("no local ipv4")]
    NoLocalIpv4,
    #[error("natpmp read gateway failed: {0}")]
    NatPmpReadGateway(String),
    #[error("natpmp read mapping failed: {0}")]
    NatPmpReadMapping(String),
    #[error("PCP: response too short ({0} bytes < 60)")]
    PcpResponseTooShort(usize),
    #[error("PCP: version mismatch (got {got}, expected {expected})")]
    PcpVersionMismatch { got: u8, expected: u8 },
    #[error("PCP: unexpected opcode (got {got}, expected {expected})")]
    PcpUnexpectedOpcode { got: u8, expected: u8 },
    #[error("PCP: unsupported version")]
    PcpUnsupportedVersion,
    #[error("PCP: not authorized")]
    PcpNotAuthorized,
    #[error("PCP: malformed request")]
    PcpMalformedRequest,
    #[error("PCP: unsupported opcode")]
    PcpUnsupportedOpcode,
    #[error("PCP: unsupported option")]
    PcpUnsupportedOption,
    #[error("PCP: malformed option")]
    PcpMalformedOption,
    #[error("PCP: network failure")]
    PcpNetworkFailure,
    #[error("PCP: insufficient resources")]
    PcpInsufficientResources,
    #[error("PCP: unsupported protocol")]
    PcpUnsupportedProtocol,
    #[error("PCP: unknown result code {0}")]
    PcpUnknownResultCode(u8),
    #[error("PCP: receive timeout")]
    PcpReceiveTimeout,
    #[error("PCP: external IP is not IPv4-mapped IPv6")]
    PcpExternalIpNotV4Mapped,
    #[error("not 16 bytes")]
    Not16Bytes,
    #[error("not IPv4-mapped IPv6")]
    NotIpv4MappedIpv6,
    #[error("UPnP error: {0}")]
    Upnp(String),
    #[error("NAT-PMP error: {0}")]
    NatPmp(String),
    #[error("PCP error: {0}")]
    Pcp(String),
}

type Result<T> = std::result::Result<T, WanDirectError>;

/// Attempt direct WAN port forwarding: UPnP → NAT-PMP → PCP
pub async fn try_direct_port_forward(port: u16) -> Result<(UdpSocket, SocketAddr)> {
    // bind local
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;

    // 1) UPnP IGD
    if let Ok((ext_ip, ext_port)) = upnp_map(port).await {
        return Ok((sock, SocketAddr::new(ext_ip, ext_port)));
    }

    // 2) NAT-PMP
    if let Ok((ext_ip, ext_port)) = natpmp_map(port).await {
        return Ok((sock, SocketAddr::new(ext_ip, ext_port)));
    }

    // 3) PCP (RFC 6887)
    if let Ok((ext_ip, ext_port)) = pcp_map(port).await {
        return Ok((sock, SocketAddr::new(ext_ip, ext_port)));
    }

    Err(WanDirectError::MappingUnsuccessful)
}

/// UPnP IGD mapping
pub async fn upnp_map(port: u16) -> Result<(IpAddr, u16)> {
    let (ext_ip, ext_port) = tokio::task::spawn_blocking(move || -> Result<(IpAddr, u16)> {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdp};

        fn local_ipv4() -> Result<Ipv4Addr> {
            let s = StdUdp::bind("0.0.0.0:0")?;
            s.connect("8.8.8.8:80")?;
            match s.local_addr()? {
                SocketAddr::V4(v4) => Ok(*v4.ip()),
                _ => Err(WanDirectError::NoLocalIpv4),
            }
        }

        let gateway = igd::search_gateway(Default::default())
            .map_err(|e| WanDirectError::Upnp(format!("no IGD gateway: {}", e)))?;
        let ext_ip = gateway
            .get_external_ip()
            .map_err(|e| WanDirectError::Upnp(format!("get external ip failed: {}", e)))?;
        let local_ip = local_ipv4()?;
        let internal = SocketAddrV4::new(local_ip, port);

        // Random description to avoid fingerprinting
        let description = format!("hs-{}", rand::random::<u32>());

        // Random lease time between 1-24 hours (3600-86400 seconds)
        let lease_time: u32 = rand::thread_rng().gen_range(3600..=86400);
        tracing::debug!("UPnP: description={}, lease={}s", description, lease_time);

        gateway
            .add_port(
                igd::PortMappingProtocol::UDP,
                port,              // external
                internal,          // internal SocketAddrV4
                lease_time as u32, // random lease
                &description,      // random description
            )
            .map_err(|e| WanDirectError::Upnp(format!("UPnP add_port failed: {}", e)))?;

        Ok((IpAddr::V4(ext_ip), port))
    })
    .await
    .map_err(|e| WanDirectError::Join(e.to_string()))??;

    tracing::info!("UPnP mapping successful: {}:{}", ext_ip, ext_port);
    Ok((ext_ip, ext_port))
}

/// NAT-PMP mapping
pub async fn natpmp_map(port: u16) -> Result<(IpAddr, u16)> {
    use natpmp::{new_tokio_natpmp, Protocol, Response};

    let mut n = new_tokio_natpmp()
        .await
        .map_err(|e| WanDirectError::NatPmp(format!("natpmp init: {:?}", e)))?;

    // 1) chiedi IP pubblico
    n.send_public_address_request()
        .await
        .map_err(|e| WanDirectError::NatPmp(format!("natpmp public addr req: {:?}", e)))?;
    let public_ip = loop {
        match n.read_response_or_retry().await {
            Ok(Response::Gateway(gw)) => break *gw.public_address(),
            Ok(_) => continue,
            Err(e) => return Err(WanDirectError::NatPmpReadGateway(format!("{:?}", e))),
        }
    };

    // 2) chiedi mapping UDP
    n.send_port_mapping_request(Protocol::UDP, port, port, 3600)
        .await
        .map_err(|e| WanDirectError::NatPmp(format!("natpmp mapping req: {:?}", e)))?;

    let mapped_port = loop {
        match n.read_response_or_retry().await {
            Ok(Response::UDP(m)) => break m.public_port(),
            Ok(_) => continue,
            Err(e) => return Err(WanDirectError::NatPmpReadMapping(format!("{:?}", e))),
        }
    };

    Ok((IpAddr::V4(public_ip), mapped_port))
}

/// PCP (RFC 6887) mapping - replaces stub
pub async fn pcp_map(port: u16) -> Result<(IpAddr, u16)> {
    // Create PCP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Enable multicast for gateway discovery
    socket
        .set_broadcast(true)
        .map_err(|e| WanDirectError::Pcp(format!("set broadcast failed: {}", e)))?;

    // Build PCP MAP request
    let mut request = Vec::with_capacity(60);

    // Request header (36 bytes)
    request.push(PCP_VERSION);
    request.push(PCP_OPCODE_MAP);
    request.extend_from_slice(&[0u8; 2]); // Reserved

    // Random lease time between 1-24 hours (3600-86400 seconds)
    let lease_time: u32 = rand::thread_rng().gen_range(3600..=86400);
    tracing::debug!("PCP: lease_time={}s", lease_time);
    request.extend_from_slice(&lease_time.to_be_bytes()); // Random lifetime

    // Client IP (16 bytes, IPv4-mapped IPv6)
    request.extend_from_slice(&ipv4_mapped_ipv6_bytes(local_ipv4()?));

    // MAP request data (24 bytes)
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    request.extend_from_slice(&nonce); // Mapping nonce

    request.push(PCP_PROTOCOL_UDP); // Protocol
    request.extend_from_slice(&[0u8; 3]); // Reserved

    request.extend_from_slice(&port.to_be_bytes()); // Internal port
    request.extend_from_slice(&0u16.to_be_bytes()); // External port (0 = any)
    request.extend_from_slice(&[0u8; 16]); // External IP (0 = any)

    // Send to multicast address
    let pcp_server = SocketAddr::from((PCP_MULTICAST_IPV4.parse::<Ipv4Addr>()?, PCP_PORT));
    socket
        .send_to(&request, pcp_server)
        .await
        .map_err(|e| WanDirectError::Pcp(format!("send request failed: {}", e)))?;

    // Receive response with timeout
    let mut buf = [0u8; 60];
    let (len, from) = tokio::time::timeout(
        std::time::Duration::from_millis(PCP_DEFAULT_TIMEOUT_MS),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| WanDirectError::PcpReceiveTimeout)?
    .map_err(|e| WanDirectError::Pcp(format!("receive error: {}", e)))?;

    if len < 60 {
        return Err(WanDirectError::PcpResponseTooShort(len));
    }

    // Parse PCP response
    let version = buf[0];
    let opcode = buf[1] & 0x7F; // Remove R bit
    let result_code = buf[3];

    if version != PCP_VERSION {
        return Err(WanDirectError::PcpVersionMismatch {
            got: version,
            expected: PCP_VERSION,
        });
    }

    if opcode != PCP_OPCODE_MAP {
        return Err(WanDirectError::PcpUnexpectedOpcode {
            got: opcode,
            expected: PCP_OPCODE_MAP,
        });
    }

    if result_code != 0 {
        match result_code {
            1 => return Err(WanDirectError::PcpUnsupportedVersion),
            2 => return Err(WanDirectError::PcpNotAuthorized),
            3 => return Err(WanDirectError::PcpMalformedRequest),
            4 => return Err(WanDirectError::PcpUnsupportedOpcode),
            5 => return Err(WanDirectError::PcpUnsupportedOption),
            6 => return Err(WanDirectError::PcpMalformedOption),
            7 => return Err(WanDirectError::PcpNetworkFailure),
            8 => return Err(WanDirectError::PcpInsufficientResources),
            9 => return Err(WanDirectError::PcpUnsupportedProtocol),
            _ => return Err(WanDirectError::PcpUnknownResultCode(result_code)),
        }
    }

    // Extract external IP and port from response
    let external_port = u16::from_be_bytes([buf[42], buf[43]]);
    let external_ip = ipv4_from_mapped_ipv6(&buf[44..60])
        .map_err(|_| WanDirectError::PcpExternalIpNotV4Mapped)?;

    tracing::info!(
        "PCP mapping successful: {}:{}, from gateway {}",
        external_ip,
        external_port,
        from
    );
    Ok((IpAddr::V4(external_ip), external_port))
}

/// Helper: get local IPv4 address
fn local_ipv4() -> Result<Ipv4Addr> {
    use std::net::UdpSocket as StdUdp;

    let s = StdUdp::bind("0.0.0.0:0")?;
    s.connect("8.8.8.8:80")?;
    match s.local_addr()? {
        std::net::SocketAddr::V4(v4) => Ok(*v4.ip()),
        _ => Err(WanDirectError::NoLocalIpv4),
    }
}

/// Helper: convert IPv4 to IPv4-mapped IPv6 bytes
fn ipv4_mapped_ipv6_bytes(ipv4: Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[10] = 0xFF;
    bytes[11] = 0xFF;
    bytes[12..].copy_from_slice(&ipv4.octets());
    bytes
}

/// Helper: extract IPv4 from IPv4-mapped IPv6
fn ipv4_from_mapped_ipv6(bytes: &[u8]) -> Result<Ipv4Addr> {
    if bytes.len() != 16 {
        return Err(WanDirectError::Not16Bytes);
    }
    // Check it's IPv4-mapped: ::ffff:xxxx:xxxx
    if bytes[0..10] != [0u8; 10] || bytes[10..12] != [0xFF, 0xFF] {
        return Err(WanDirectError::NotIpv4MappedIpv6);
    }
    Ok(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

/// Inizializza WAN direct con NAT detection per strategia adattiva
pub async fn init_wan_direct(
    port: u16,
    cfg: &crate::config::Config,
) -> Result<(UdpSocket, SocketAddr)> {
    use crate::transport::nat_detection::{NatDetector, NatType};

    // Rileva tipo di NAT (cached, non blocca se fallisce)
    let detector = NatDetector::new(cfg.nat_detection_servers.clone());
    let nat_type = match detector.detect_nat_type().await {
        Ok(nt) => {
            tracing::info!("Detected NAT type: {}", nt);
            nt
        }
        Err(e) => {
            tracing::warn!("NAT detection failed: {}, using Unknown (conservative)", e);
            NatType::Unknown
        }
    };

    match nat_type {
        NatType::Symmetric => {
            tracing::info!("Symmetric NAT detected: prioritizing UPnP/PMP for port mapping");
        }
        NatType::FullCone => {
            tracing::info!("FullCone NAT: hole punching should work directly");
        }
        NatType::OpenInternet => {
            tracing::info!("Open internet: no NAT, direct connection possible");
        }
        _ => {
            tracing::debug!("NAT type: {}, using standard strategy", nat_type);
        }
    }

    // Usa strategia standard (UPnP → NAT-PMP → PCP)
    // Il codice chiamante può usare nat_type per decidere di saltare direttamente a Tor/Relay
    try_direct_port_forward(port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_mapped_conversion() {
        let ipv4 = Ipv4Addr::new(192, 168, 1, 100);
        let mapped = ipv4_mapped_ipv6_bytes(ipv4);
        let back = ipv4_from_mapped_ipv6(&mapped).unwrap();
        assert_eq!(ipv4, back);
    }

    #[test]
    fn test_ipv4_mapped_not_ipv6() {
        let not_mapped = [0u8; 16];
        assert!(ipv4_from_mapped_ipv6(&not_mapped).is_err());
    }
}
