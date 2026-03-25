//! ORP — Ouroboros Routing Protocol
//!
//! Implements a deterministic routing control plane layered on top of EtherSync slots.
//! Peers sharing a passphrase can exchange reachability hints (route announcements) and
//! respond to route lookups, enabling dynamic peer discovery without static bootstrap lists.
//!
//! ## Subspace assignments
//! - `0`: user/application payloads (existing EtherSync behavior)
//! - `1`: route announcements  (`SUBSPACE_ROUTE_ANNOUNCE`)
//! - `2`: route lookups        (`SUBSPACE_ROUTE_LOOKUP`)
//! - `3`: route offers         (`SUBSPACE_ROUTE_OFFER`)
//! - `4`: relay health beacons (`SUBSPACE_RELAY_BEACON`)
//! - `5`: circuit open         (`SUBSPACE_CIRCUIT_OPEN`)
//! - `6`: circuit extend       (`SUBSPACE_CIRCUIT_EXTEND`)
//! - `7`: circuit close        (`SUBSPACE_CIRCUIT_CLOSE`)
//! - `8`: cover traffic        (`SUBSPACE_COVER_TRAFFIC`)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::EtherSyncError;

// ---------------------------------------------------------------------------
// Subspace constants
// ---------------------------------------------------------------------------

/// User/application payloads — existing EtherSync channel (no change).
pub const SUBSPACE_USER: u64 = 0;
/// Route announcement channel.
pub const SUBSPACE_ROUTE_ANNOUNCE: u64 = 1;
/// Route lookup channel.
pub const SUBSPACE_ROUTE_LOOKUP: u64 = 2;
/// Route offer channel.
pub const SUBSPACE_ROUTE_OFFER: u64 = 3;
/// Relay health beacon channel.
pub const SUBSPACE_RELAY_BEACON: u64 = 4;
/// Circuit establishment channel for future ORP-HighRisk overlays.
pub const SUBSPACE_CIRCUIT_OPEN: u64 = 5;
/// Circuit extension channel for future ORP-HighRisk overlays.
pub const SUBSPACE_CIRCUIT_EXTEND: u64 = 6;
/// Circuit teardown channel for future ORP-HighRisk overlays.
pub const SUBSPACE_CIRCUIT_CLOSE: u64 = 7;
/// Cover traffic channel for future ORP-HighRisk overlays.
pub const SUBSPACE_COVER_TRAFFIC: u64 = 8;

/// Maximum number of announcements to keep per (space_hash, slot).
pub const MAX_ANNOUNCEMENTS_PER_SLOT: usize = 64;
/// Maximum number of cached offers per lookup_id.
pub const MAX_OFFERS_PER_LOOKUP: usize = 8;
/// How many slots back we accept announcements (beyond current slot).
pub const ANNOUNCE_SLOT_LOOKBACK: u64 = 2;

// ---------------------------------------------------------------------------
// Capability flags
// ---------------------------------------------------------------------------

/// Capabilities advertised by a peer in its route announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteCapabilities {
    /// Peer can forward traffic as a relay (wan_assist semantics).
    pub can_relay: bool,
    /// Peer is directly reachable over UDP.
    pub direct_udp: bool,
    /// Peer has WAN assist (STUN/relay infrastructure) available.
    pub wan_assist: bool,
    /// Peer supports Tor as a fallback transport.
    pub tor_capable: bool,
}

impl Default for RouteCapabilities {
    fn default() -> Self {
        Self {
            can_relay: false,
            direct_udp: true,
            wan_assist: false,
            tor_capable: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Route hop
// ---------------------------------------------------------------------------

/// A single routing hop candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteHop {
    /// Direct UDP/TCP reachability.
    Direct { addr: SocketAddr },
    /// One-hop relay via a known relay node.
    Relay {
        relay_addr: SocketAddr,
        /// Ephemeral tag used to address the target through the relay.
        target_tag: [u8; 8],
    },
    /// Route via Tor hidden service.
    Tor { onion_address: String },
}

// ---------------------------------------------------------------------------
// ORP frame types
// ---------------------------------------------------------------------------

/// Top-level ORP frame, serialized inside a normal `EtherMessage` ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrpFrame {
    Announce(RouteAnnouncement),
    Lookup(RouteLookup),
    Offer(RouteOffer),
    Forward(RouteForward),
    Ack(RouteAck),
    CircuitOpen(CircuitOpen),
    CircuitExtend(CircuitExtend),
    CircuitClose(CircuitClose),
    Cover(CoverPacket),
}

/// Periodic advertisement that a peer is online and reachable within a slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteAnnouncement {
    pub version: u8,
    /// Slot this announcement is valid for.
    pub slot: u64,
    /// Ephemeral node id for this slot (derived from slot + node identity).
    pub node_id: [u8; 16],
    pub capabilities: RouteCapabilities,
    /// Known direct UDP endpoints for this peer.
    pub reachable_udp: Vec<SocketAddr>,
    /// Short tag used to look up this peer in relay-assisted forwarding.
    pub assist_tag: [u8; 8],
    /// Slot after which this announcement should be discarded.
    pub expires_at_slot: u64,
}

/// Request to locate a peer by its assist_tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteLookup {
    pub version: u8,
    /// Unique id for this lookup request (used to correlate offers).
    pub lookup_id: [u8; 16],
    /// The assist_tag of the peer we are trying to reach.
    pub target_tag: [u8; 8],
    /// Maximum hops the requester is willing to traverse.
    pub max_hops: u8,
    /// Gossip TTL for this lookup frame.
    pub ttl: u8,
}

/// Response to a route lookup with a candidate next hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteOffer {
    pub version: u8,
    /// Matches the `lookup_id` in the corresponding `RouteLookup`.
    pub lookup_id: [u8; 16],
    /// Node id of the peer responding with this offer.
    pub responder_id: [u8; 16],
    pub next_hop: RouteHop,
    /// Relative quality score (higher = preferred). Range 0–65535.
    pub score: u16,
}

/// ORP-layer data plane packet for multi-hop forwarding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteForward {
    pub version: u8,
    pub circuit_id: [u8; 16],
    pub hop_index: u8,
    pub remaining_hops: u8,
    pub payload: Vec<u8>,
}

/// Delivery acknowledgment for a forwarded packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteAck {
    pub version: u8,
    pub circuit_id: [u8; 16],
    pub delivered_hop: u8,
}

/// Opens a high-risk overlay circuit with a first hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitOpen {
    pub version: u8,
    pub circuit_id: [u8; 16],
    pub origin_id: [u8; 16],
    pub first_hop: RouteHop,
    /// Encrypted handshake material for the first hop only.
    pub hop_payload: Vec<u8>,
    pub expires_at_slot: u64,
}

/// Extends an existing high-risk circuit to the next hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitExtend {
    pub version: u8,
    pub circuit_id: [u8; 16],
    pub current_hop: u8,
    pub next_hop: RouteHop,
    /// Onion-layer payload only the next hop can open.
    pub hop_payload: Vec<u8>,
    pub expires_at_slot: u64,
}

/// Closes a previously opened high-risk circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitClose {
    pub version: u8,
    pub circuit_id: [u8; 16],
    pub reason_code: u16,
}

/// Fixed-shape padding or cover packet for anti-correlation work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverPacket {
    pub version: u8,
    pub stream_id: [u8; 16],
    pub cover_class: u8,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Route cache
// ---------------------------------------------------------------------------

/// Cache key for announcements: (space_hash prefix, slot, node_id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    /// First 8 bytes of the space hash (sufficient for bucketing).
    pub space_prefix: [u8; 8],
    pub slot: u64,
    pub node_id: [u8; 16],
}

/// A cached route announcement with metadata.
#[derive(Debug)]
pub struct CachedAnnouncement {
    pub frame: RouteAnnouncement,
    pub last_seen: Instant,
    /// The peer address from which this announcement was received.
    pub source_peer: SocketAddr,
}

/// A cached route offer with metadata.
#[derive(Debug)]
pub struct CachedOffer {
    pub frame: RouteOffer,
    pub last_seen: Instant,
}

/// In-memory route cache for ORP control-plane state.
#[derive(Debug, Default)]
pub struct RouteCache {
    /// Announcements indexed by RouteKey.
    pub announcements: HashMap<RouteKey, CachedAnnouncement>,
    /// Offers indexed by lookup_id.
    pub offers: HashMap<[u8; 16], Vec<CachedOffer>>,
}

impl RouteCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or refresh a route announcement.
    ///
    /// Returns `false` if the announcement was rejected (expired slot, cache full).
    pub fn insert_announcement(
        &mut self,
        frame: RouteAnnouncement,
        source_peer: SocketAddr,
        current_slot: u64,
        space_hash: &[u8; 32],
    ) -> bool {
        // Reject announcements from slots that are too far in the past.
        if frame.slot + ANNOUNCE_SLOT_LOOKBACK < current_slot {
            return false;
        }
        // Reject already-expired announcements.
        if frame.expires_at_slot < current_slot {
            return false;
        }

        let mut space_prefix = [0u8; 8];
        space_prefix.copy_from_slice(&space_hash[..8]);

        let key = RouteKey {
            space_prefix,
            slot: frame.slot,
            node_id: frame.node_id,
        };

        // Enforce per-slot cap (count entries sharing the same slot bucket).
        let slot_count = self
            .announcements
            .keys()
            .filter(|k| k.space_prefix == space_prefix && k.slot == frame.slot)
            .count();

        if slot_count >= MAX_ANNOUNCEMENTS_PER_SLOT && !self.announcements.contains_key(&key) {
            return false;
        }

        self.announcements.insert(
            key,
            CachedAnnouncement {
                frame,
                last_seen: Instant::now(),
                source_peer,
            },
        );
        true
    }

    /// Insert a route offer, capping at `MAX_OFFERS_PER_LOOKUP` per lookup_id.
    pub fn insert_offer(&mut self, frame: RouteOffer) {
        let entry = self.offers.entry(frame.lookup_id).or_default();
        if entry.len() >= MAX_OFFERS_PER_LOOKUP {
            // Drop the lowest-scored offer to make room.
            if let Some(worst_idx) = entry
                .iter()
                .enumerate()
                .min_by_key(|(_, o)| o.frame.score)
                .map(|(i, _)| i)
            {
                if entry[worst_idx].frame.score < frame.score {
                    entry.remove(worst_idx);
                } else {
                    return; // New offer is worse than all cached; discard.
                }
            }
        }
        entry.push(CachedOffer {
            frame,
            last_seen: Instant::now(),
        });
    }

    /// Return all announcements for the given space prefix and slot range.
    pub fn announcements_for_slot(
        &self,
        space_prefix: &[u8; 8],
        slot: u64,
    ) -> Vec<&CachedAnnouncement> {
        self.announcements
            .iter()
            .filter(|(k, _)| k.space_prefix == *space_prefix && k.slot == slot)
            .map(|(_, v)| v)
            .collect()
    }

    /// Find a cached announcement whose `assist_tag` matches `target_tag`.
    ///
    /// Only considers the current slot and one slot back.
    pub fn find_by_tag(
        &self,
        space_prefix: &[u8; 8],
        target_tag: &[u8; 8],
        current_slot: u64,
    ) -> Option<&CachedAnnouncement> {
        let min_slot = current_slot.saturating_sub(ANNOUNCE_SLOT_LOOKBACK);
        self.announcements
            .iter()
            .filter(|(k, _)| k.space_prefix == *space_prefix && k.slot >= min_slot)
            .map(|(_, v)| v)
            .find(|a| &a.frame.assist_tag == target_tag)
    }

    /// Return the best scored offer for a lookup id (highest score wins).
    pub fn best_offer(&self, lookup_id: &[u8; 16]) -> Option<&CachedOffer> {
        self.offers
            .get(lookup_id)?
            .iter()
            .max_by_key(|o| o.frame.score)
    }

    /// Evict expired announcements and offers older than `max_age_secs`.
    pub fn evict_stale(&mut self, current_slot: u64, max_age_secs: u64) {
        let max_age = std::time::Duration::from_secs(max_age_secs);

        self.announcements.retain(|_, v| {
            v.frame.expires_at_slot >= current_slot && v.last_seen.elapsed() < max_age
        });

        self.offers.retain(|_, offers| {
            offers.retain(|o| o.last_seen.elapsed() < max_age);
            !offers.is_empty()
        });
    }
}

// ---------------------------------------------------------------------------
// Frame serialization helpers
// ---------------------------------------------------------------------------

/// Serialize an `OrpFrame` to bytes using bincode.
pub fn encode_orp_frame(frame: &OrpFrame) -> Result<Vec<u8>, EtherSyncError> {
    bincode::serialize(frame)
        .map_err(|e| EtherSyncError::NetworkError(format!("ORP frame encode failed: {e}")))
}

/// Deserialize an `OrpFrame` from bytes.
pub fn decode_orp_frame(bytes: &[u8]) -> Result<OrpFrame, EtherSyncError> {
    bincode::deserialize(bytes)
        .map_err(|e| EtherSyncError::NetworkError(format!("ORP frame decode failed: {e}")))
}

/// Score a `CachedOffer` based on freshness and hop quality.
///
/// Higher score = preferred route.
pub fn score_offer(offer: &CachedOffer, _current_slot: u64) -> u16 {
    let age_slots = (offer.last_seen.elapsed().as_secs() / 300).min(5);
    let freshness_penalty = (age_slots * 1000) as u16;

    let hop_bonus: u16 = match &offer.frame.next_hop {
        RouteHop::Direct { .. } => 5000,
        RouteHop::Relay { .. } => 2000,
        RouteHop::Tor { .. } => 500,
    };

    offer
        .frame
        .score
        .saturating_add(hop_bonus)
        .saturating_sub(freshness_penalty)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:4000".parse().unwrap()
    }

    fn make_announcement(slot: u64, node_id: [u8; 16], tag: [u8; 8]) -> RouteAnnouncement {
        RouteAnnouncement {
            version: 1,
            slot,
            node_id,
            capabilities: RouteCapabilities::default(),
            reachable_udp: vec![dummy_addr()],
            assist_tag: tag,
            expires_at_slot: slot + 4,
        }
    }

    fn space_hash() -> [u8; 32] {
        [0xABu8; 32]
    }

    fn space_prefix() -> [u8; 8] {
        [0xABu8; 8]
    }

    #[test]
    fn orp_frame_roundtrip_announce() {
        let ann = make_announcement(100, [1u8; 16], [2u8; 8]);
        let frame = OrpFrame::Announce(ann.clone());
        let bytes = encode_orp_frame(&frame).unwrap();
        let decoded = decode_orp_frame(&bytes).unwrap();
        match decoded {
            OrpFrame::Announce(decoded_ann) => {
                assert_eq!(decoded_ann.slot, ann.slot);
                assert_eq!(decoded_ann.node_id, ann.node_id);
                assert_eq!(decoded_ann.assist_tag, ann.assist_tag);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn orp_frame_roundtrip_lookup() {
        let lookup = RouteLookup {
            version: 1,
            lookup_id: [7u8; 16],
            target_tag: [9u8; 8],
            max_hops: 2,
            ttl: 3,
        };
        let frame = OrpFrame::Lookup(lookup.clone());
        let bytes = encode_orp_frame(&frame).unwrap();
        let decoded = decode_orp_frame(&bytes).unwrap();
        match decoded {
            OrpFrame::Lookup(l) => {
                assert_eq!(l.lookup_id, lookup.lookup_id);
                assert_eq!(l.target_tag, lookup.target_tag);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn route_cache_insert_and_find() {
        let mut cache = RouteCache::new();
        let ann = make_announcement(50, [3u8; 16], [5u8; 8]);
        let sh = space_hash();

        assert!(cache.insert_announcement(ann.clone(), dummy_addr(), 50, &sh));

        let prefix = space_prefix();
        let found = cache.find_by_tag(&prefix, &[5u8; 8], 50);
        assert!(found.is_some());
        assert_eq!(found.unwrap().frame.node_id, [3u8; 16]);
    }

    #[test]
    fn route_cache_rejects_expired_announcement() {
        let mut cache = RouteCache::new();
        let mut ann = make_announcement(10, [1u8; 16], [1u8; 8]);
        ann.expires_at_slot = 11; // expires at slot 11
        let sh = space_hash();

        // current_slot = 20, announcement expired at 11 → should be rejected
        assert!(!cache.insert_announcement(ann, dummy_addr(), 20, &sh));
    }

    #[test]
    fn route_cache_rejects_old_slot() {
        let mut cache = RouteCache::new();
        // Announcement from slot 5, current is 100 → too far back
        let ann = make_announcement(5, [2u8; 16], [2u8; 8]);
        let sh = space_hash();

        assert!(!cache.insert_announcement(ann, dummy_addr(), 100, &sh));
    }

    #[test]
    fn route_cache_best_offer_highest_score() {
        let mut cache = RouteCache::new();
        let lookup_id = [42u8; 16];

        for score in [100u16, 500, 200] {
            cache.insert_offer(RouteOffer {
                version: 1,
                lookup_id,
                responder_id: [0u8; 16],
                next_hop: RouteHop::Direct { addr: dummy_addr() },
                score,
            });
        }

        let best = cache.best_offer(&lookup_id).unwrap();
        assert_eq!(best.frame.score, 500);
    }

    #[test]
    fn route_cache_evicts_stale_entries() {
        let mut cache = RouteCache::new();
        let sh = space_hash();
        let ann = make_announcement(50, [4u8; 16], [6u8; 8]);
        cache.insert_announcement(ann, dummy_addr(), 50, &sh);

        // Evict with max_age = 0 seconds (everything is stale immediately)
        cache.evict_stale(50, 0);

        assert!(cache.announcements.is_empty());
    }

    #[test]
    fn announcements_for_slot_returns_correct_entries() {
        let mut cache = RouteCache::new();
        let sh = space_hash();
        let prefix = space_prefix();

        cache.insert_announcement(
            make_announcement(10, [1u8; 16], [1u8; 8]),
            dummy_addr(),
            10,
            &sh,
        );
        cache.insert_announcement(
            make_announcement(10, [2u8; 16], [2u8; 8]),
            dummy_addr(),
            10,
            &sh,
        );
        cache.insert_announcement(
            make_announcement(11, [3u8; 16], [3u8; 8]),
            dummy_addr(),
            11,
            &sh,
        );

        let slot10 = cache.announcements_for_slot(&prefix, 10);
        assert_eq!(slot10.len(), 2);

        let slot11 = cache.announcements_for_slot(&prefix, 11);
        assert_eq!(slot11.len(), 1);
    }

    #[test]
    fn subspace_constants_are_distinct() {
        let subs = [
            SUBSPACE_USER,
            SUBSPACE_ROUTE_ANNOUNCE,
            SUBSPACE_ROUTE_LOOKUP,
            SUBSPACE_ROUTE_OFFER,
            SUBSPACE_RELAY_BEACON,
            SUBSPACE_CIRCUIT_OPEN,
            SUBSPACE_CIRCUIT_EXTEND,
            SUBSPACE_CIRCUIT_CLOSE,
            SUBSPACE_COVER_TRAFFIC,
        ];
        for i in 0..subs.len() {
            for j in (i + 1)..subs.len() {
                assert_ne!(subs[i], subs[j], "subspace collision at ({}, {})", i, j);
            }
        }
    }

    #[test]
    fn no_cross_space_cache_leakage() {
        let mut cache = RouteCache::new();
        let space_a = [0xAAu8; 32];
        let tag = [5u8; 8];

        let ann = make_announcement(50, [1u8; 16], tag);
        cache.insert_announcement(ann, dummy_addr(), 50, &space_a);

        // Lookup with space_b prefix should find nothing
        let prefix_b = [0xBBu8; 8];
        assert!(cache.find_by_tag(&prefix_b, &tag, 50).is_none());

        // Lookup with space_a prefix should find it
        let prefix_a = [0xAAu8; 8];
        assert!(cache.find_by_tag(&prefix_a, &tag, 50).is_some());
    }

    #[test]
    fn orp_frame_roundtrip_offer() {
        let offer = RouteOffer {
            version: 1,
            lookup_id: [1u8; 16],
            responder_id: [2u8; 16],
            next_hop: RouteHop::Direct { addr: dummy_addr() },
            score: 5000,
        };
        let frame = OrpFrame::Offer(offer.clone());
        let bytes = encode_orp_frame(&frame).unwrap();
        let decoded = decode_orp_frame(&bytes).unwrap();
        match decoded {
            OrpFrame::Offer(o) => {
                assert_eq!(o.lookup_id, offer.lookup_id);
                assert_eq!(o.score, 5000);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn orp_frame_roundtrip_circuit_open() {
        let open = CircuitOpen {
            version: 1,
            circuit_id: [3u8; 16],
            origin_id: [4u8; 16],
            first_hop: RouteHop::Relay {
                relay_addr: dummy_addr(),
                target_tag: [9u8; 8],
            },
            hop_payload: vec![1, 2, 3, 4],
            expires_at_slot: 88,
        };
        let frame = OrpFrame::CircuitOpen(open.clone());
        let bytes = encode_orp_frame(&frame).unwrap();
        let decoded = decode_orp_frame(&bytes).unwrap();
        match decoded {
            OrpFrame::CircuitOpen(decoded_open) => {
                assert_eq!(decoded_open.circuit_id, open.circuit_id);
                assert_eq!(decoded_open.origin_id, open.origin_id);
                assert_eq!(decoded_open.expires_at_slot, open.expires_at_slot);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn orp_frame_roundtrip_cover_packet() {
        let cover = CoverPacket {
            version: 1,
            stream_id: [7u8; 16],
            cover_class: 2,
            payload: vec![0u8; 32],
        };
        let frame = OrpFrame::Cover(cover.clone());
        let bytes = encode_orp_frame(&frame).unwrap();
        let decoded = decode_orp_frame(&bytes).unwrap();
        match decoded {
            OrpFrame::Cover(decoded_cover) => {
                assert_eq!(decoded_cover.stream_id, cover.stream_id);
                assert_eq!(decoded_cover.cover_class, cover.cover_class);
                assert_eq!(decoded_cover.payload.len(), 32);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn lookup_produces_offer_via_cache() {
        let mut cache = RouteCache::new();
        let lookup_id = [0xCC; 16];

        // Simulate: a lookup targeting our tag produced an offer
        let offer = RouteOffer {
            version: 1,
            lookup_id,
            responder_id: [10u8; 16],
            next_hop: RouteHop::Direct { addr: dummy_addr() },
            score: 5000,
        };
        cache.insert_offer(offer);

        let best = cache.best_offer(&lookup_id);
        assert!(best.is_some());
        let best = best.unwrap();
        assert_eq!(best.frame.score, 5000);
        assert_eq!(best.frame.responder_id, [10u8; 16]);
        match &best.frame.next_hop {
            RouteHop::Direct { addr } => assert_eq!(*addr, dummy_addr()),
            _ => panic!("expected Direct hop"),
        }
    }
}
