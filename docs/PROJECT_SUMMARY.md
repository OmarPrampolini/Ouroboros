# PROJECT SUMMARY — Ouroboros

> Comunicazione P2P deterministica, cifrata e serverless.

---

## 1. Cos'è e Perché Esiste

**Ouroboros** è una piattaforma di comunicazione privata che elimina la dipendenza da discovery centralizzata o backend cloud.

Due prodotti complementari in una sola architettura:

| Prodotto | Quando usarlo |
|---|---|
| **Handshake** | Sessioni live 1:1 — pairing immediato via passphrase o QR, ottimizzato per connessione rapida con fallback NAT aggressivi |
| **EtherSync** | Presenza intermittente — spazio gossip cifrato condiviso, messaggistica asincrona, file transfer chunked |

Principio fondante: **stessa passphrase = stesso spazio logico**, deterministicamente, senza coordinamento esterno.

---

## 2. Struttura del Repository

```
Ouroboros/
├── src/                        # Daemon principale (binary: handshacke)
│   ├── main.rs                 # Entry point CLI (clap 4)
│   ├── lib.rs                  # Public API surface
│   ├── api/                    # REST server Axum 0.7 (~25 endpoint /v1/)
│   │   ├── auth.rs             # Bearer token middleware
│   │   ├── connect.rs          # /v1/connect
│   │   ├── ethersync.rs        # /v1/ethersync/*
│   │   ├── phrase.rs           # /v1/phrase/*
│   │   ├── diagnostics.rs      # /v1/metrics, /v1/capabilities
│   │   └── ...
│   ├── transport/              # Orchestrazione multi-trasporto
│   │   ├── mod.rs              # ICE candidate racing coordinator
│   │   ├── lan.rs              # LAN discovery (UDP broadcast/mDNS)
│   │   ├── wan_direct.rs       # UPnP + NAT-PMP + STUN
│   │   ├── wan_assist.rs       # Relay server (blind forward)
│   │   ├── wan_tor.rs          # SOCKS5 Tor client
│   │   ├── ice.rs              # Candidate racing
│   │   ├── stun.rs             # STUN protocol
│   │   ├── tcp_hole_punch.rs   # TCP hole punching
│   │   ├── icmp_hole_punch.rs  # ICMP hole punching
│   │   ├── dandelion.rs        # Anti-correlation delay
│   │   ├── multipath.rs        # Multi-path sequencing
│   │   ├── pluggable.rs        # DPI evasion transports
│   │   ├── quic_rfc9000.rs     # QUIC (feature: quic)
│   │   └── webrtc.rs           # WebRTC (feature: webrtc)
│   ├── crypto/                 # NonceSeq, domini, packet format
│   ├── derive.rs               # Passphrase → RendezvousParams
│   ├── session_noise.rs        # Noise XX handshake + resume
│   ├── offer.rs                # Offer payload + QR generation
│   ├── phrase.rs               # Tor-based phrase tunnel
│   ├── resume.rs               # Session resumption token
│   ├── state.rs                # AppState + ConnectionManager + circuit breaker
│   ├── discovery.rs            # Discovery abstraction
│   └── network_telemetry.rs    # NAT type + STUN metrics
├── ethersync/                  # Crate: spazio gossip P2P
│   └── src/
│       ├── node.rs             # EtherNode coordinator
│       ├── coordinate.rs       # Slot derivation (blake3 + HKDF)
│       ├── message.rs          # EtherMessage framing + cipher
│       ├── network.rs          # UDP networking
│       ├── gossip.rs           # Anti-entropy protocol
│       ├── storage.rs          # In-memory + SQLite (feature)
│       └── erasure_coding.rs   # Compressione + fragmentazione
├── ouroboros-crypto/           # Crate condiviso crittografia
│   └── src/
│       ├── aead.rs             # XChaCha20-Poly1305 wrapper
│       ├── derive.rs           # Argon2id + HKDF-SHA256
│       └── hash.rs             # Blake3
├── ui/                         # Desktop app Tauri v2
│   ├── src/                    # React 18 + TypeScript 5 frontend
│   └── src-tauri/              # Rust backend Tauri (command handlers)
├── docs/                       # Documentazione tecnica
├── tests/                      # Integration tests
├── fuzz/                       # Fuzzing targets (cargo-fuzz)
└── Cargo.toml                  # Workspace root
```

---

## 3. Stack Tecnologico

### Rust (core daemon + crates)

| Area | Crate / Tecnologia |
|---|---|
| Async runtime | `tokio 1.37` (multi-thread) |
| HTTP/REST API | `axum 0.7` + `hyper 1.0` |
| Noise Protocol | `snow` (Noise_XX_25519_ChaChaPoly_BLAKE2s) |
| AEAD | `chacha20poly1305` (XChaCha20-Poly1305) |
| KDF | `argon2` (Argon2id) + `hkdf` (HKDF-SHA256) |
| Hash | `blake3` |
| ECDH | `x25519-dalek 2.0` |
| Post-Quantum | `pqcrypto-kyber` (Kyber1024 hybrid, feature `pq`) |
| QUIC | `quinn 0.11` (feature `quic`) |
| WebRTC | `webrtc 0.14` (feature `webrtc`) |
| NAT traversal | `igdp` (UPnP) + `natpmp` + STUN custom |
| Tor | `tokio-socks` (SOCKS5 client) |
| Serialization | `serde` + `bincode` + `serde_json` |
| Memory safety | `zeroize 1.7` + `secrecy 0.8` + `subtle 2.5` |
| Error handling | `anyhow 1.0` + `thiserror 1.0` |
| CLI | `clap 4.0` |
| Testing | `proptest 1.4` (property-based) |

### Frontend (Tauri app)

| Area | Tecnologia |
|---|---|
| Framework | Tauri v2 |
| UI | React 18 + TypeScript 5.4 |
| Build | Vite 5.2 |
| QR | `qrcode 1.5` |
| Tauri bridge | `@tauri-apps/api v2` |

---

## 4. Feature Flags

```toml
[features]
default = ["quic"]                        # Build sicuro di default
full    = ["quic", "webrtc", "pq"]        # Tutte le capability
quic    = ["dep:quinn", "dep:rcgen"]      # QUIC RFC 9000
webrtc  = ["dep:webrtc", "dep:bytes"]     # WebRTC DataChannel
pq      = ["dep:pqcrypto-kyber", ...]     # Kyber1024 hybrid PQ
dht     = ["dep:libp2p"]                  # DHT discovery (roadmap)
```

---

## 5. Flussi Principali

### 5.1 Handshake Classico (sessione live P2P)

```
passphrase "cat123"
    │
    ▼  Argon2id(passphrase, salt) → HKDF-SHA256
    │
    ├─ port        (ephemeral, deterministic)
    ├─ key_enc     (32 byte)
    ├─ key_mac     (32 byte)
    └─ tag16/tag8  (identificazione rapida peer)

ICE Candidate Racing (parallelo/sequenziale):
    [T=0s]   LAN → UDP broadcast / mDNS
    [T=0.5s] WAN direct → UPnP + NAT-PMP + STUN
    [T=2s]   WAN assist relay → blind forwarding cifrato
    [T=4s+]  Tor → SOCKS5 + ephemeral onion
    → primo successo vince, motivo fallback loggato

Noise XX Handshake (su transport vincente):
    A ──[msg1: ephemeral pubkey]──→ B
    A ←──[msg2: ephemeral+static]── B
    A ──[msg3: static encrypted]──→ B
    → shared secret, forward secrecy per sessione

Tutto il traffico successivo: XChaCha20-Poly1305
```

### 5.2 EtherSync (spazio gossip asincrono)

```
passphrase "friends42"
    │
    ▼  blake3(passphrase) → space_hash
    ▼  unix_timestamp / 300 → slot_id   (slot da 5 minuti)
    ▼  HKDF(space_hash, slot_id) → entropy per slot

Publish messaggio:
    1. Cifra con space_hash (XChaCha20-Poly1305)
    2. Frame: [version|space_hash|slot|seq|ciphertext|auth_tag]
    3. UDP multicast ai peer noti

Gossip anti-entropy (ogni 30s):
    1. Build Bloom filter degli slot posseduti
    2. Invia digest ai peer
    3. Ricevi digest → identifica slot mancanti
    4. Request/response batch messaggi
    5. TTL decrement (default 3 hops)

Replay su join:
    - Lookback: 12 slot (1 ora)
    - Emit: space_replay_started → messaggi → space_replay_completed
```

### 5.3 Phrase Mode (Tor-only invite)

```
Alice: POST /v1/phrase/open
    → crea ephemeral onion service su Tor
    → restituisce onion_addr + ephemeral key

Alice genera QR con invite string
Bob scansiona → POST /v1/phrase/join (onion_addr)
    → connessione SOCKS5 → circuiti Tor → onion Alice
    → Noise XX upgrade sopra Tor
    → canale cifrato end-to-end (Tor + Noise)
```

### 5.4 Autenticazione API

```
Tauri backend:
    1. Genera token = hex(random_bytes(32))
    2. Spawna daemon con env HANDSHACKE_API_TOKEN=<token>
    3. Inietta token in tutte le chiamate REST

API server:
    Authorization: Bearer <token>
    → auth.rs middleware verifica contro env token
    → localhost-only (127.0.0.1:8731)
    → token mai scritto su disco (solo RAM)
```

---

## 6. API REST — Endpoint Principali

Porta default: `127.0.0.1:8731`
Auth: `Authorization: Bearer <token>`

### Connessione
| Metodo | Path | Descrizione |
|---|---|---|
| `POST` | `/v1/connect` | Avvia connessione (mode, passphrase, config) |
| `GET` | `/v1/status` | Stato connessione corrente |
| `POST` | `/v1/disconnect` | Termina connessione |
| `POST` | `/v1/offer` | Genera offer payload |
| `POST` | `/v1/qr/hybrid` | QR ibrido (resume + offer) |

### Messaggistica
| Metodo | Path | Descrizione |
|---|---|---|
| `POST` | `/v1/send` | Invia messaggio ai peer connessi |
| `GET` | `/v1/recv` | SSE stream ricezione messaggi |

### Phrase (Tor)
| Metodo | Path | Descrizione |
|---|---|---|
| `POST` | `/v1/phrase/open` | Apri phrase space (onion ephemero) |
| `POST` | `/v1/phrase/join` | Entra in phrase space esistente |
| `GET` | `/v1/phrase/status` | Status phrase |
| `POST` | `/v1/phrase/close` | Chiudi phrase space |

### EtherSync
| Metodo | Path | Descrizione |
|---|---|---|
| `POST` | `/v1/ethersync/start` | Avvia nodo EtherSync |
| `POST` | `/v1/ethersync/stop` | Ferma nodo |
| `POST` | `/v1/ethersync/spaces/join` | Entra in uno space (passphrase) |
| `POST` | `/v1/ethersync/spaces/publish` | Pubblica messaggio |
| `POST` | `/v1/ethersync/files/publish` | Pubblica file (chunked) |
| `GET` | `/v1/ethersync/events` | SSE stream eventi space |

### Diagnostica
| Metodo | Path | Descrizione |
|---|---|---|
| `GET` | `/v1/metrics` | Metriche performance |
| `GET` | `/v1/capabilities` | Feature matrix runtime |
| `GET` | `/v1/connect/fallbacks` | Ring buffer motivi fallback |
| `GET` | `/v1/network/nat-metrics` | NAT type + STUN scores |
| `GET` | `/v1/circuit` | Stato circuit breaker |
| `GET` | `/v1/pluggable/protocols` | Pluggable transports disponibili |

---

## 7. Crittografia

### Primitive

| Primitive | Uso | Crate |
|---|---|---|
| XChaCha20-Poly1305 | AEAD per tutti i dati (256-bit nonce) | `chacha20poly1305` |
| Argon2id | Password KDF (mem=8192KB, iter=3, par=1) | `argon2` |
| HKDF-SHA256 | Key expansion da master secret | `hkdf` |
| Blake3 | Space hash EtherSync, fingerprint | `blake3` |
| X25519 | ECDH key agreement | `x25519-dalek` |
| HMAC-SHA256 | Commitment QR offer | `hmac` |
| Noise XX | Session upgrade + forward secrecy | `snow` |
| Kyber1024 | PQ hybrid (opzionale, feature `pq`) | `pqcrypto-kyber` |

### Formato Pacchetto

```
[tag8: 1 byte] [ciphertext: N bytes] [auth_tag: 16 bytes]
```

### Nonce Domains (separazione per contesto)

| Domain | Byte | Uso |
|---|---|---|
| Noise | `0x01` | Session handshake |
| App | `0x02` | Messaggi applicativi |
| Assist | `0x03` | Relay assist |
| API | `0x04` | REST API |
| Resume | `0x05` | Token resume |

### Memory Safety
- `zeroize`: cancellazione sicura chiavi dopo uso
- `secrecy`: type-driven secrets (no debug/log accidentale)
- `subtle`: operazioni constant-time (anti timing attack)

---

## 8. Transport Layer — Cascade Fallback

```
connect(passphrase)
    │
    ├─ [1] LAN discovery    → UDP broadcast/mDNS
    │       ↓ fallback se nessuna risposta (timeout ~0.5s)
    ├─ [2] WAN direct       → UPnP + NAT-PMP + STUN hole punch
    │       ↓ fallback se NAT simmetrico o firewall
    ├─ [3] WAN assist relay  → relay1, relay2... (parallel)
    │       ↓ fallback se tutti relay irraggiungibili
    └─ [4] Tor              → SOCKS5 + ephemeral onion service
```

**NAT Detection** (`nat_detection.rs`): classifica Full Cone / Restricted / Port Restricted / Symmetric per decidere strategia ottimale.

**Dandelion** (`transport/dandelion.rs`): anti-correlation routing con delay randomizzato.
- `LowLatency`: 0–16 ms
- `HighSecurity`: 128–256 ms
- Override: `HANDSHACKE_DANDELION_MODE=HighSecurity`

**Pluggable Transports** (`transport/pluggable.rs`): DPI evasion.
- Stable: `None`, `HttpsLike`, `FtpData`, `DnsTunnel`
- Experimental: `RealTls`, `WebSocket`, `QUIC`

---

## 9. GUI Desktop (Tauri v2)

- **6 flow guidati Handshake**: classic, offer, hybrid, target, phrase, guaranteed
- **EtherSync Board**: messaggi + timeline eventi + file download
- **QR Scanner/Generator**: pairing visivo
- **Live Logging**: SSE stream log dal daemon per debugging
- **Lifecycle daemon**: start/stop/reconnect/reclaim porta

---

## 10. Configurazione

### Variabili d'Ambiente

```bash
HANDSHACKE_API_TOKEN=<hex32>          # Bearer token obbligatorio
HANDSHACKE_API_TOKEN_FILE=/path/file  # Alternativa file (perm 0600)
HANDSHACKE_DANDELION_MODE=HighSecurity|LowLatency
ASSIST_OBFUSCATION_V5=true
CI=1                                  # Strict mode in CI
```

### Config File (JSON)

```json
{
  "api_bind": "127.0.0.1:8731",
  "rendezvous_timeout_ms": 5000,
  "wan_connect_timeout_ms": 3000,
  "assist_relays": ["relay1.example.com:5555"],
  "assist_candidate_policy": "all",
  "discovery_enabled": true,
  "enable_compression": true
}
```

---

## 11. Testing & Qualità

| Tipo | Strumento | Copertura |
|---|---|---|
| Unit test | `cargo test` | Derive, crypto, protocol parser |
| Property-based | `proptest 1.4` | Invarianti crittografici (determinismo derive, ecc.) |
| Fuzzing | `cargo-fuzz` | Parser offer, frame, protocollo |
| Integration | `tests/` | Scenari multi-peer, NAT edge cases |
| Performance | `docs/performance.md` | Benchmark CI con budget nightly |
| WASM compat | `wasm32-unknown-unknown` | `ouroboros-crypto` compilabile per browser |

---

## 12. Stato del Progetto (Marzo 2026)

### Solido e Funzionante
- Derivazione deterministica da passphrase (V1 legacy SHA256, V2 Argon2id+HKDF)
- API locale autenticata con token in RAM
- Flussi QR operativi (Offer, Hybrid, Phrase)
- Cascata trasporti con fallback (LAN → WAN → relay → Tor)
- Noise XX handshake + resume token
- GUI Tauri con flow guidati e lifecycle daemon robusto
- EtherSync: publish messaggi e file chunked, replay backlog su join
- EtherSync Board UI con timeline eventi

### In Consolidamento
- **Multipath** (P0): sequencing robusto, ACK/SACK, reorder buffer, failover
- **Session layer refactor** (P1): riduzione complessità `session_noise.rs`
- **Validazione SOTA esterna** (P1): audit indipendente + benchmark pubblici comparativi
- **DHT discovery** (P2): peer discovery dinamica via libp2p

### Limiti Noti
- Persistenza storica distribuita dipende da nodi sempre accesi
- Se nessun peer mantiene i dati, lo storico non è recuperabile oltre lookback locale (1 ora)

---

## 13. Sicurezza

- **Threat model formale**: `docs/threat_model_visibility.md` — categorizza esposizione per layer (LAN/WAN/relay/Tor) e attore (ISP, governo, relay, Tor)
- **SECURITY.md**: coordinated disclosure policy con SLA (critical: 24h → 7gg fix)
- **Supply chain**: `Cargo.lock` + `deny.toml` + SBOM CycloneDX + cosign keyless signing
- **Circuit Breaker**: failure detection automatica con stato `Initial → Connecting → Connected → Failed`

---

## 14. Licenza

**MIT** — uso commerciale consentito.
Autori: Omar Prampolini (design), Bossman (implementazione).
