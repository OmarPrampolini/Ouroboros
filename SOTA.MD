# SOTA.MD - Analisi Modulo-per-Modulo (Rete + Supporto)

## Executive Verdict

### Livello attuale
**Valutazione complessiva: pre-SOTA avanzato (SOTA-leaning architecture).**

Il progetto mostra una architettura di rete rara per ampiezza e integrazione:
- percorso multi-trasporto con fallback aggressivi;
- upgrade di sessione con Noise/resume;
- moduli anti-correlation (Assist V5 + Dandelion);
- attenzione a operabilita (CI, security workflow, perf workflow, fuzz workflow).

Non e ancora una dichiarazione SOTA pienamente difendibile per tre motivi principali:
1. alcune aree sono ancora parzialmente prototipali o non completamente "wired" nel runtime (soprattutto multipath);
2. mancano evidenze esterne di livello SOTA (audit indipendente e benchmark comparativi pubblici su reti ostili);
3. alcune scelte di coerenza/robustezza cross-modulo sono forti ma non ancora uniformi in tutto lo stack.

### Motivazione sintetica
- **Punti da top-tier engineering:** design del path selection, Assist V5, session layer, difese replay/rate/time, pipeline CI estesa.
- **Gap verso SOTA difendibile:** maturita runtime disomogenea, telemetria/KPI operativi incompleti, validazione esterna ancora assente.

## Aggiornamento Operativo (2026-03-06)

### Completato oggi (codice + verifica)
- **Dandelion differenziato**: `LowLatency` e `HighSecurity` con policy diverse (delay/batch) e override runtime via env con clamping bounds.
- **Capabilities matrix**: endpoint `/v1/capabilities` esteso con `dandelion_mode`, policy effettiva e flag runtime rilevanti.
- **NAT/STUN data-driven**:
  - telemetria runtime in memoria (`src/network_telemetry.rs`),
  - fallback reasons tracciati lungo connect/sync/transport,
  - bias runtime delle priorita strategy in `transport/mod.rs`.
- **STUN ranking dinamico**: score per server con success/fail, avg RTT, freshness (`last_used_ms`) e snapshot ordinato.
- **Diagnostica rete**:
  - `/v1/connect/fallbacks` (ring buffer motivi fallback),
  - `/v1/network/nat-metrics` (snapshot NAT + score STUN).
- **Qualita**: `cargo fmt`, `cargo clippy -- -D warnings`, `CI=1 cargo test --locked` verdi.

### Cosa manca (prossima ripartenza)
- **Multipath Tranche A (priorita massima)**: sequencing/header, ACK/SACK, reorder buffer, health monitor, fallback single-path robusto, test e2e loss/reorder/failover.
- **Session layer refactor** (`session_noise.rs`): riduzione complessita e separazione componenti senza regressioni.
- **Pluggable transports**: separazione chiara `stable` vs `experimental`.
- **Validazione esterna SOTA**: benchmark comparativi + audit indipendente.

### Nota di stato
Questo aggiornamento supera parte dei gap P1 originari (Dandelion differenziato, NAT/STUN data-driven e diagnostica fallback di base), che ora passano da "mancante" a "implementato, da consolidare con dati reali".


## Metodo e Rubrica

## Criteri (scala 0-5)
- **Affidabilita:** resilienza in condizioni reali (NAT complessi, timeout, fallback).
- **Sicurezza:** robustezza protocollare, anti-replay, anti-abuso, superfici di attacco.
- **Performance:** latenza, throughput, degrado sotto perdita/jitter.
- **Operabilita:** osservabilita, configurabilita, comportamento prevedibile in produzione.
- **Maturita test:** copertura, qualita dei test, aderenza a scenari realistici.

## Interpretazione punteggi
- `0-1`: concetto o prototipo fragile.
- `2`: base funzionante ma non pronta per ambienti ostili.
- `3`: buona maturita tecnica, con gap significativi.
- `4`: molto robusto, vicino a livello production hard.
- `5`: stato SOTA difendibile con evidenza esterna e risultati ripetibili.

## Baseline assunta
- CI/test/clippy considerati affidabili su GitHub (informazione fornita dal maintainer).
- Nessuna esecuzione benchmark o audit esterno in questa analisi.

## Analisi Modulo per Modulo

### 1) ICE e Candidate Racing (`src/transport/ice.rs`)
**Score:** 4.0/5

- **Stato attuale**
  Implementazione concreta con raccolta candidati, priorita, retry/backoff, timeout globali e validazione finale tramite handshake vero.
- **Perche e forte**
  Valida i path con `run_noise_upgrade`/`run_resume_or_noise` invece di affidarsi solo a probe di trasporto.
- **Limiti attuali**
  Esecuzione prevalentemente sequenziale per evitare contesa socket; buono per correttezza, ma puo limitare velocita in reti altamente variabili.
- **Potenziamenti consigliati**
  Introdurre un modello ibrido: parallelismo controllato (N candidati) con cancellazione rapida al primo successo validato.
- **KPI/criteri di successo**
  p95 tempo connessione, success rate per tipo NAT, tasso fallback relay/tor.
- **Priorita (P0/P1/P2)**
  **P0**

### 2) WAN Assist Core (`src/transport/wan_assist.rs`)
**Score:** 4.0/5

- **Stato attuale**
  Flusso relay-assisted completo: request/go, burst coordinato, timeout, fallback.
- **Perche e forte**
  Buona orchestrazione temporale e buon controllo di errore su canali assistiti.
- **Limiti attuali**
  Alcune parti di coordinazione simultanea richiedono riallineamento di semantica per evitare coupling ambiguo.
- **Potenziamenti consigliati**
  Separare in modo piu netto i campi di protocol version dalla logica temporale di sync.
- **KPI/criteri di successo**
  success rate assist in reti symmetric NAT, p95 tempo handoff relay->peer, retry efficaci.
- **Priorita (P0/P1/P2)**
  **P0**

### 3) WAN Assist V5 (IP-blinded) (`src/protocol_assist_v5.rs`)
**Score:** 4.3/5

- **Stato attuale**
  Schema ricco: fixed candidate shape, blind/unblind, nonce derivation, policy candidato, MAC coverage ampia.
- **Perche e forte**
  Ottimo equilibrio tra privacy del metadata-plane e verificabilita crittografica lato peer.
- **Limiti attuali**
  Richiede maggiore validazione esterna e prove comparative pubbliche per claim "state of the art" definitivi.
- **Potenziamenti consigliati**
  Test avversariali dedicati (traffic analysis simulation) e report pubblico ripetibile.
- **KPI/criteri di successo**
  leakage score in test synthetic, false accept/false reject candidate rates.
- **Priorita (P0/P1/P2)**
  **P1**

### 4) Dandelion + Assist Inbox (`src/transport/dandelion.rs`, `src/transport/assist_inbox.rs`)
**Score:** 2.8/5

- **Stato attuale**
  Presenza architetturale buona, integrazione attiva nell'inbox assist.
- **Perche e forte**
  Idea corretta per ridurre correlazione temporale lato relay.
- **Limiti attuali**
  Le modalita `LowLatency`/`HighSecurity` non modulano ancora in modo pienamente differenziato la strategia di batching.
- **Potenziamenti consigliati**
  Legare esplicitamente mode -> delay range, batch target size, policy di flush.
- **KPI/criteri di successo**
  batch entropy, delay distribution per mode, impatto su success rate assist.
- **Priorita (P0/P1/P2)**
  **P1**

### 5) WAN Direct (UPnP/NAT-PMP/PCP) (`src/transport/wan_direct.rs`)
**Score:** 3.5/5

- **Stato attuale**
  Fallback chain completa e moderna (incluso PCP), con gestione errori dettagliata.
- **Perche e forte**
  Copre piu ecosistemi gateway ed evita lock-in su un solo meccanismo.
- **Limiti attuali**
  Manca una telemetria robusta per decisioni adattive data-driven su mapping strategy.
- **Potenziamenti consigliati**
  Aggiungere metriche per successo/fallimento per metodo e per classe NAT.
- **KPI/criteri di successo**
  successo mapping per metodo, tempo medio mapping, churn mapping.
- **Priorita (P0/P1/P2)**
  **P1**

### 6) STUN Discovery + Hole Punch (`src/transport/stun.rs`)
**Score:** 3.4/5

- **Stato attuale**
  Implementazione operativa con parsing XOR-MAPPED-ADDRESS e supporto IPv4/IPv6.
- **Perche e forte**
  Buona base RFC-oriented e integrazione con NAT classification.
- **Limiti attuali**
  Heuristics conservative; servono test piu duri su scenari enterprise/restricted.
- **Potenziamenti consigliati**
  Espandere matrice test su ambienti con UDP parzialmente bloccato e jitter elevato.
- **KPI/criteri di successo**
  accuratezza endpoint discovery, punch success in finestre temporali variabili.
- **Priorita (P0/P1/P2)**
  **P1**

### 7) NAT Detection Strategy (`src/transport/nat_detection.rs`)
**Score:** 3.2/5

- **Stato attuale**
  NAT typing + strategy selection + caching globale.
- **Perche e forte**
  Il motore di policy e collegato al trasporto in modo pratico e leggibile.
- **Limiti attuali**
  Parte delle classificazioni e test-dependent; necessita convalida estesa in reti reali.
- **Potenziamenti consigliati**
  Dataset operativo su NAT reali e tuning automatizzato della policy.
- **KPI/criteri di successo**
  precisione classificazione vs ground-truth, miglioramento connect success post tuning.
- **Priorita (P0/P1/P2)**
  **P1**

### 8) Tor Path e Fallback (`src/transport/mod.rs`, `src/transport/wan_tor.rs`)
**Score:** 3.7/5

- **Stato attuale**
  Tor e relay sono integrati come fallback seri, non cosmetici.
- **Perche e forte**
  Rende la connettivita praticabile anche in scenari restrittivi.
- **Limiti attuali**
  Tradeoff latency/reliability richiede profiling continuo e politiche adattive.
- **Potenziamenti consigliati**
  Migliorare il ranking dinamico dei fallback in base a metriche storiche.
- **KPI/criteri di successo**
  tor connect p95, drop rate post-upgrade, fallback churn.
- **Priorita (P0/P1/P2)**
  **P1**

### 9) Multipath Scheduling (`src/transport/multipath.rs`)
**Score:** 2.1/5

- **Stato attuale**
  Struttura promettente ma alcune funzioni core restano placeholder (`send_single_path`, `recv_single_path`).
- **Perche e forte**
  Design concettuale buono: policy, metadata, scoring.
- **Limiti attuali**
  Mancanza di path I/O reale end-to-end limita l'impatto operativo.
- **Potenziamenti consigliati**
  Implementare I/O reale per path, ACK/reordering strategy e policy runtime.
- **KPI/criteri di successo**
  gain throughput multi-path, failover recovery time, packet reorder loss.
- **Priorita (P0/P1/P2)**
  **P0**

### 10) Pluggable Transports + QUIC/WebRTC (`src/transport/pluggable.rs`, `src/transport/quic_rfc9000.rs`, `src/transport/webrtc.rs`)
**Score:** 2.9/5

- **Stato attuale**
  Copertura ampia e ambiziosa, inclusa mimicry multi-protocol.
- **Perche e forte**
  Visione anti-censorship e anti-DPI notevole per un progetto di questa scala.
- **Limiti attuali**
  Maturita non uniforme tra profili; dipendenza da infrastruttura esterna per alcuni mode.
- **Potenziamenti consigliati**
  Separare chiaramente modalita "production-backed" da "experimental".
- **KPI/criteri di successo**
  successo handshake per mode, fingerprint robustness, operativita su reti filtrate.
- **Priorita (P0/P1/P2)**
  **P2**

### 11) Session Upgrade (Noise/Resume) (`src/session_noise.rs`)
**Score:** 4.0/5

- **Stato attuale**
  Layer di upgrade robusto, con fallback resume->noise, limiti dimensione, validazioni stato protocollo.
- **Perche e forte**
  Chiarezza del controllo di transizione di stato e gestione errori buona.
- **Limiti attuali**
  Modulo molto denso, con rischio manutentivo nel medio termine.
- **Potenziamenti consigliati**
  Refactor in sottocomponenti (state machine, I/O adapters, validation policy) senza cambiare semantica.
- **KPI/criteri di successo**
  riduzione complessita ciclomatica, stabilita test handshake matrix.
- **Priorita (P0/P1/P2)**
  **P0**

### 12) Security Controls (rate, replay, time) (`src/security/*`, `src/crypto/replay.rs`)
**Score:** 3.9/5

- **Stato attuale**
  Buona difesa multilivello: early drop, rate limiter, replay window, time validation.
- **Perche e forte**
  Difesa composita e ben allineata al threat model di rete.
- **Limiti attuali**
  Alcune policy hanno bisogno di tuning orientato dati in ambienti ad alto traffico.
- **Potenziamenti consigliati**
  Profilazione in carico reale per tarare bucket/backoff/window in modo empirico.
- **KPI/criteri di successo**
  false positive drop rate, replay reject efficacy, stabilita sotto burst.
- **Priorita (P0/P1/P2)**
  **P0**

### 13) Config Networking Knobs (`src/config.rs`)
**Score:** 3.3/5

- **Stato attuale**
  Configurabilita ampia e utile per tuning.
- **Perche e forte**
  Copre molti scenari operativi senza forzare rebuild.
- **Limiti attuali**
  Alcuni knob superano la maturita effettiva del runtime e rischiano aspettative non allineate.
- **Potenziamenti consigliati**
  Allineare documentazione e capability matrix per ogni flag/mode.
- **KPI/criteri di successo**
  riduzione config confusion incidents, percentuale feature realmente operative per profilo.
- **Priorita (P0/P1/P2)**
  **P1**

### 14) API Connessione e Sync (`src/api/connect.rs`, `src/api/sync.rs`, `src/api/stream.rs`)
**Score:** 3.7/5

- **Stato attuale**
  API ricca con validazioni semantiche, flussi offer/qr/target/guaranteed e SSE.
- **Perche e forte**
  Buona gestione stato connessione e orchestrazione task tx/rx.
- **Limiti attuali**
  Necessita consolidamento di metriche operative per debug/diagnostica avanzata.
- **Potenziamenti consigliati**
  Espandere diagnostica per motivo fallback/errore handshake e outcome per path.
- **KPI/criteri di successo**
  MTTR incidenti di connessione, tasso errori non classificati, precisione reporting runtime.
- **Priorita (P0/P1/P2)**
  **P1**

## SOTA Claim

## Cosa e gia SOTA-like
- Integrazione tecnica end-to-end tra routing/fallback, session security e controlli anti-abuso.
- Design Assist V5 con attenzione reale a metadata minimization.
- Strategia operativa multi-trasporto con fallback robusti.

## Cosa manca per dichiarazione SOTA difendibile
- **Audit esterno indipendente** (security + protocol review).
- **Benchmark comparativi pubblici** contro stack equivalenti su scenari standardizzati.
- **Evidenza runtime su reti ostili** (carrier NAT, enterprise firewall, packet loss alto).
- **KPI operativi consolidati** con trend ripetibili.

## Gap to SOTA

| Gap | Impatto | Difficolta | Priorita |
|---|---|---|---|
| Multipath non pienamente operativo end-to-end | Molto alto | Medio-Alta | P0 |
| Densita del session layer (manutenibilita) | Alto | Media | P0 |
| Tuning empirico security controls su carico reale | Alto | Media | P0 |
| Coerenza semantics in simultaneous coordination | Alto | Media | P0 |
| Dandelion differenziato da consolidare su reti reali (tuning empirico) | Medio | Media | P1 |
| NAT/STUN data-driven da consolidare con auto-tuning basato su dati reali | Medio | Media | P1 |
| Diagnostica runtime da estendere (persistenza/export metriche) | Medio | Bassa-Media | P1 |
| Maturita pluggable transports disomogenea | Medio | Alta | P2 |
| Evidenza esterna (audit+bench) assente | Molto alto | Alta | P1/P2 |

## Roadmap P0/P1/P2 (90 giorni)

## P0 (settimane 1-4): stabilita core e coerenza runtime (focus attuale)
- Completare multipath path I/O reale con failover misurabile.
- Refactor tecnico del session layer in componenti piu isolati.
- Hardening coordination path con semantica temporale separata.
- Tuning iniziale rate/replay/time su scenari burst e loss.

**KPI P0**
- connect success rate +8-12% su NAT difficili.
- riduzione p95 connect time del 15%.
- zero regressioni nei flussi base (offer/qr/target/guaranteed).

## P1 (settimane 5-8): adattivita e osservabilita
- [Completato] Dandelion mode differenziato per profilo + override runtime.
- [Completato] Policy NAT/STUN basata su metriche runtime + bias strategy.
- [Completato] Diagnostica API fallback/NAT (`/v1/connect/fallbacks`, `/v1/network/nat-metrics`).
- [Completato] Capability matrix estesa tra config e stato runtime (`/v1/capabilities`).

**KPI P1**
- diminuzione fallback non necessari del 20%.
- riduzione errori "unknown" nelle diagnostiche del 40%.
- miglioramento coerenza mode-config percepita dal client.

## P2 (settimane 9-12): validazione SOTA esterna
- Benchmark comparativi pubblici su scenari replicabili.
- Test suite avversariale estesa per pluggable/anti-DPI.
- Preparazione audit esterno protocol/security.

**KPI P2**
- report benchmark pubblicato e ripetibile.
- backlog hardening post-audit classificato e pianificato.

## Rischi e Tradeoff

- Incrementare parallelismo ICE/multipath puo aumentare complessita di sincronizzazione e rischio race.
- Hardening security aggressivo puo alzare false positive se non calibrato su traffico reale.
- Aumentare superficie pluggable puo introdurre variabilita operativa se non si separano chiaramente profili stable vs experimental.
- Refactor profondo di session layer senza fasi incrementali puo causare regressioni difficili da isolare.

## Note finali

- Questo documento non modifica API o tipi pubblici.
- Le proposte di cambiamento sono raccomandazioni operative priorizzate.
- Claim SOTA raccomandato solo dopo evidenza esterna (audit + benchmark + metriche runtime ripetibili).

