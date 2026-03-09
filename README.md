# OUROBOROS

Comunicazione P2P deterministica, cifrata e serverless.

Ouroboros unisce due prodotti in una sola piattaforma:
- **Handshake**: sessioni punto-punto cifrate con fallback di rete aggressivo.
- **EtherSync**: spazi condivisi derivati da passphrase per messaggi e file chunked.

Repository: [https://github.com/OmarPrampolini/Ouroboros](https://github.com/OmarPrampolini/Ouroboros)  
Licenza: MIT

## Perche esiste

L'obiettivo e semplice: creare comunicazione privata senza dipendere da discovery centralizzata o da un backend cloud obbligatorio.

In pratica:
- se due peer sono online insieme, **Handshake** ottimizza il collegamento live;
- se i peer hanno presenza intermittente, **EtherSync** offre uno spazio gossip cifrato condiviso.

## Stato Reale Del Progetto (Marzo 2026)

### Solido oggi
- Derivazione deterministica da passphrase (tag/parametri/rendezvous).
- API locale autenticata con token in RAM.
- Flussi QR (Offer / Hybrid / Phrase) funzionanti.
- Cascata trasporti con fallback (LAN/WAN/assist/Tor e casi UDP ostili).
- GUI Tauri con modalita guidate, separate per Handshake ed EtherSync.
- Lifecycle daemon robusto in GUI:
  - start/stop,
  - reconnect a daemon gia attivo,
  - reclaim porta quando occupata,
  - log live RAM per debugging.
- EtherSync space con publish messaggi e file chunked.
- Board UI EtherSync migliorata (messages + event timeline).

### Appena aggiunto
- **Replay backlog su join EtherSync**: quando rientri nello stesso space con la stessa passphrase, il nodo rigioca la finestra recente disponibile localmente e pubblica eventi `space_replay_started` / `space_replay_completed`.

### Non ancora garantito globalmente
- Persistenza storica distribuita "sempre e comunque" non e ancora assoluta.
- Se nessun peer mantiene i dati online/in storage, lo storico non e recuperabile.

## Modello Prodotto: A | B

All'apertura GUI trovi due ingressi distinti:

- **A. Handshake Matrix**
  - sessione live 1:1,
  - pairing via passphrase o QR,
  - ottimizzato per connessione immediata e fallback.

- **B. EtherSync Gold**
  - spazio condiviso cifrato derivato da passphrase,
  - publish/subscribe eventi,
  - file transfer chunked,
  - UX dedicata con board operativa.

## Architettura In Breve

### Handshake
- Set passphrase -> derivazione deterministica.
- Connessione via `/v1/connect` con modalita classica, offer, hybrid, target, phrase, guaranteed.
- Stato runtime esposto da endpoint diagnostici.

### EtherSync
- `space_id` derivato deterministicamente da passphrase.
- Pubblicazione su gossip/slot.
- Join space con subscription stream eventi.
- Replay locale su join per backlog recente.

## Semantica EtherSync (Importante)

EtherSync e un sistema gossip cifrato, non un DB centrale.

Questo implica:
- stessa passphrase -> stesso spazio logico;
- il recupero storico dipende dai nodi che hanno visto/mantenuto i messaggi;
- oggi il replay al join copre la finestra recente presente nel nodo locale;
- per retention forte a lungo termine serve almeno un nodo sempre acceso o storage persistente esplicito.

Tradotto in modo operativo: un Raspberry acceso con il tuo nodo puo fungere da seed stabile dello spazio.

## Quick Start

## 1) Core (CLI/API)

```bash
git clone https://github.com/OmarPrampolini/Ouroboros.git
cd Ouroboros
cargo build --release
cargo run --release
```

Default API bind: `127.0.0.1:8731`

## 2) GUI Tauri (consigliato)

```bash
cargo build --release
# Windows:
# copy target\release\handshacke.exe ui\src-tauri\bin\handshacke.exe
# Linux/macOS:
# cp target/release/handshacke ui/src-tauri/bin/handshacke

cd ui
npm install
npm run dev
```

## Flussi GUI

Handshake:
- Classic
- Offer QR
- Hybrid QR
- Target direct
- Phrase (Tor)
- Guaranteed relay

EtherSync:
- Start node
- Join space
- Publish messages/files
- Monitor board + timeline + replay events

## API Principali

Connessione e sessione:
- `POST /v1/connect`
- `GET /v1/status`
- `POST /v1/disconnect`
- `POST /v1/offer`
- `POST /v1/qr/hybrid`
- `POST /v1/phrase/open`
- `POST /v1/phrase/join`
- `GET /v1/phrase/status`
- `POST /v1/phrase/close`
- `GET /v1/circuit`

Messaggistica:
- `POST /v1/send`
- `GET /v1/recv`

EtherSync:
- `POST /v1/ethersync/start`
- `POST /v1/ethersync/stop`
- `GET /v1/ethersync/status`
- `POST /v1/ethersync/peers/add`
- `POST /v1/ethersync/spaces/join`
- `POST /v1/ethersync/spaces/publish`
- `POST /v1/ethersync/files/publish`
- `GET /v1/ethersync/events`

Diagnostica:
- `GET /v1/metrics`
- `GET /v1/capabilities`
- `GET /v1/connect/fallbacks`
- `GET /v1/network/nat-metrics`

## Sicurezza

- Cifratura payload con primitive moderne.
- Token API richiesto lato GUI/daemon.
- Limiti anti-abuso e controlli replay/time window.
- Nessuna persistenza forzata delle chiavi applicative in chiaro.

Riferimenti:
- [SECURITY.md](SECURITY.md)
- [docs/threat_model_visibility.md](docs/threat_model_visibility.md)
- [SOTA.MD](SOTA.MD)

## Roadmap Breve

- Completare replay distribuito piu profondo (oltre finestra locale).
- Migliorare retention multi-peer e osservabilita storage.
- Raffinare UX guided per tutti i flow edge-case.
- Consolidare benchmark comparativi per claim SOTA difendibile.

---

Ouroboros non vuole essere "solo un'altra chat": vuole essere un layer di comunicazione privato, deterministico e controllabile end-to-end, con UX reale da prodotto.
