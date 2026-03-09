export const DEFAULT_API_BIND = "127.0.0.1:8731";

export const ROLE_OPTIONS = ["auto", "host", "client"] as const;
export const WAN_MODES = ["auto", "direct", "tor"] as const;
export const TOR_ROLES = ["client", "host"] as const;
export const GUARANTEED_EGRESS = ["public", "tor"] as const;
export const PLUGGABLE_TRANSPORTS = ["none", "https", "ftp", "dns", "websocket", "quic"] as const;
export const PLUGGABLE_PROFILES = ["stable", "experimental"] as const;
export const STEALTH_MODES = ["active", "passive", "mdns"] as const;
export const FLOW_MODES = ["classic", "offer", "hybrid", "target", "phrase", "guaranteed", "space"] as const;

export type FlowMode = (typeof FLOW_MODES)[number];

export const FLOW_LABELS: Record<FlowMode, string> = {
  classic: "Classic cascade",
  offer: "Offer QR",
  hybrid: "Hybrid QR (resume)",
  target: "Target direct",
  phrase: "Easy Tor (Phrase)",
  guaranteed: "Guaranteed relay",
  space: "EtherSync Space"
};

export const FLOW_DESC: Record<FlowMode, string> = {
  classic: "LAN -> WAN -> Assist -> Tor fallback with full automation.",
  offer: "QR offer handshake for quick pairing without typing addresses.",
  hybrid: "QR with resume token + deterministic fallback (best UX for re-join).",
  target: "Direct connect to an IP:port or .onion target you already know.",
  phrase: "Tor-friendly invite flow with a private passphrase.",
  guaranteed: "Always-on relay with optional Tor egress.",
  space: "Connectionless shared space: join by passphrase, publish and receive realtime messages."
};

export const FLOW_STEPS: Record<FlowMode, string[]> = {
  classic: ["Start daemon", "Set passphrase", "Pick WAN + Tor role", "Connect cascade"],
  offer: ["Start daemon", "Set passphrase", "Generate offer QR", "Client connects with offer"],
  hybrid: [
    "Start daemon",
    "Set passphrase",
    "Generate Hybrid QR",
    "Client connects with QR (resume + fallback)"
  ],
  target: ["Start daemon", "Set passphrase", "Enter target", "Connect direct"],
  phrase: ["Start daemon", "Host opens phrase", "Share invite", "Client joins"],
  guaranteed: ["Start daemon", "Enter passphrase", "Pick egress", "Connect relay"],
  space: ["Start daemon", "Start EtherSync node", "Join space", "Publish and monitor events"]
};

export type DaemonStatus = {
  running: boolean;
  pid?: number | null;
  last_error?: string | null;
  last_exit_code?: number | null;
};

export interface StartResult {
  pid: number;
  api_url: string;
  token: string;
}

export interface SetPassResponse {
  status: string;
  port: number;
  tag16: number;
  tag8?: number;
}

export interface StatusResponse {
  status: string;
  port?: number | null;
  mode: string;
  peer?: string | null;
  resume_status?: string | null;
}

export interface OfferResponse {
  offer: string;
  ver: number;
  expires_at_ms: number;
  endpoints: string[];
}

export interface HybridQrResponse {
  qr: string;
  offer: string;
  ver: number;
  expires_at_ms: number;
  resume_expires_at_ms: number;
  endpoints: string[];
  relay_hints: string[];
}

export interface PluggableCheckResponse {
  pluggable_transport: {
    profile: "stable" | "experimental";
    enabled: boolean;
    mode: string;
    mode_class: "stable" | "experimental";
    status: string;
    checklist: {
      real_tls: string;
      websocket: string;
      http2: string;
      quic: string;
    };
  };
}

export interface DebugMetricsResponse {
  connection: {
    transport_mode: string;
    nat_type?: string | null;
    packet_loss_rate: number;
    avg_encrypt_us: number;
    avg_decrypt_us: number;
    connection_errors: number;
  };
  throughput_mbps: number;
  health_score: number;
  status: string;
}

export interface EtherSyncStatusResponse {
  running: boolean;
  bind_addr?: string | null;
  local_addr?: string | null;
  peer_count: number;
  subscription_count: number;
  spaces: string[];
}

export interface EtherSyncJoinResponse {
  space_id: string;
}

export interface EtherSyncPublishResponse {
  space_id: string;
  slot_id: number;
  payload_len: number;
}

export interface EtherSyncFilePublishResponse {
  space_id: string;
  transfer_id: string;
  filename: string;
  total_bytes: number;
  total_chunks: number;
  published_chunks: number;
}

export interface EtherSyncFileChunkEnvelope {
  kind: "file_chunk";
  transfer_id: string;
  filename: string;
  total_bytes: number;
  chunk_index: number;
  total_chunks: number;
  chunk_b64: string;
}

export interface EtherSyncEvent {
  kind: string;
  ts_ms: number;
  space_id?: string | null;
  slot_id?: number | null;
  payload_b64?: string | null;
  text?: string | null;
  info?: string | null;
  error?: string | null;
}
