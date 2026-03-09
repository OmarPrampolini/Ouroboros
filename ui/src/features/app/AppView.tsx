import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import QRCode from "qrcode";
import { useSSE } from "../../hooks/useSSE";
import { useLogs } from "../../hooks/useLogs";
import { TopBar } from "../../components/TopBar";
import { WizardSteps } from "../../components/WizardSteps";
import { PhaseBar, PhaseState } from "../../components/PhaseBar";
import { ConsolePanel } from "../../components/ConsolePanel";
import {
  DaemonStatus,
  DebugMetricsResponse,
  EtherSyncEvent,
  EtherSyncFileChunkEnvelope,
  EtherSyncFilePublishResponse,
  EtherSyncJoinResponse,
  EtherSyncPublishResponse,
  EtherSyncStatusResponse,
  FLOW_DESC,
  FLOW_LABELS,
  FLOW_MODES,
  FLOW_STEPS,
  FlowMode,
  GUARANTEED_EGRESS,
  HybridQrResponse,
  OfferResponse,
  PLUGGABLE_PROFILES,
  PLUGGABLE_TRANSPORTS,
  PluggableCheckResponse,
  ROLE_OPTIONS,
  SetPassResponse,
  StartResult,
  StatusResponse,
  STEALTH_MODES,
  TOR_ROLES,
  WAN_MODES
} from "./model";
import {
  useAdvancedSlice,
  useConnectionSlice,
  useGuaranteedSlice,
  useHybridSlice,
  useOfferSlice,
  usePhraseSlice,
  useSpaceSlice,
  useSystemSlice,
  useTargetSlice
} from "./stateSlices";

const SPACE_CHUNK_SIZE_DEFAULT = 1024;
const SPACE_CHUNK_SIZE_MIN = 256;
const SPACE_CHUNK_SIZE_MAX = 12288;

const HANDSHAKE_FLOW_MODES: readonly FlowMode[] = [
  "classic",
  "offer",
  "hybrid",
  "target",
  "phrase",
  "guaranteed"
];
const ETHERSYNC_FLOW_MODES: readonly FlowMode[] = ["space"];

type ProductTrack = "handshake" | "ethersync";

type SpaceIncomingTransfer = {
  transfer_id: string;
  filename: string;
  total_bytes: number;
  total_chunks: number;
  chunks: Record<number, string>;
  updated_at_ms: number;
};

export function AppView() {
  const {
    apiBind,
    setApiBind,
    unsafeExpose,
    setUnsafeExpose,
    daemonStatus,
    setDaemonStatus,
    token,
    setToken,
    warning,
    setWarning,
    sseEnabled,
    setSseEnabled,
    screen,
    setScreen,
    connectAttempted,
    setConnectAttempted
  } = useSystemSlice();
  const {
    passphrase,
    setPassphrase,
    showPassphrase,
    setShowPassphrase,
    localRole,
    setLocalRole,
    wanMode,
    setWanMode,
    torRole,
    setTorRole,
    connectStatus,
    setConnectStatus,
    setPassResult,
    setSetPassResult,
    flowMode,
    setFlowMode
  } = useConnectionSlice();
  const {
    offerResult,
    setOfferResult,
    offerQr,
    setOfferQr,
    offerTtl,
    setOfferTtl,
    offerRoleHint,
    setOfferRoleHint,
    offerLocalRole,
    setOfferLocalRole,
    classicOffer,
    setClassicOffer,
    includeTorOffer,
    setIncludeTorOffer
  } = useOfferSlice();
  const {
    hybridQrResult,
    setHybridQrResult,
    hybridQrImage,
    setHybridQrImage,
    hybridQrTtl,
    setHybridQrTtl,
    hybridResumeTtl,
    setHybridResumeTtl,
    hybridRoleHint,
    setHybridRoleHint,
    hybridLocalRole,
    setHybridLocalRole,
    hybridIncludeTor,
    setHybridIncludeTor,
    hybridRelayHints,
    setHybridRelayHints,
    hybridQrInput,
    setHybridQrInput
  } = useHybridSlice();
  const {
    phraseInvite,
    setPhraseInvite,
    phraseQr,
    setPhraseQr,
    phraseStatus,
    setPhraseStatus,
    joinInvite,
    setJoinInvite,
    phrasePassphrase,
    setPhrasePassphrase
  } = usePhraseSlice();
  const {
    classicTarget,
    setClassicTarget,
    targetIsOnion,
    setTargetIsOnion,
    targetOnion,
    setTargetOnion
  } = useTargetSlice();
  const {
    guaranteedPassphrase,
    setGuaranteedPassphrase,
    guaranteedEgress,
    setGuaranteedEgress,
    guaranteedRelayUrl,
    setGuaranteedRelayUrl
  } = useGuaranteedSlice();
  const {
    spaceBindAddr,
    setSpaceBindAddr,
    spaceBootstrapPeers,
    setSpaceBootstrapPeers,
    spacePassphrase,
    setSpacePassphrase,
    spaceLabel,
    setSpaceLabel,
    spacePeerToAdd,
    setSpacePeerToAdd,
    spaceMessage,
    setSpaceMessage,
    spaceFileName,
    setSpaceFileName,
    spaceFileB64,
    setSpaceFileB64,
    spaceFileSize,
    setSpaceFileSize,
    spaceChunkSize,
    setSpaceChunkSize,
    spaceStatus,
    setSpaceStatus,
    spaceJoinedId,
    setSpaceJoinedId,
    spaceEvents,
    setSpaceEvents
  } = useSpaceSlice();
  const {
    pluggableProfile,
    setPluggableProfile,
    pluggableTransport,
    setPluggableTransport,
    realTlsDomain,
    setRealTlsDomain,
    stealthMode,
    setStealthMode,
    assistRelays,
    setAssistRelays,
    torSocksAddr,
    setTorSocksAddr,
    torOnionAddr,
    setTorOnionAddr,
    pluggableCheck,
    setPluggableCheck,
    metrics,
    setMetrics
  } = useAdvancedSlice();
  const { filtered, filter, setFilter, logLine, clear } = useLogs();

  const statusTimer = useRef<number | null>(null);
  const lastDaemonError = useRef<string | null>(null);
  const [spaceIncomingFiles, setSpaceIncomingFiles] = useState<Record<string, SpaceIncomingTransfer>>(
    {}
  );
  const [homeTrack, setHomeTrack] = useState<"selector" | ProductTrack>("selector");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [daemonLiveLines, setDaemonLiveLines] = useState<string[]>([]);
  const [externalDaemonAttached, setExternalDaemonAttached] = useState(false);
  const [attachTokenInput, setAttachTokenInput] = useState("");
  const daemonLogCursor = useRef(0);

  const apiUrl = useMemo(() => `http://${apiBind}`, [apiBind]);
  const authHeader = useMemo(
    () => (token ? { Authorization: `Bearer ${token}` } : {}),
    [token]
  );

  const formatTtl = useCallback((expiresAtMs?: number | null) => {
    if (!expiresAtMs) return "-";
    const delta = Math.max(0, expiresAtMs - Date.now());
    const s = Math.floor(delta / 1000);
    const m = Math.floor(s / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    if (m > 0) return `${m}m ${s % 60}s`;
    return `${s}s`;
  }, []);

  const isSymmetricNat = useMemo(() => {
    const nat = metrics?.connection?.nat_type?.toLowerCase() ?? "";
    return nat.includes("symmetric");
  }, [metrics]);

  const modeBadge = useMemo(() => {
    const mode = connectStatus?.mode ?? "unknown";
    if (mode === "lan" || mode === "wan" || mode === "stun") return { label: mode, tone: "ok" };
    if (mode === "wan_tcp") return { label: "wan_tcp (udp blocked)", tone: "warn" };
    if (mode === "wan_tor") return { label: "wan_tor (relay)", tone: "warn" };
    if (mode === "quic" || mode === "webrtc") return { label: mode, tone: "info" };
    return { label: mode, tone: "muted" };
  }, [connectStatus]);

  const healthBadge = useMemo(() => {
    if (!metrics) return { label: "unknown", tone: "muted" };
    if (metrics.health_score >= 80) return { label: "healthy", tone: "ok" };
    if (metrics.health_score >= 50) return { label: "degraded", tone: "warn" };
    return { label: "poor", tone: "danger" };
  }, [metrics]);

  const fetchWithAuth = useCallback(
    async (path: string, options?: RequestInit) => {
      const activeToken = token;
      if (!activeToken) throw new Error("token not loaded");
      const headers = new Headers(options?.headers || {});
      if (activeToken) {
        headers.set("Authorization", `Bearer ${activeToken}`);
      }
      headers.set("Content-Type", "application/json");
      const res = await fetch(`${apiUrl}${path}`, { ...options, headers });
      if (!res.ok) throw new Error(`API error ${res.status}`);
      return res;
    },
    [apiUrl, token]
  );

  const probeStatusWithToken = useCallback(
    async (tokenCandidate: string) => {
      const cleanToken = tokenCandidate.trim();
      if (!cleanToken) {
        throw new Error("token required");
      }

      const res = await fetch(`${apiUrl}/v1/status`, {
        headers: {
          Authorization: `Bearer ${cleanToken}`,
          "Content-Type": "application/json"
        }
      });

      if (!res.ok) {
        throw new Error(`API error ${res.status}`);
      }

      return (await res.json()) as StatusResponse;
    },
    [apiUrl]
  );
  const refreshStatus = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetchWithAuth("/v1/status");
      const data = await res.json();
      setConnectStatus(data);
    } catch (err) {
      logLine("STATUS", (err as Error).message);
    }
  }, [fetchWithAuth, logLine, token]);

  const startStatusPoll = useCallback(() => {
    if (statusTimer.current) clearInterval(statusTimer.current);
    statusTimer.current = window.setInterval(refreshStatus, 3000);
  }, [refreshStatus]);

  const stopStatusPoll = useCallback(() => {
    if (statusTimer.current) {
      clearInterval(statusTimer.current);
      statusTimer.current = null;
    }
  }, []);

  const { state: sseState } = useSSE(`${apiUrl}/v1/recv`, {
    enabled: sseEnabled && !!token,
    headers: authHeader,
    onEvent: (evt) => {
      if (evt.data && evt.data !== "ok") {
        logLine("SSE", String(evt.data));
      }
    },
    onError: (err) => {
      logLine("SSE", String(err));
    }
  });

  const parsePeersCsv = useCallback((raw: string): string[] => {
    return raw
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
  }, []);

  const decodeBase64Utf8 = useCallback((raw: string): string => {
    const binary = atob(raw);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  }, []);

  const decodeBase64Bytes = useCallback((raw: string): Uint8Array => {
    const binary = atob(raw);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }, []);

  const encodeBytesToBase64 = useCallback((bytes: Uint8Array): string => {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }, []);

  const copyToClipboard = useCallback(
    async (value: string, label: string) => {
      const clean = value.trim();
      if (!clean) return;
      try {
        await navigator.clipboard.writeText(clean);
        logLine("SPACE", `${label} copied`);
      } catch (err) {
        logLine("SPACE", `copy failed: ${(err as Error).message}`);
      }
    },
    [logLine]
  );

  const handleSpacePayload = useCallback(
    (payloadB64?: string | null) => {
      if (!payloadB64) return;
      try {
        const json = decodeBase64Utf8(payloadB64);
        const parsed = JSON.parse(json) as Partial<EtherSyncFileChunkEnvelope>;
        if (parsed.kind !== "file_chunk" || !parsed.transfer_id || !parsed.filename) return;
        if (
          typeof parsed.chunk_index !== "number" ||
          typeof parsed.total_chunks !== "number" ||
          typeof parsed.total_bytes !== "number" ||
          typeof parsed.chunk_b64 !== "string"
        ) {
          return;
        }
        setSpaceIncomingFiles((prev) => {
          const existing = prev[parsed.transfer_id!] ?? {
            transfer_id: parsed.transfer_id!,
            filename: parsed.filename!,
            total_bytes: parsed.total_bytes!,
            total_chunks: parsed.total_chunks!,
            chunks: {},
            updated_at_ms: Date.now()
          };
          if (existing.chunks[parsed.chunk_index!] === parsed.chunk_b64) {
            return prev;
          }
          return {
            ...prev,
            [parsed.transfer_id!]: {
              ...existing,
              total_bytes: parsed.total_bytes!,
              total_chunks: parsed.total_chunks!,
              chunks: {
                ...existing.chunks,
                [parsed.chunk_index!]: parsed.chunk_b64!
              },
              updated_at_ms: Date.now()
            }
          };
        });
      } catch {
        // Non-JSON or non-file payload.
      }
    },
    [decodeBase64Utf8]
  );

  const { state: spaceSseState } = useSSE(`${apiUrl}/v1/ethersync/events`, {
    enabled: daemonStatus.running && !!token && flowMode === "space" && Boolean(spaceStatus?.running),
    headers: authHeader,
    onEvent: (evt) => {
      const raw = String(evt.data || "");
      if (!raw || raw === "ok") return;
      try {
        const event = JSON.parse(raw) as EtherSyncEvent;
        setSpaceEvents((prev) => [event, ...prev].slice(0, 120));
        handleSpacePayload(event.payload_b64);
      } catch {
        logLine("SPACE", raw);
      }
    },
    onError: (err) => {
      logLine("SPACE", `events: ${String(err)}`);
    }
  });

  const handleStartDaemon = useCallback(async () => {
    const isUnsafeBind = apiBind.startsWith("0.0.0.0");
    if (isUnsafeBind && !unsafeExpose) {
      setWarning("Unsafe bind requires --unsafe-expose-api");
      return;
    }

    const cleanedPluggableProfile = pluggableProfile.trim() || undefined;
    const cleanedPluggable =
      pluggableTransport === "none" ? undefined : pluggableTransport;
    const cleanedRealTlsDomain = realTlsDomain.trim() || undefined;
    const cleanedStealthMode = stealthMode.trim() || undefined;
    const cleanedAssistRelays = assistRelays.trim() || undefined;
    const cleanedTorSocks = torSocksAddr.trim() || undefined;
    const cleanedTorOnion = torOnionAddr.trim() || undefined;

    try {
      daemonLogCursor.current = 0;
      setDaemonLiveLines([]);
      const result = await invoke<StartResult>("start_daemon", {
        apiBind,
        unsafeExposeApi: unsafeExpose,
        pluggableTransport: cleanedPluggable,
        pluggableProfile: cleanedPluggableProfile,
        realTlsDomain: cleanedRealTlsDomain,
        stealthMode: cleanedStealthMode,
        assistRelays: cleanedAssistRelays,
        torSocksAddr: cleanedTorSocks,
        torOnionAddr: cleanedTorOnion
      });

      setDaemonStatus({ running: true, pid: result.pid });
      setToken(result.token);
      setHomeTrack(flowMode === "space" ? "ethersync" : "handshake");
      setScreen("mode");
      setWarning(null);
      logLine("DAEMON", `started pid=${result.pid}`);
    } catch (err) {
      const msg = (err as Error).message || String(err);
      setWarning(msg);
      setScreen("mode");
      logLine("DAEMON", msg);
      setDaemonStatus({ running: false });
    }
  }, [
    apiBind,
    unsafeExpose,
    pluggableProfile,
    pluggableTransport,
    realTlsDomain,
    stealthMode,
    assistRelays,
    torSocksAddr,
    torOnionAddr,
    flowMode,
    logLine
  ]);

  const pullDaemonLogsLive = useCallback(
    async (snapshot = false) => {
      try {
        const logs = (await invoke<string[]>("daemon_logs")) || [];
        if (logs.length < daemonLogCursor.current) {
          daemonLogCursor.current = 0;
        }
        if (snapshot) {
          daemonLogCursor.current = logs.length;
          setDaemonLiveLines(logs.slice(-200));
          if (logs.length === 0) {
            logLine("DAEMON", "no daemon logs yet");
          }
          return;
        }
        const fresh = logs.slice(daemonLogCursor.current);
        daemonLogCursor.current = logs.length;
        if (fresh.length > 0) {
          setDaemonLiveLines((prev) => [...prev, ...fresh].slice(-200));
          fresh.forEach((line) => logLine("DAEMON", line));
        }
      } catch (err) {
        logLine("DAEMON", `live log poll failed: ${(err as Error).message}`);
      }
    },
    [logLine]
  );

  const handleFetchDaemonLogs = useCallback(async () => {
    await pullDaemonLogsLive(true);
  }, [pullDaemonLogsLive]);

  const handleAttachDaemon = useCallback(async () => {
    const candidate = attachTokenInput.trim() || token?.trim() || "";
    if (!candidate) {
      setWarning("Token required to reconnect an existing daemon");
      return;
    }

    try {
      const status = await probeStatusWithToken(candidate);
      setToken(candidate);
      setAttachTokenInput(candidate);
      setDaemonStatus({ running: true, pid: null });
      setExternalDaemonAttached(true);
      setWarning(null);
      setScreen("mode");
      setConnectStatus(status);
      startStatusPoll();
      logLine("DAEMON", `attached to existing daemon on ${apiBind}`);
    } catch (err) {
      const msg = (err as Error).message || String(err);
      setWarning(`attach failed: ${msg}`);
      logLine("DAEMON", `attach failed: ${msg}`);
    }
  }, [
    attachTokenInput,
    token,
    probeStatusWithToken,
    setConnectStatus,
    startStatusPoll,
    apiBind,
    logLine
  ]);
  const handleReclaimPort = useCallback(async () => {
    try {
      const result = await invoke<string>("reclaim_port", { apiBind });
      setDaemonStatus({ running: false });
      setExternalDaemonAttached(false);
      setToken(null);
      setAttachTokenInput("");
      stopStatusPoll();
      setSseEnabled(false);
      setWarning(null);
      logLine("DAEMON", result);
      await pullDaemonLogsLive(true);
    } catch (err) {
      const msg = (err as Error).message || String(err);
      logLine("DAEMON", `reclaim failed: ${msg}`);
    }
  }, [apiBind, logLine, pullDaemonLogsLive, stopStatusPoll]);

  const handleRefreshPluggable = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/pluggable/check");
      const data = (await res.json()) as PluggableCheckResponse;
      setPluggableCheck(data);
    } catch (err) {
      logLine("PLUGGABLE", (err as Error).message);
    }
  }, [fetchWithAuth, logLine]);

  const handleRefreshMetrics = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/metrics");
      const data = (await res.json()) as DebugMetricsResponse;
      setMetrics(data);
    } catch (err) {
      logLine("METRICS", (err as Error).message);
    }
  }, [fetchWithAuth, logLine]);

  const handleStopDaemon = useCallback(async () => {
    try {
      if (externalDaemonAttached) {
        const reclaimed = await invoke<string>("reclaim_port", { apiBind });
        logLine("DAEMON", reclaimed);
      } else {
        await invoke("stop_daemon");
      }
    } catch (err) {
      logLine("DAEMON", `stop failed: ${(err as Error).message}`);
    }

    setDaemonStatus({ running: false });
    setExternalDaemonAttached(false);
    setToken(null);
    setAttachTokenInput("");
    stopStatusPoll();
    setSseEnabled(false);
    setSpaceStatus(null);
    setSpaceJoinedId("");
    setSpaceEvents([]);
    setSpaceIncomingFiles({});
    setSpaceFileName("");
    setSpaceFileB64("");
    setSpaceFileSize(0);
    logLine("DAEMON", "stopped");
  }, [
    externalDaemonAttached,
    apiBind,
    logLine,
    stopStatusPoll,
    setSpaceStatus,
    setSpaceJoinedId,
    setSpaceEvents,
    setSpaceFileName,
    setSpaceFileB64,
    setSpaceFileSize
  ]);

  // Token is passed in-RAM by the launcher; no token file on disk.

  const handleSetPassphrase = useCallback(async () => {
    if (!passphrase) return;
    try {
      const res = await fetchWithAuth("/v1/set_passphrase", {
        method: "POST",
        body: JSON.stringify({ passphrase })
      });
      const data = (await res.json()) as SetPassResponse;
      setSetPassResult(data);
      logLine("PASS", `port=${data.port} tag16=${data.tag16}`);
    } catch (err) {
      logLine("PASS", (err as Error).message);
    }
  }, [fetchWithAuth, passphrase, logLine]);

  const localRolePayload =
    localRole === "auto" ? undefined : localRole;

  const handleConnectCascade = useCallback(async () => {
    if (!passphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          product_mode: "classic",
          passphrase,
          wan_mode: wanMode,
          tor_role: torRole,
          local_role: localRolePayload,
          target_onion: targetOnion.trim() || undefined
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    passphrase,
    wanMode,
    torRole,
    localRolePayload,
    targetOnion,
    logLine
  ]);

  const handleConnectOffer = useCallback(async () => {
    const offerTrim = classicOffer.trim();
    if (!offerTrim) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          offer: offerTrim,
          local_role: offerLocalRole
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [fetchWithAuth, classicOffer, offerLocalRole, logLine]);

  const handleConnectTarget = useCallback(async () => {
    const targetTrim = classicTarget.trim();
    if (!passphrase.trim() || !targetTrim) return;
    const onion = targetIsOnion ? targetTrim : undefined;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          product_mode: "classic",
          passphrase,
          target: targetTrim,
          wan_mode: targetIsOnion ? "tor" : wanMode,
          tor_role: targetIsOnion ? "client" : torRole,
          local_role: localRolePayload,
          target_onion: onion
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    passphrase,
    classicTarget,
    targetIsOnion,
    wanMode,
    torRole,
    localRolePayload,
    logLine
  ]);

  const handleConnectGuaranteed = useCallback(async () => {
    if (!guaranteedPassphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          product_mode: "guaranteed",
          passphrase: guaranteedPassphrase,
          guaranteed_egress: guaranteedEgress,
          guaranteed_relay_url: guaranteedRelayUrl || undefined,
          local_role: localRolePayload
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("GUARANTEED", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("GUARANTEED", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    guaranteedPassphrase,
    guaranteedEgress,
    guaranteedRelayUrl,
    localRolePayload,
    logLine
  ]);

  const handleSpaceStart = useCallback(async () => {
    try {
      const peers = parsePeersCsv(spaceBootstrapPeers);
      const res = await fetchWithAuth("/v1/ethersync/start", {
        method: "POST",
        body: JSON.stringify({
          bind_addr: spaceBindAddr.trim() || undefined,
          bootstrap_peers: peers.length > 0 ? peers : undefined
        })
      });
      const data = (await res.json()) as EtherSyncStatusResponse;
      setSpaceStatus(data);
      logLine("SPACE", `node started at ${data.local_addr ?? "unknown"}`);
    } catch (err) {
      logLine("SPACE", (err as Error).message);
    }
  }, [fetchWithAuth, parsePeersCsv, spaceBootstrapPeers, spaceBindAddr, logLine]);

  const handleSpaceStop = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/ethersync/stop", { method: "POST" });
      const data = (await res.json()) as EtherSyncStatusResponse;
      setSpaceStatus(data);
      setSpaceJoinedId("");
      setSpaceIncomingFiles({});
      setSpaceEvents([]);
      setSpaceFileName("");
      setSpaceFileB64("");
      setSpaceFileSize(0);
      logLine("SPACE", "node stopped");
    } catch (err) {
      logLine("SPACE", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    logLine,
    setSpaceEvents,
    setSpaceFileB64,
    setSpaceFileName,
    setSpaceFileSize
  ]);

  const handleSpaceStatus = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/ethersync/status");
      const data = (await res.json()) as EtherSyncStatusResponse;
      setSpaceStatus(data);
    } catch (err) {
      logLine("SPACE", (err as Error).message);
    }
  }, [fetchWithAuth, logLine]);

  const handleSpaceAddPeer = useCallback(async () => {
    const peer = spacePeerToAdd.trim();
    if (!peer) return;
    try {
      const res = await fetchWithAuth("/v1/ethersync/peers/add", {
        method: "POST",
        body: JSON.stringify({ addr: peer })
      });
      const data = (await res.json()) as EtherSyncStatusResponse;
      setSpaceStatus(data);
      logLine("SPACE", `peer added ${peer}`);
      setSpacePeerToAdd("");
    } catch (err) {
      logLine("SPACE", (err as Error).message);
    }
  }, [fetchWithAuth, spacePeerToAdd, logLine, setSpacePeerToAdd]);

  const handleSpaceJoin = useCallback(async () => {
    if (!spacePassphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/ethersync/spaces/join", {
        method: "POST",
        body: JSON.stringify({
          passphrase: spacePassphrase,
          label: spaceLabel.trim() || undefined
        })
      });
      const data = (await res.json()) as EtherSyncJoinResponse;
      setSpaceJoinedId(data.space_id);
      logLine("SPACE", `joined ${data.space_id}`);
      await handleSpaceStatus();
    } catch (err) {
      logLine("SPACE", (err as Error).message);
    }
  }, [fetchWithAuth, spacePassphrase, spaceLabel, handleSpaceStatus, logLine]);

  const handleSpaceStartAndJoin = useCallback(async () => {
    if (!spacePassphrase.trim()) return;
    if (!spaceStatus?.running) {
      await handleSpaceStart();
    }
    await handleSpaceJoin();
  }, [spacePassphrase, spaceStatus?.running, handleSpaceStart, handleSpaceJoin]);

  const handleSpacePublish = useCallback(async () => {
    if (!spacePassphrase.trim() || !spaceMessage.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/ethersync/spaces/publish", {
        method: "POST",
        body: JSON.stringify({
          passphrase: spacePassphrase,
          message: spaceMessage
        })
      });
      const data = (await res.json()) as EtherSyncPublishResponse;
      logLine("SPACE", `published ${data.payload_len}B in slot ${data.slot_id}`);
      setSpaceMessage("");
    } catch (err) {
      logLine("SPACE", (err as Error).message);
    }
  }, [fetchWithAuth, spacePassphrase, spaceMessage, logLine, setSpaceMessage]);

  const handleSpaceFileSelected = useCallback(
    async (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;
      const bytes = new Uint8Array(await file.arrayBuffer());
      setSpaceFileName(file.name);
      setSpaceFileSize(file.size);
      setSpaceFileB64(encodeBytesToBase64(bytes));
      event.target.value = "";
    },
    [encodeBytesToBase64, setSpaceFileB64, setSpaceFileName, setSpaceFileSize]
  );

  const handleSpacePublishFile = useCallback(async () => {
    if (!spacePassphrase.trim() || !spaceFileB64 || !spaceFileName.trim()) return;
    try {
      const parsedChunkSize = Number(spaceChunkSize);
      const validChunkSize =
        Number.isInteger(parsedChunkSize) &&
        parsedChunkSize >= SPACE_CHUNK_SIZE_MIN &&
        parsedChunkSize <= SPACE_CHUNK_SIZE_MAX
          ? parsedChunkSize
          : undefined;
      const res = await fetchWithAuth("/v1/ethersync/files/publish", {
        method: "POST",
        body: JSON.stringify({
          passphrase: spacePassphrase,
          filename: spaceFileName,
          file_b64: spaceFileB64,
          chunk_size: validChunkSize
        })
      });
      const data = (await res.json()) as EtherSyncFilePublishResponse;
      logLine(
        "SPACE",
        `file ${data.filename} published in ${data.published_chunks}/${data.total_chunks} chunks`
      );
      setSpaceFileName("");
      setSpaceFileB64("");
      setSpaceFileSize(0);
    } catch (err) {
      logLine("SPACE", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    spacePassphrase,
    spaceFileB64,
    spaceFileName,
    spaceChunkSize,
    logLine,
    setSpaceFileName,
    setSpaceFileB64,
    setSpaceFileSize
  ]);

  const handleSpaceDownloadTransfer = useCallback(
    (transferId: string) => {
      const transfer = spaceIncomingFiles[transferId];
      if (!transfer) return;
      const chunks: Uint8Array[] = [];
      let totalSize = 0;
      for (let i = 0; i < transfer.total_chunks; i += 1) {
        const chunkB64 = transfer.chunks[i];
        if (!chunkB64) return;
        const chunk = decodeBase64Bytes(chunkB64);
        chunks.push(chunk);
        totalSize += chunk.byteLength;
      }

      const payload = new ArrayBuffer(totalSize);
      const merged = new Uint8Array(payload);
      let offset = 0;
      for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.byteLength;
      }

      const blob = new Blob([payload], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = transfer.filename;
      a.click();
      URL.revokeObjectURL(url);
    },
    [spaceIncomingFiles, decodeBase64Bytes]
  );

  const refreshPhraseStatus = useCallback(async () => {
    try {
      const res = await fetchWithAuth("/v1/phrase/status");
      const data = (await res.json()) as { status: string };
      setPhraseStatus(data.status);
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, logLine]);

  const handlePhraseOpen = useCallback(async () => {
    if (!phrasePassphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/phrase/open", {
        method: "POST",
        body: JSON.stringify({ passphrase: phrasePassphrase })
      });
      const data = (await res.json()) as { invite: string };
      setPhraseInvite(data.invite);
      setPhraseQr(await QRCode.toDataURL(data.invite, { width: 280, margin: 1 }));
      setJoinInvite(data.invite);
      await refreshPhraseStatus();
      logLine("PHRASE", "opened");
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, phrasePassphrase, refreshPhraseStatus, logLine]);

  const handlePhraseClose = useCallback(async () => {
    try {
      await fetchWithAuth("/v1/phrase/close", { method: "POST" });
      setPhraseInvite("");
      setPhraseQr(null);
      setPhrasePassphrase("");
      await refreshPhraseStatus();
      logLine("PHRASE", "closed");
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, refreshPhraseStatus, logLine]);

  const handlePhraseJoin = useCallback(async () => {
    if (!joinInvite.trim() || !phrasePassphrase.trim()) return;
    try {
      const res = await fetchWithAuth("/v1/phrase/join", {
        method: "POST",
        body: JSON.stringify({ invite: joinInvite.trim(), passphrase: phrasePassphrase })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      setSseEnabled(true);
      startStatusPoll();
      logLine("PHRASE", `joined ${data.status}`);
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [fetchWithAuth, joinInvite, phrasePassphrase, logLine, startStatusPoll]);

  const handlePasteTheme = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText();
      setPhrasePassphrase(text);
      logLine("PHRASE", "theme pasted from clipboard");
    } catch (err) {
      logLine("PHRASE", (err as Error).message);
    }
  }, [logLine]);

  const handleStartAuto = useCallback(async () => {
    if (!passphrase.trim()) {
      setWarning("Passphrase required");
      return;
    }
    try {
      if (!daemonStatus.running) {
        await handleStartDaemon();
      }
      await handleSetPassphrase();
      await handleConnectCascade();
      setSseEnabled(true);
      startStatusPoll();
      setWarning(null);
    } catch (err) {
      logLine("AUTO", (err as Error).message);
    }
  }, [
    passphrase,
    daemonStatus.running,
    handleStartDaemon,
    handleSetPassphrase,
    handleConnectCascade,
    startStatusPoll
  ]);

  const handleOffer = useCallback(async () => {
    if (!passphrase) return;
    try {
      const res = await fetchWithAuth("/v1/offer", {
        method: "POST",
        body: JSON.stringify({
          passphrase,
          include_tor: includeTorOffer,
          role_hint: offerRoleHint,
          ttl_s: offerTtl ? Number(offerTtl) : undefined
        })
      });
      const data = (await res.json()) as OfferResponse;
      setOfferResult(data);
      setOfferQr(await QRCode.toDataURL(data.offer, { width: 280, margin: 1 }));
      logLine("OFFER", `ver=${data.ver}`);
    } catch (err) {
      logLine("OFFER", (err as Error).message);
    }
  }, [fetchWithAuth, passphrase, includeTorOffer, offerRoleHint, offerTtl]);

  const handleHybridQr = useCallback(async () => {
    if (!passphrase) return;
    try {
      const res = await fetchWithAuth("/v1/qr/hybrid", {
        method: "POST",
        body: JSON.stringify({
          passphrase,
          include_tor: hybridIncludeTor,
          role_hint: hybridRoleHint,
          ttl_s: hybridQrTtl ? Number(hybridQrTtl) : undefined,
          resume_ttl_s: hybridResumeTtl ? Number(hybridResumeTtl) : undefined,
          relay_hints: hybridRelayHints
            ? hybridRelayHints.split(",").map((s) => s.trim()).filter(Boolean)
            : undefined
        })
      });
      const data = (await res.json()) as HybridQrResponse;
      setHybridQrResult(data);
      setHybridQrImage(await QRCode.toDataURL(data.qr, { width: 280, margin: 1 }));
      logLine("QR", `hybrid ver=${data.ver}`);
    } catch (err) {
      logLine("QR", (err as Error).message);
    }
  }, [
    fetchWithAuth,
    passphrase,
    hybridIncludeTor,
    hybridRoleHint,
    hybridQrTtl,
    hybridResumeTtl,
    hybridRelayHints,
    logLine
  ]);

  const handleConnectHybridQr = useCallback(async () => {
    const qrTrim = hybridQrInput.trim();
    if (!qrTrim) return;
    try {
      const res = await fetchWithAuth("/v1/connect", {
        method: "POST",
        body: JSON.stringify({
          qr: qrTrim,
          local_role: hybridLocalRole
        })
      });
      const data = (await res.json()) as StatusResponse;
      setConnectStatus(data);
      setConnectAttempted(true);
      logLine("CONNECT", `${data.status} mode=${data.mode}`);
    } catch (err) {
      logLine("CONNECT", (err as Error).message);
    }
  }, [fetchWithAuth, hybridQrInput, hybridLocalRole, logLine]);

  useEffect(() => {
    invoke("daemon_status").then((r) => setDaemonStatus(r as DaemonStatus));
  }, []);

  useEffect(() => {
    if (!daemonStatus.running || externalDaemonAttached) return;
    let alive = true;
    const tick = async () => {
      while (alive) {
        try {
          const r = (await invoke("daemon_status")) as DaemonStatus;
          setDaemonStatus(r);
        } catch (err) {
          logLine("DAEMON", String(err));
        }
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
    };
    tick();
    return () => {
      alive = false;
    };
  }, [daemonStatus.running, externalDaemonAttached, logLine]);

  // no token-file loading

  useEffect(() => {
    const err = daemonStatus.last_error || null;
    if (err && err !== lastDaemonError.current) {
      lastDaemonError.current = err;
      logLine("DAEMON", err);
    }
  }, [daemonStatus.last_error, logLine]);

  useEffect(() => {
    if (screen !== "mode") return;
    void pullDaemonLogsLive(true);
    const timer = window.setInterval(() => {
      void pullDaemonLogsLive();
    }, 1200);
    return () => {
      clearInterval(timer);
    };
  }, [screen, pullDaemonLogsLive]);

  useEffect(() => {
    if (!externalDaemonAttached || !token) return;
    let alive = true;

    const tick = async () => {
      while (alive) {
        try {
          await probeStatusWithToken(token);
          setDaemonStatus((prev) => ({ ...prev, running: true }));
        } catch (err) {
          const msg = (err as Error).message || String(err);
          setWarning(`attached daemon unreachable: ${msg}`);
          setDaemonStatus({ running: false });
          setExternalDaemonAttached(false);
          stopStatusPoll();
          break;
        }

        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
    };

    tick();
    return () => {
      alive = false;
    };
  }, [externalDaemonAttached, token, probeStatusWithToken, stopStatusPoll]);

  useEffect(() => {
    if (!daemonStatus.running || !token) return;
    if (flowMode !== "space") return;
    handleSpaceStatus();
  }, [daemonStatus.running, token, flowMode, handleSpaceStatus]);

  const flowTrack: ProductTrack = flowMode === "space" ? "ethersync" : "handshake";
  const currentTrack: ProductTrack =
    screen === "mode" ? flowTrack : homeTrack === "selector" ? "handshake" : homeTrack;
  const visibleModes =
    homeTrack === "ethersync" ? ETHERSYNC_FLOW_MODES : HANDSHAKE_FLOW_MODES;

  useEffect(() => {
    setShowAdvanced(false);
  }, [flowMode]);

  useEffect(() => {
    const handshakeClass = "theme-handshake";
    const ethersyncClass = "theme-ethersync";
    document.body.classList.remove(handshakeClass, ethersyncClass);
    document.body.classList.add(currentTrack === "ethersync" ? ethersyncClass : handshakeClass);
    return () => {
      document.body.classList.remove(handshakeClass, ethersyncClass);
    };
  }, [currentTrack]);

  const universeId = useMemo(() => {
    if (!setPassResult) return "";
    const tag16 = setPassResult.tag16.toString(16).padStart(4, "0").toUpperCase();
    if (typeof setPassResult.tag8 === "number") {
      const tag8 = setPassResult.tag8.toString(16).padStart(2, "0").toUpperCase();
      return `HS-${tag16}-${tag8}`;
    }
    return `HS-${tag16}`;
  }, [setPassResult]);

  const wizardSteps = FLOW_STEPS[flowMode];
  const wizardIndex = useMemo(() => {
    if (!daemonStatus.running) return 0;

    switch (flowMode) {
      case "classic":
        if (!passphrase.trim()) return 1;
        if (!connectAttempted) return 2;
        return 3;
      case "offer":
        if (!passphrase.trim()) return 1;
        if (!offerResult) return 2;
        if (!connectAttempted) return 3;
        return 3;
      case "hybrid":
        if (!passphrase.trim()) return 1;
        if (!hybridQrResult) return 2;
        if (!connectAttempted) return 3;
        return 3;
      case "target":
        if (!passphrase.trim()) return 1;
        if (!classicTarget.trim()) return 2;
        if (!connectAttempted) return 3;
        return 3;
      case "phrase":
        if (!phraseInvite.trim()) return 1;
        if (!joinInvite.trim()) return 2;
        if (!connectAttempted) return 3;
        return 3;
      case "guaranteed":
        if (!guaranteedPassphrase.trim()) return 1;
        if (!guaranteedEgress.trim()) return 2;
        if (!connectAttempted) return 3;
        return 3;
      case "space":
        if (!spaceStatus?.running) return 1;
        if (!spaceJoinedId) return 2;
        if (spaceEvents.length === 0) return 3;
        return 3;
      default:
        return 0;
    }
  }, [
    daemonStatus.running,
    flowMode,
    passphrase,
    connectAttempted,
    offerResult,
    hybridQrResult,
    classicTarget,
    phraseInvite,
    joinInvite,
    guaranteedPassphrase,
    guaranteedEgress,
    spaceStatus,
    spaceJoinedId,
    spaceEvents
  ]);

  const nextGuidedStep = wizardSteps[Math.min(wizardIndex, wizardSteps.length - 1)] ?? "Review flow state";
  const isConnected = connectStatus?.status === "connected";
  const phaseLabels = ["Derive", "Offer", "Dial", "Noise", "Ready"];
  const phaseState = useMemo<PhaseState[]>(() => {
    const status = (connectStatus?.status || "").toLowerCase();
    const dial = status === "connecting" || status === "connected";
    const noise = status === "connecting" || status === "connected";
    const ready = status === "connected";
    const offer = Boolean(offerResult) || Boolean(phraseInvite) || connectAttempted;
    const derive =
      Boolean(setPassResult) ||
      passphrase.trim().length > 0 ||
      phrasePassphrase.trim().length > 0;
    const flags = [derive, offer, dial, noise, ready];
    const activeIndex = flags.findIndex((f) => !f);
    return flags.map((done, idx) => {
      if (done && idx < (activeIndex === -1 ? flags.length : activeIndex)) return "done";
      if (idx === (activeIndex === -1 ? flags.length - 1 : activeIndex)) return "active";
      return "pending";
    });
  }, [
    connectStatus,
    offerResult,
    phraseInvite,
    connectAttempted,
    setPassResult,
    passphrase,
    phrasePassphrase
  ]);

  const phraseStats = useMemo(() => {
    const text = phrasePassphrase;
    const chars = text.length;
    const lines = text.length ? text.split("\n").length : 0;
    return { chars, lines };
  }, [phrasePassphrase]);

  const parsedSpaceChunkSize = Number(spaceChunkSize);
  const spaceChunkSizeValid =
    !spaceChunkSize.trim() ||
    (Number.isInteger(parsedSpaceChunkSize) &&
      parsedSpaceChunkSize >= SPACE_CHUNK_SIZE_MIN &&
      parsedSpaceChunkSize <= SPACE_CHUNK_SIZE_MAX);
  const spaceChunkSizeEffective = spaceChunkSize.trim()
    ? parsedSpaceChunkSize
    : SPACE_CHUNK_SIZE_DEFAULT;

  const spaceTransferList = useMemo(() => {
    return (Object.values(spaceIncomingFiles) as Array<(typeof spaceIncomingFiles)[string]>)
      .map((transfer) => {
        const received = Object.keys(transfer.chunks).length;
        const progress_pct =
          transfer.total_chunks > 0 ? Math.min(100, Math.round((received / transfer.total_chunks) * 100)) : 0;
        return {
          ...transfer,
          received,
          complete: received >= transfer.total_chunks,
          progress_pct
        };
      })
      .sort((a, b) => b.updated_at_ms - a.updated_at_ms);
  }, [spaceIncomingFiles]);

  const spaceMessageList = useMemo(() => {
    return spaceEvents.filter((evt) => evt.kind === "space_message" && evt.text).slice(0, 25);
  }, [spaceEvents]);

  const phases = phaseLabels.map((label, idx) => ({
    label,
    state: phaseState[idx]
  }));

  const warningBanner =
    warning ||
    (apiBind.startsWith("0.0.0.0") && unsafeExpose
      ? "API exposed: restrict network access and keep the token private."
      : null);

  const usesClassicPass =
    flowMode === "classic" ||
    flowMode === "offer" ||
    flowMode === "hybrid" ||
    flowMode === "target";
  const tokenReady = Boolean(token);
  const apiReady = daemonStatus.running && tokenReady;
  const canSpaceStartAndJoin =
    apiReady && spacePassphrase.trim().length > 0 && (spaceStatus?.running || spaceBindAddr.trim().length > 0);
  const canSpacePublishFile =
    apiReady &&
    Boolean(spaceStatus?.running) &&
    spacePassphrase.trim().length > 0 &&
    Boolean(spaceFileB64) &&
    spaceChunkSizeValid;
  const canSetPassphrase = passphrase.trim().length > 0 && apiReady;
  const canStartAuto = passphrase.trim().length > 0;
  const allowAdvanced =
    (flowMode === "space" && wizardIndex >= 3) || (flowMode !== "space" && isConnected);
  const showDaemonStep = wizardIndex === 0;
  const showPassphraseStep = usesClassicPass && wizardIndex === 1;
  const showClassicFlow = flowMode === "classic" && wizardIndex >= 2 && !isConnected;
  const showOfferFlow = flowMode === "offer" && wizardIndex >= 2 && !isConnected;
  const showHybridFlow = flowMode === "hybrid" && wizardIndex >= 2 && !isConnected;
  const showTargetFlow = flowMode === "target" && wizardIndex >= 2 && !isConnected;
  const showPhraseFlow = flowMode === "phrase" && wizardIndex >= 1 && !isConnected;
  const showGuaranteedFlow = flowMode === "guaranteed" && wizardIndex >= 1 && !isConnected;
  const showSpaceFlow = flowMode === "space" && wizardIndex >= 1;
  const showConnectionStatus = flowMode !== "space" && isConnected;
  const daemonPortBusy =
    `${warning ?? ""} ${daemonStatus.last_error ?? ""}`.toLowerCase().includes("10048") ||
    `${warning ?? ""} ${daemonStatus.last_error ?? ""}`
      .toLowerCase()
      .includes("address already in use") ||
    `${warning ?? ""} ${daemonStatus.last_error ?? ""}`
      .toLowerCase()
      .includes("indirizzo di socket");

  const tokenStatus = token ? "token loaded" : "token missing";
  const daemonLabel = daemonStatus.running
    ? externalDaemonAttached
      ? "running (attached)"
      : `running pid ${daemonStatus.pid ?? "?"}`
    : "stopped";
  const statusLabel = `${daemonLabel} | ${apiBind} | ${tokenStatus} | SSE ${sseState}`;
  const productLabel = currentTrack === "ethersync" ? "ETHERSYNC" : "HANDSHAKE";
  const mark = (ok: boolean) => (ok ? "[x]" : "[ ]");
  const selectTrack = (track: ProductTrack) => {
    setHomeTrack(track);
  };
  const resetTrackSelector = () => setHomeTrack("selector");
  const selectMode = (mode: FlowMode) => {
    setHomeTrack(mode === "space" ? "ethersync" : "handshake");
    setFlowMode(mode);
    setScreen("mode");
    setShowAdvanced(false);
    setConnectAttempted(false);
  };

  useEffect(() => {
    if (!allowAdvanced) {
      setShowAdvanced(false);
    }
  }, [allowAdvanced]);

  return (
    <div
      className={`app ${currentTrack === "ethersync" ? "app-track-ethersync" : "app-track-handshake"}`}
    >
      <TopBar statusLabel={statusLabel} universeId={universeId} brandLabel={productLabel} />
      {warningBanner && <div className="banner">{warningBanner}</div>}

      {screen === "home" ? (
        <div className="home">
          {homeTrack === "selector" ? (
            <>
              <div className="hero hero-entry">
                <h1>OUROBOROS</h1>
              </div>
              <div className="track-grid">
                <div className="track-card track-card-handshake" onClick={() => selectTrack("handshake")}>
                  <div className="track-label">A</div>
                  <div className="mode-title">Handshake Matrix</div>
                  <div className="mode-desc">
                    Tutti i flow di connessione (classic/offer/hybrid/target/phrase/guaranteed)
                    con routing aggressivo.
                  </div>
                  <button type="button" className="mode-cta">Open Handshake</button>
                </div>
                <div className="track-card track-card-ethersync" onClick={() => selectTrack("ethersync")}>
                  <div className="track-label">B</div>
                  <div className="mode-title">EtherSync Gold</div>
                  <div className="mode-desc">
                    Workspace realtime dedicato a space, messaggi e file chunked con UX separata.
                  </div>
                  <button type="button" className="mode-cta">Open EtherSync</button>
                </div>
              </div>
            </>
          ) : (
            <>
              <div className="page-header">
                <button type="button" className="secondary" onClick={resetTrackSelector}>
                  Switch product
                </button>
                <div>
                  <div className="page-title">
                    {homeTrack === "handshake" ? "Handshake Flows" : "EtherSync Flows"}
                  </div>
                  <div className="page-subtitle">
                    {homeTrack === "handshake"
                      ? "Modalita guidate per pairing e connessione resilienti."
                      : "Modalita guidata space-first per collaborazione e sincronizzazione."}
                  </div>
                </div>
              </div>
              <div className="mode-grid">
                {visibleModes.map((mode) => (
                  <div key={mode} className="mode-card" onClick={() => selectMode(mode)}>
                    <div className="mode-title">{FLOW_LABELS[mode]}</div>
                    <div className="mode-desc">{FLOW_DESC[mode]}</div>
                    <ul className="mode-steps">
                      {FLOW_STEPS[mode].map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ul>
                    <button type="button" className="mode-cta">Open</button>
                  </div>
                ))}
              </div>
            </>
          )}
          <div className="panel">
            <h2>System Status</h2>
            <div style={{ fontSize: 13 }}>
              {connectStatus ? (
                <div>
                  status: {connectStatus.status}
                  <br />
                  mode: {connectStatus.mode}
                  <br />
                  port: {connectStatus.port ?? "-"}
                  <br />
                  peer: {connectStatus.peer ?? "-"}
                </div>
              ) : (
                "No status"
              )}
            </div>
            <div style={{ marginTop: 10, fontSize: 12 }}>
              daemon error: {daemonStatus.last_error ?? "-"}
              <br />
              daemon exit: {daemonStatus.last_exit_code ?? "-"}
            </div>
          </div>
        </div>
      ) : (
        <>
          <div className="page-header">
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <button type="button" className="secondary" onClick={() => setScreen("home")}>Back to flows</button>
              <span className="status-pill">
                Step {Math.min(wizardIndex + 1, wizardSteps.length)}/{wizardSteps.length}
              </span>
              {allowAdvanced && (
                <button type="button" className="secondary" onClick={() => setShowAdvanced((v) => !v)}>
                  {showAdvanced ? "Hide advanced" : "Show advanced"}
                </button>
              )}
            </div>
            <div>
              <div className="page-title">{FLOW_LABELS[flowMode]}</div>
              <div className="page-subtitle">{FLOW_DESC[flowMode]}</div>
            </div>
          </div>

          <WizardSteps steps={wizardSteps} activeIndex={wizardIndex} />
          <PhaseBar phases={phases} />

          <div className="panel guided-panel">
            <h2>Guided Next Step</h2>
            <div className="helper-text">Flow corrente: {FLOW_LABELS[flowMode]}</div>
            <div className="guided-next">{nextGuidedStep}</div>
          </div>

          <div className={`panel ${showDaemonStep ? "daemon-live-panel" : "mini-debug-panel"}`}>
            <h2>Live Daemon Debug (RAM)</h2>
            <div className="helper-text">Output stdout/stderr live dal sidecar handshacke.</div>
            <div className={`console ${showDaemonStep ? "daemon-live-console" : "mini-debug-console"}`} style={{ marginTop: 10 }}>
              {daemonLiveLines.length === 0 ? (
                <div className="console-line">No daemon logs yet</div>
              ) : (
                daemonLiveLines.map((line, idx) => (
                  <div key={`${idx}-${line.slice(0, 18)}`} className="console-line">
                    <span>{line}</span>
                  </div>
                ))
              )}
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
              <button type="button" className="secondary" onClick={() => void pullDaemonLogsLive(true)}>
                Refresh logs
              </button>
              <button type="button" className="secondary" onClick={() => setDaemonLiveLines([])}>
                Clear view
              </button>
            </div>
          </div>

          <div className="grid guided-grid">
            {showDaemonStep && (
              <div className="panel step-panel">
                <h2>Step 1: Daemon lifecycle</h2>
                <label htmlFor="bind">API bind</label>
                <input
                  id="bind"
                  value={apiBind}
                  onChange={(e) => setApiBind(e.target.value)}
                />

                <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                  <button type="button" onClick={handleStartDaemon} disabled={daemonStatus.running}>
                    Start daemon
                  </button>
                  <button
                    type="button"
                    className="secondary"
                    onClick={handleStopDaemon}
                    disabled={!daemonStatus.running}
                  >
                    Stop daemon
                  </button>
                  <button type="button" className="secondary" onClick={handleReclaimPort}>
                    Force reclaim port
                  </button>
                </div>

                {daemonPortBusy && (
                  <div className="helper-text" style={{ marginTop: 10, color: "var(--warn)" }}>
                    Porta occupata rilevata. Fai reconnect al daemon gia attivo oppure forzane lo stop.
                  </div>
                )}

                <label style={{ marginTop: 12, display: "block" }}>
                  <input
                    type="checkbox"
                    checked={unsafeExpose}
                    onChange={(e) => setUnsafeExpose(e.target.checked)}
                  />
                  &nbsp;Allow unsafe expose
                </label>

                <label htmlFor="attach-token" style={{ marginTop: 12, display: "block" }}>
                  Reconnect token (daemon gia attivo)
                </label>
                <input
                  id="attach-token"
                  value={attachTokenInput}
                  onChange={(e) => setAttachTokenInput(e.target.value)}
                  placeholder="Bearer token del daemon esistente"
                />

                <div style={{ marginTop: 12, fontSize: 12 }}>
                  Token: {token ? "loaded" : "missing"}
                  {externalDaemonAttached ? " (attached external daemon)" : ""}
                </div>

                <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                  <button type="button" className="secondary" onClick={handleAttachDaemon}>
                    Reconnect existing daemon
                  </button>
                  <button type="button" className="secondary" onClick={handleFetchDaemonLogs}>
                    Fetch daemon logs
                  </button>
                </div>

                <div className="helper-text">Completa questo step per sbloccare il successivo.</div>
              </div>
            )}

            {showAdvanced && allowAdvanced && (
              <div className="panel">
                <h2>Advanced Settings</h2>
              <div className="field-block">
                <div className="field-label">Pluggable profile</div>
                <div className="mode-row">
                  {PLUGGABLE_PROFILES.map((profile) => (
                    <div
                      key={profile}
                      className={`mode-pill ${pluggableProfile === profile ? "active" : ""}`}
                      onClick={() => setPluggableProfile(profile)}
                    >
                      {profile}
                    </div>
                  ))}
                </div>
              </div>
              <div className="field-block">
                <div className="field-label">Pluggable transport</div>
                <div className="mode-row">
                  {PLUGGABLE_TRANSPORTS.map((pt) => (
                    <div
                      key={pt}
                      className={`mode-pill ${pluggableTransport === pt ? "active" : ""}`}
                      onClick={() => setPluggableTransport(pt)}
                    >
                      {pt}
                    </div>
                  ))}
                </div>
              </div>
              <input
                placeholder="RealTLS domain (optional)"
                value={realTlsDomain}
                onChange={(e) => setRealTlsDomain(e.target.value)}
              />
              <div className="helper-text">RealTLS overrides pluggable transport. In stable profile, experimental transports are blocked.</div>
              <div className="field-block">
                <div className="field-label">Stealth mode</div>
                <div className="mode-row">
                  {STEALTH_MODES.map((mode) => (
                    <div
                      key={mode}
                      className={`mode-pill ${stealthMode === mode ? "active" : ""}`}
                      onClick={() => setStealthMode(mode)}
                    >
                      {mode}
                    </div>
                  ))}
                </div>
              </div>
              <textarea
                rows={2}
                placeholder="Assist relays (comma-separated, max 5)"
                value={assistRelays}
                onChange={(e) => setAssistRelays(e.target.value)}
              />
              <input
                placeholder="Tor SOCKS address (host:port)"
                value={torSocksAddr}
                onChange={(e) => setTorSocksAddr(e.target.value)}
              />
              <input
                placeholder="Tor onion address (client target)"
                value={torOnionAddr}
                onChange={(e) => setTorOnionAddr(e.target.value)}
              />
                <div className="helper-text">Restart daemon to apply changes.</div>
              </div>
            )}

            {showPassphraseStep && (
              <div className="panel">
                <h2>Passphrase (Classic/Offer/Target)</h2>
                <input
                  type={showPassphrase ? "text" : "password"}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
                {!apiReady && (
                  <div className="helper-text">Start daemon and load token before setting.</div>
                )}
                <div className="universe-note">
                  Universe ID: {universeId || "HS-UNSET"}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                  <button type="button" className="secondary" onClick={() => setShowPassphrase((v) => !v)}>
                    {showPassphrase ? "Hide" : "Show"}
                  </button>
                  <button type="button" onClick={handleSetPassphrase} disabled={!canSetPassphrase}>
                    Set
                  </button>
                </div>
                {setPassResult && (
                  <div style={{ marginTop: 12, fontSize: 12 }}>
                    port={setPassResult.port} tag16={setPassResult.tag16}
                    {typeof setPassResult.tag8 === "number"
                      ? ` tag8=${setPassResult.tag8}`
                      : ""}
                  </div>
                )}
              </div>
            )}

        {showClassicFlow && (
          <div className="panel">
            <h2>Classic Cascade</h2>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${connectAttempted ? "done" : ""}`}>
                {mark(connectAttempted)} Connect attempted
              </div>
            </div>
            <ol className="flow-steps">
              <li>Enter passphrase and press Set</li>
              <li>Select WAN mode + Tor role</li>
              <li>Connect (LAN to WAN to Assist to Tor fallback)</li>
            </ol>
            <div className="field-block">
              <div className="field-label">Local role</div>
              <div className="mode-row">
                {ROLE_OPTIONS.map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${localRole === r ? "active" : ""}`}
                    onClick={() => setLocalRole(r)}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            <div className="field-block">
              <div className="field-label">WAN mode</div>
              <div className="mode-row">
                {WAN_MODES.map((m) => (
                  <div
                    key={m}
                    className={`mode-pill ${wanMode === m ? "active" : ""}`}
                    onClick={() => setWanMode(m)}
                  >
                    {m}
                  </div>
                ))}
              </div>
            </div>
            <div className="field-block">
              <div className="field-label">Tor role</div>
              <div className="mode-row">
                {TOR_ROLES.map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${torRole === r ? "active" : ""}`}
                    onClick={() => setTorRole(r)}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            {(wanMode === "tor" || wanMode === "auto") && torRole === "client" && (
              <input
                placeholder="target_onion (required for Tor client)"
                value={targetOnion}
                onChange={(e) => setTargetOnion(e.target.value)}
              />
            )}
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button type="button" onClick={handleConnectCascade} disabled={!passphrase.trim() || !apiReady}>
                Connect cascade
              </button>
              <button type="button" onClick={handleStartAuto} className="secondary" disabled={!canStartAuto}>
                Quick start
              </button>
            </div>
          </div>
        )}

        {showOfferFlow && (
          <div className="panel">
            <h2>Offer QR</h2>
            <div className="helper-text">
              The QR is a rendezvous envelope (endpoints + timing). It does NOT contain your
              passphrase. Use it for fast pairing without typing addresses.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${offerResult ? "done" : ""}`}>
                {mark(Boolean(offerResult))} Offer generated
              </div>
            </div>
            <ol className="flow-steps">
              <li>Host generates offer (QR)</li>
              <li>Client scans offer</li>
              <li>Client connects via offer</li>
            </ol>
            <div className="field-block">
              <div className="field-label">Role hint (host)</div>
              <div className="mode-row">
                {["host", "client"].map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${offerRoleHint === r ? "active" : ""}`}
                    onClick={() => setOfferRoleHint(r as "host" | "client")}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            <label style={{ display: "block", marginBottom: 6 }}>
              <input
                type="checkbox"
                checked={includeTorOffer}
                onChange={(e) => setIncludeTorOffer(e.target.checked)}
              />
              &nbsp;Include Tor endpoint
            </label>
            <input
              placeholder="TTL seconds (optional)"
              value={offerTtl}
              onChange={(e) => setOfferTtl(e.target.value)}
            />
            <div className="qr-box" style={{ marginTop: 12 }}>
              <button type="button" onClick={handleOffer} disabled={!apiReady || !passphrase.trim()}>
                Generate offer QR
              </button>
              {offerQr && <img src={offerQr} alt="offer qr" />}
              {offerResult && <textarea rows={4} value={offerResult.offer} readOnly />}
              {offerResult && (
                <div className="helper-text">
                  Expires in {formatTtl(offerResult.expires_at_ms)}. Endpoints:{" "}
                  {offerResult.endpoints.join(", ")}
                </div>
              )}
              {offerResult && (
                <div style={{ display: "flex", gap: 8 }}>
                  <button type="button"
                    className="secondary"
                    onClick={() => navigator.clipboard.writeText(offerResult.offer)}
                  >
                    Copy
                  </button>
                  <button type="button" className="secondary" onClick={handleOffer}>
                    Regenerate
                  </button>
                </div>
              )}
            </div>
            <div style={{ marginTop: 12 }}>
              <input
                placeholder="paste offer"
                value={classicOffer}
                onChange={(e) => setClassicOffer(e.target.value)}
              />
              <div className="field-block">
                <div className="field-label">Local role (client)</div>
                <div className="mode-row">
                  {["host", "client"].map((r) => (
                    <div
                      key={r}
                      className={`mode-pill ${offerLocalRole === r ? "active" : ""}`}
                      onClick={() => setOfferLocalRole(r as "host" | "client")}
                    >
                      {r}
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button type="button" className="secondary" onClick={() => setClassicOffer("")}>
                  Clear offer
                </button>
                <button type="button" onClick={handleConnectOffer} disabled={!apiReady || !classicOffer.trim()}>
                  Connect via offer
                </button>
              </div>
            </div>
          </div>
        )}

        {showHybridFlow && (
          <div className="panel">
            <h2>Hybrid QR (Resume + Fallback)</h2>
            <div className="helper-text">
              Hybrid QR adds a resume token for fast re-join while keeping the deterministic
              fallback offer inside. This is the most robust QR flow.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${hybridQrResult ? "done" : ""}`}>
                {mark(Boolean(hybridQrResult))} Hybrid QR generated
              </div>
            </div>
            <ol className="flow-steps">
              <li>Host generates Hybrid QR</li>
              <li>Client scans QR</li>
              <li>Client connects (resume if possible, fallback otherwise)</li>
            </ol>
            <div className="field-block">
              <div className="field-label">Role hint (host)</div>
              <div className="mode-row">
                {["host", "client"].map((r) => (
                  <div
                    key={r}
                    className={`mode-pill ${hybridRoleHint === r ? "active" : ""}`}
                    onClick={() => setHybridRoleHint(r as "host" | "client")}
                  >
                    {r}
                  </div>
                ))}
              </div>
            </div>
            <label style={{ display: "block", marginBottom: 6 }}>
              <input
                type="checkbox"
                checked={hybridIncludeTor}
                onChange={(e) => setHybridIncludeTor(e.target.checked)}
              />
              &nbsp;Include Tor endpoint
            </label>
            <div className="field-block">
              <div className="field-label">QR TTL (seconds)</div>
              <input
                placeholder="QR TTL seconds (optional)"
                value={hybridQrTtl}
                onChange={(e) => setHybridQrTtl(e.target.value)}
              />
            </div>
            <div className="field-block">
              <div className="field-label">Resume TTL (seconds)</div>
              <input
                placeholder="Resume TTL seconds (optional)"
                value={hybridResumeTtl}
                onChange={(e) => setHybridResumeTtl(e.target.value)}
              />
            </div>
            <textarea
              rows={2}
              placeholder="Relay hints (comma-separated)"
              value={hybridRelayHints}
              onChange={(e) => setHybridRelayHints(e.target.value)}
            />
            <div className="qr-box" style={{ marginTop: 12 }}>
              <button type="button" onClick={handleHybridQr} disabled={!apiReady || !passphrase.trim()}>
                Generate hybrid QR
              </button>
              {hybridQrImage && <img src={hybridQrImage} alt="hybrid qr" />}
              {hybridQrResult && <textarea rows={4} value={hybridQrResult.qr} readOnly />}
              {hybridQrResult && (
                <div className="helper-text">
                  QR expires in {formatTtl(hybridQrResult.expires_at_ms)}. Resume expires in{" "}
                  {formatTtl(hybridQrResult.resume_expires_at_ms)}. Endpoints:{" "}
                  {hybridQrResult.endpoints.join(", ")}
                </div>
              )}
              {hybridQrResult && (
                <div style={{ display: "flex", gap: 8 }}>
                  <button type="button"
                    className="secondary"
                    onClick={() => navigator.clipboard.writeText(hybridQrResult.qr)}
                  >
                    Copy QR
                  </button>
                  <button type="button" className="secondary" onClick={handleHybridQr}>
                    Regenerate
                  </button>
                </div>
              )}
            </div>
            <div style={{ marginTop: 12 }}>
              <input
                placeholder="paste hybrid QR"
                value={hybridQrInput}
                onChange={(e) => setHybridQrInput(e.target.value)}
              />
              <div className="field-block">
                <div className="field-label">Local role (client)</div>
                <div className="mode-row">
                  {["host", "client"].map((r) => (
                    <div
                      key={r}
                      className={`mode-pill ${hybridLocalRole === r ? "active" : ""}`}
                      onClick={() => setHybridLocalRole(r as "host" | "client")}
                    >
                      {r}
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button type="button" className="secondary" onClick={() => setHybridQrInput("")}>
                  Clear QR
                </button>
                <button type="button"
                  onClick={handleConnectHybridQr}
                  disabled={!apiReady || !hybridQrInput.trim()}
                >
                  Connect via QR
                </button>
              </div>
            </div>
          </div>
        )}

        {showTargetFlow && (
          <div className="panel">
            <h2>Target Direct</h2>
            <div className="helper-text">
              Direct target is fragile behind NAT/firewall. If this fails, prefer Offer/Hybrid QR
              with Tor relay.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${passphrase.trim() ? "done" : ""}`}>
                {mark(passphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${classicTarget.trim() ? "done" : ""}`}>
                {mark(classicTarget.trim().length > 0)} Target filled
              </div>
            </div>
            <ol className="flow-steps">
              <li>Enter passphrase and press Set</li>
              <li>Enter target address</li>
              <li>Connect directly</li>
            </ol>
            <input
              placeholder="target ip:port or onion:port"
              value={classicTarget}
              onChange={(e) => setClassicTarget(e.target.value)}
            />
            <label style={{ display: "block", marginTop: 8 }}>
              <input
                type="checkbox"
                checked={targetIsOnion}
                onChange={(e) => setTargetIsOnion(e.target.checked)}
              />
              &nbsp;Target is .onion (use Tor)
            </label>
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button type="button" className="secondary" onClick={() => setClassicTarget("")}>
                Clear target
              </button>
              <button type="button"
                onClick={handleConnectTarget}
                disabled={!apiReady || !passphrase.trim() || !classicTarget.trim()}
              >
                Connect via target
              </button>
            </div>
          </div>
        )}

        {showPhraseFlow && (
          <div className="panel">
            <h2>Easy Tor (Phrase)</h2>
            <div className="helper-text">
              The QR invite does NOT include the passphrase. Share the QR and send the passphrase
              privately.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${phrasePassphrase.trim() ? "done" : ""}`}>
                {mark(phrasePassphrase.trim().length > 0)} Passphrase set
              </div>
              <div className={`check-item ${phraseInvite ? "done" : ""}`}>
                {mark(Boolean(phraseInvite))} Invite generated
              </div>
            </div>
            <ol className="flow-steps">
              <li>Host opens phrase</li>
              <li>Share invite QR</li>
              <li>Client joins with passphrase</li>
            </ol>
            <textarea
              placeholder="Passphrase (private, not in QR)"
              rows={3}
              value={phrasePassphrase}
              onChange={(e) => setPhrasePassphrase(e.target.value)}
            />
            <div style={{ marginTop: 6, fontSize: 12 }}>
              {phraseStats.chars} chars / {phraseStats.lines} lines
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" onClick={handlePhraseOpen} disabled={!apiReady || !phrasePassphrase.trim()}>
                Open phrase
              </button>
              <button type="button" className="secondary" onClick={handlePasteTheme}>
                Paste
              </button>
              <button type="button" className="secondary" onClick={handlePhraseClose} disabled={!apiReady}>
                Close
              </button>
              <button type="button" className="secondary" onClick={() => setPhrasePassphrase("")}>
                Clear
              </button>
              <button type="button" className="secondary" onClick={refreshPhraseStatus} disabled={!apiReady}>
                Status
              </button>
            </div>
            <div style={{ marginTop: 10, fontSize: 12 }}>
              Status: {phraseStatus}
            </div>
            <div className="qr-box" style={{ marginTop: 12 }}>
              {phraseQr && <img src={phraseQr} alt="phrase qr" />}
              {phraseInvite && <textarea rows={4} value={phraseInvite} readOnly />}
              {phraseInvite && (
                <button type="button"
                  className="secondary"
                  onClick={() => navigator.clipboard.writeText(phraseInvite)}
                >
                  Copy invite
                </button>
              )}
            </div>
            <div style={{ marginTop: 12 }}>
              <input
                placeholder="paste invite"
                value={joinInvite}
                onChange={(e) => setJoinInvite(e.target.value)}
              />
              <button type="button" style={{ marginTop: 8 }} onClick={handlePhraseJoin} disabled={!apiReady}>
                Join phrase
              </button>
            </div>
          </div>
        )}

        {showGuaranteedFlow && (
          <div className="panel">
            <h2>Guaranteed Relay</h2>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${guaranteedPassphrase.trim() ? "done" : ""}`}>
                {mark(guaranteedPassphrase.trim().length > 0)} Passphrase set
              </div>
            </div>
            <ol className="flow-steps">
              <li>Enter passphrase</li>
              <li>Select egress (public/Tor)</li>
              <li>Connect via relay</li>
            </ol>
            <textarea
              placeholder="Passphrase"
              rows={2}
              value={guaranteedPassphrase}
              onChange={(e) => setGuaranteedPassphrase(e.target.value)}
            />
            <input
              placeholder="Relay URL (optional)"
              value={guaranteedRelayUrl}
              onChange={(e) => setGuaranteedRelayUrl(e.target.value)}
            />
            <div className="field-block">
              <div className="field-label">Egress</div>
              <div className="mode-row">
                {GUARANTEED_EGRESS.map((eg) => (
                  <div
                    key={eg}
                    className={`mode-pill ${guaranteedEgress === eg ? "active" : ""}`}
                    onClick={() => setGuaranteedEgress(eg)}
                  >
                    {eg}
                  </div>
                ))}
              </div>
            </div>
            <button type="button"
              onClick={handleConnectGuaranteed}
              disabled={!apiReady || !guaranteedPassphrase.trim()}
            >
              Connect guaranteed
            </button>
          </div>
        )}

        {showSpaceFlow && (
          <div className="panel step-panel space-panel">
            <h2>EtherSync Space</h2>
            <div className="space-focus">
              <div className="space-focus-id">SPACE ID: {spaceJoinedId || "NOT JOINED"}</div>
              <div className="space-focus-meta">
                node: {spaceStatus?.local_addr ?? "-"} | peers: {spaceStatus?.peer_count ?? 0} | stream: {spaceSseState}
              </div>
            </div>
            <div className="helper-text">
              Start the EtherSync node, join a space with a passphrase, then publish messages.
            </div>
            <div className="checklist">
              <div className={`check-item ${apiReady ? "done" : ""}`}>
                {mark(apiReady)} Daemon running + token loaded
              </div>
              <div className={`check-item ${spaceStatus?.running ? "done" : ""}`}>
                {mark(Boolean(spaceStatus?.running))} EtherSync node running
              </div>
              <div className={`check-item ${spaceJoinedId ? "done" : ""}`}>
                {mark(Boolean(spaceJoinedId))} Space joined
              </div>
            </div>
            <ol className="flow-steps">
              <li>Start EtherSync node</li>
              <li>Add peers (optional)</li>
              <li>Join a space passphrase</li>
              <li>Publish and monitor events</li>
            </ol>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
              <button type="button" onClick={handleSpaceStartAndJoin} disabled={!canSpaceStartAndJoin}>
                Start + Join
              </button>
              <button type="button"
                className="secondary"
                onClick={() => setSpacePassphrase(passphrase)}
                disabled={!passphrase.trim()}
              >
                Use main passphrase
              </button>
              <button type="button"
                className="secondary"
                onClick={() => copyToClipboard(spaceStatus?.local_addr ?? "", "local addr")}
                disabled={!spaceStatus?.local_addr}
              >
                Copy local addr
              </button>
              <button type="button"
                className="secondary"
                onClick={() => copyToClipboard(spaceJoinedId, "space id")}
                disabled={!spaceJoinedId}
              >
                Copy space id
              </button>
            </div>

            <div className="field-block">
              <div className="field-label">Node bind address</div>
              <input
                placeholder="0.0.0.0:0"
                value={spaceBindAddr}
                onChange={(e) => setSpaceBindAddr(e.target.value)}
              />
            </div>
            <div className="field-block">
              <div className="field-label">Bootstrap peers (comma-separated)</div>
              <input
                placeholder="203.0.113.10:4567,198.51.100.20:4567"
                value={spaceBootstrapPeers}
                onChange={(e) => setSpaceBootstrapPeers(e.target.value)}
              />
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button type="button" onClick={handleSpaceStart} disabled={!apiReady}>
                Start EtherSync node
              </button>
              <button type="button" className="secondary" onClick={handleSpaceStop} disabled={!apiReady}>
                Stop node
              </button>
              <button type="button" className="secondary" onClick={handleSpaceStatus} disabled={!apiReady}>
                Refresh
              </button>
            </div>

            <div style={{ marginTop: 10, fontSize: 12 }}>
              running: {String(spaceStatus?.running ?? false)}
              <br />
              bind: {spaceStatus?.bind_addr ?? "-"}
              <br />
              local: {spaceStatus?.local_addr ?? "-"}
              <br />
              peers: {spaceStatus?.peer_count ?? 0} | subscriptions:{" "}
              {spaceStatus?.subscription_count ?? 0}
              <br />
              spaces: {(spaceStatus?.spaces ?? []).join(", ") || "-"}
              <br />
              events stream: {spaceSseState}
            </div>

            <div className="field-block" style={{ marginTop: 12 }}>
              <div className="field-label">Add peer</div>
              <input
                placeholder="198.51.100.20:4567"
                value={spacePeerToAdd}
                onChange={(e) => setSpacePeerToAdd(e.target.value)}
              />
              <button type="button"
                style={{ marginTop: 8 }}
                className="secondary"
                onClick={handleSpaceAddPeer}
                disabled={!apiReady || !spacePeerToAdd.trim()}
              >
                Add peer
              </button>
            </div>

            <div className="field-block" style={{ marginTop: 12 }}>
              <div className="field-label">Join space</div>
              <textarea
                rows={2}
                placeholder="Space passphrase"
                value={spacePassphrase}
                onChange={(e) => setSpacePassphrase(e.target.value)}
              />
              <input
                placeholder="Label (optional)"
                value={spaceLabel}
                onChange={(e) => setSpaceLabel(e.target.value)}
              />
              <div className="helper-text">
                Keep this passphrase private: anyone with it can join the same space.
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                <button type="button"
                  onClick={handleSpaceJoin}
                  disabled={!apiReady || !spaceStatus?.running || !spacePassphrase.trim()}
                >
                  Join space
                </button>
                <button type="button" className="secondary" onClick={() => setSpaceEvents([])}>
                  Clear events
                </button>
              </div>
              <div style={{ marginTop: 8, fontSize: 12 }}>
                joined space: {spaceJoinedId || "-"}
              </div>
            </div>

            <div className="field-block" style={{ marginTop: 12 }}>
              <div className="field-label">Publish message</div>
              <textarea
                rows={3}
                placeholder="Write a message to publish in this space"
                value={spaceMessage}
                onChange={(e) => setSpaceMessage(e.target.value)}
              />
              <button type="button"
                style={{ marginTop: 8 }}
                onClick={handleSpacePublish}
                disabled={!apiReady || !spacePassphrase.trim() || !spaceMessage.trim()}
              >
                Publish
              </button>
            </div>

            <div className="field-block" style={{ marginTop: 12 }}>
              <div className="field-label">Publish file (chunked)</div>
              <input
                type="file"
                onChange={handleSpaceFileSelected}
                disabled={!apiReady || !spaceStatus?.running}
              />
              <input
                placeholder="Chunk size bytes (default 1024)"
                value={spaceChunkSize}
                onChange={(e) => setSpaceChunkSize(e.target.value)}
              />
              <div className="helper-text">
                chunk size: {spaceChunkSize.trim() ? spaceChunkSizeEffective : SPACE_CHUNK_SIZE_DEFAULT} bytes
                (allowed {SPACE_CHUNK_SIZE_MIN}-{SPACE_CHUNK_SIZE_MAX})
              </div>
              {!spaceChunkSizeValid && (
                <div className="warning-text">
                  Chunk size must be an integer between {SPACE_CHUNK_SIZE_MIN} and {SPACE_CHUNK_SIZE_MAX}.
                </div>
              )}
              <div style={{ marginTop: 8, fontSize: 12 }}>
                file: {spaceFileName || "-"} | size: {spaceFileSize || 0} bytes
              </div>
              <button type="button"
                style={{ marginTop: 8 }}
                onClick={handleSpacePublishFile}
                disabled={!canSpacePublishFile}
              >
                Publish file
              </button>
            </div>

            <div className="field-block" style={{ marginTop: 12 }}>
              <div className="field-label">Received files</div>
              <button type="button"
                className="secondary"
                onClick={() => setSpaceIncomingFiles({})}
                disabled={spaceTransferList.length === 0}
              >
                Clear received files
              </button>
              {spaceTransferList.length === 0 ? (
                <div className="helper-text">No file transfers received yet.</div>
              ) : (
                spaceTransferList.map((transfer) => (
                  <div
                    key={transfer.transfer_id}
                    style={{
                      marginTop: 8,
                      marginBottom: 8,
                      padding: 10,
                      borderRadius: 10,
                      border: "1px solid rgba(0,255,154,0.18)",
                      background: "rgba(6,12,9,0.65)"
                    }}
                  >
                    <div style={{ fontSize: 12 }}>
                      {transfer.filename} | {transfer.total_bytes} bytes
                    </div>
                    <div style={{ marginTop: 4, fontSize: 12 }}>
                      chunks: {transfer.received}/{transfer.total_chunks} | {transfer.progress_pct}% |{" "}
                      {transfer.complete ? "ready" : "receiving"}
                    </div>
                    <div
                      style={{
                        marginTop: 6,
                        height: 6,
                        borderRadius: 999,
                        background: "rgba(0,255,154,0.12)",
                        overflow: "hidden"
                      }}
                    >
                      <div
                        style={{
                          width: `${transfer.progress_pct}%`,
                          height: "100%",
                          background: "var(--accent)",
                          transition: "width 0.15s ease"
                        }}
                      />
                    </div>
                    <button type="button"
                      style={{ marginTop: 8 }}
                      className="secondary"
                      onClick={() => handleSpaceDownloadTransfer(transfer.transfer_id)}
                      disabled={!transfer.complete}
                    >
                      Download
                    </button>
                  </div>
                ))
              )}
            </div>

            <div className="space-board">
              <div className="space-board-header">
                <div>
                  <div className="space-board-title">Space Board</div>
                  <div className="space-board-meta">
                    Live feed di messaggi + timeline eventi del nodo corrente
                  </div>
                </div>
                <div className="space-board-meta">
                  stream: {spaceSseState} | joined: {spaceJoinedId || "-"}
                </div>
              </div>

              <div className="space-board-grid">
                <div className="space-board-column">
                  <div className="space-board-column-head">Messages</div>
                  <div className="space-message-feed">
                    {spaceMessageList.length === 0 ? (
                      <div className="space-placeholder">No text messages received yet.</div>
                    ) : (
                      spaceMessageList.map((evt, idx) => (
                        <div key={`${evt.ts_ms}-${idx}`} className="space-message-card">
                          <div className="space-message-top">
                            <span>{new Date(evt.ts_ms).toLocaleTimeString()}</span>
                            <span>{evt.space_id || spaceJoinedId || "space-unknown"}</span>
                          </div>
                          <div className="space-message-text">{evt.text}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="space-board-column">
                  <div className="space-board-column-head">Event timeline</div>
                  <div className="space-event-feed">
                    {spaceEvents.length === 0 ? (
                      <div className="space-placeholder">No EtherSync events yet.</div>
                    ) : (
                      spaceEvents.map((evt, idx) => (
                        <div key={`${evt.ts_ms}-${idx}`} className="space-event-card">
                          <div className="space-event-top">
                            <span className="space-event-kind">{evt.kind}</span>
                            <span>{new Date(evt.ts_ms).toLocaleTimeString()}</span>
                          </div>
                          <div className="space-event-meta">
                            {evt.space_id ? `space=${evt.space_id}` : ""}
                            {typeof evt.slot_id === "number" ? ` slot=${evt.slot_id}` : ""}
                            {evt.text ? ` text=${evt.text}` : ""}
                            {evt.info ? ` info=${evt.info}` : ""}
                            {evt.error ? ` error=${evt.error}` : ""}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {showConnectionStatus && (
          <div className="panel step-panel">
            <h2>Connected Session</h2>
          <div style={{ fontSize: 13 }}>
            {connectStatus ? (
              <div>
                status: {connectStatus.status}
                <br />
                mode: {connectStatus.mode}{" "}
                <span className={`badge badge-${modeBadge.tone}`}>{modeBadge.label}</span>
                <br />
                port: {connectStatus.port ?? "-"}
                <br />
                peer: {connectStatus.peer ?? "-"}
                <br />
                resume: {connectStatus.resume_status ?? "-"}
              </div>
            ) : (
              "No status"
            )}
          </div>
          {connectStatus?.mode === "wan_tcp" && (
            <div className="warning-text" style={{ marginTop: 8 }}>
              UDP blocked detected. TCP fallback active. For reliability, prefer Offer/Hybrid QR
              with Tor relay.
            </div>
          )}
          {connectStatus?.mode === "wan_tor" && (
            <div className="helper-text" style={{ marginTop: 8 }}>
              Tor/relay transport active. Stable but higher latency.
            </div>
          )}
          <div style={{ marginTop: 10, fontSize: 12 }}>
            daemon error: {daemonStatus.last_error ?? "-"}
            <br />
            daemon exit: {daemonStatus.last_exit_code ?? "-"}
          </div>
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button type="button" className="secondary" onClick={refreshStatus} disabled={!apiReady}>
                Refresh
              </button>
              <button type="button" className="secondary" onClick={() => setSseEnabled(true)} disabled={!apiReady}>
                Start SSE
              </button>
              <button type="button" className="secondary" onClick={() => setSseEnabled(false)} disabled={!apiReady}>
                Stop SSE
              </button>
            </div>
          </div>
        )}

        {showAdvanced && allowAdvanced && (
          <>
            <div className="panel">
              <h2>Network Diagnostics</h2>
          <div className="helper-text">
            This panel reflects live, RAM-only diagnostics. No data is persisted.
          </div>
          <div style={{ fontSize: 13, marginTop: 8 }}>
            {metrics ? (
              <div>
                health: {metrics.status} ({metrics.health_score}){" "}
                <span className={`badge badge-${healthBadge.tone}`}>{healthBadge.label}</span>
                <br />
                nat_type: {metrics.connection.nat_type ?? "-"}
                <br />
                transport: {metrics.connection.transport_mode}
                <br />
                throughput: {metrics.throughput_mbps.toFixed(3)} MB/s
                <br />
                packet_loss: {metrics.connection.packet_loss_rate.toFixed(2)}%
                <br />
                encrypt_avg: {metrics.connection.avg_encrypt_us.toFixed(1)} us
                <br />
                decrypt_avg: {metrics.connection.avg_decrypt_us.toFixed(1)} us
                <br />
                connection_errors: {metrics.connection.connection_errors}
              </div>
            ) : (
              "No diagnostics"
            )}
          </div>
          {isSymmetricNat && (
            <div className="warning-text" style={{ marginTop: 8 }}>
              Symmetric NAT detected. Direct paths are unreliable. Prefer Offer/Hybrid QR with Tor
              relay.
            </div>
          )}
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <button type="button" className="secondary" onClick={handleRefreshMetrics} disabled={!apiReady}>
              Refresh diagnostics
            </button>
          </div>
        </div>

        <div className="panel">
          <h2>Pluggable Transports</h2>
          <div className="helper-text">
            Pluggables require external infrastructure. HTTP/2 and QUIC are mimicry-only.
          </div>
          <div style={{ fontSize: 13, marginTop: 8 }}>
            {pluggableCheck ? (
              <div>
                profile: {pluggableCheck.pluggable_transport.profile}
                <br />
                mode: {pluggableCheck.pluggable_transport.mode}
                <br />
                mode_class: {pluggableCheck.pluggable_transport.mode_class}
                <br />
                enabled: {String(pluggableCheck.pluggable_transport.enabled)}
                <br />
                status: {pluggableCheck.pluggable_transport.status}
                <br />
                real_tls: {pluggableCheck.pluggable_transport.checklist.real_tls}
                <br />
                websocket: {pluggableCheck.pluggable_transport.checklist.websocket}
                <br />
                http2: {pluggableCheck.pluggable_transport.checklist.http2}
                <br />
                quic: {pluggableCheck.pluggable_transport.checklist.quic}
              </div>
            ) : (
              "No pluggable status"
            )}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
            <button type="button" className="secondary" onClick={handleRefreshPluggable} disabled={!apiReady}>
              Refresh pluggables
            </button>
          </div>
        </div>
          </>
        )}
      </div>
    </>
  )}

      {screen === "mode" && showAdvanced && allowAdvanced && (
        <ConsolePanel
          logs={filtered}
          filter={filter}
          onFilterChange={setFilter}
          onClear={clear}
        />
      )}
    </div>
  );
}



















