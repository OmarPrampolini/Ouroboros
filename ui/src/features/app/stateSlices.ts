import { useState } from "react";
import {
  DaemonStatus,
  DebugMetricsResponse,
  EtherSyncEvent,
  EtherSyncStatusResponse,
  FlowMode,
  GUARANTEED_EGRESS,
  HybridQrResponse,
  OfferResponse,
  PLUGGABLE_PROFILES,
  PLUGGABLE_TRANSPORTS,
  PluggableCheckResponse,
  ROLE_OPTIONS,
  SetPassResponse,
  StatusResponse,
  STEALTH_MODES,
  TOR_ROLES,
  WAN_MODES
} from "./model";

export function useSystemSlice() {
  const [apiBind, setApiBind] = useState("127.0.0.1:8731");
  const [unsafeExpose, setUnsafeExpose] = useState(false);
  const [daemonStatus, setDaemonStatus] = useState<DaemonStatus>({ running: false });
  const [token, setToken] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [sseEnabled, setSseEnabled] = useState(false);
  const [screen, setScreen] = useState<"home" | "mode">("home");
  const [connectAttempted, setConnectAttempted] = useState(false);

  return {
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
  };
}

export function useConnectionSlice() {
  const [passphrase, setPassphrase] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [localRole, setLocalRole] = useState<(typeof ROLE_OPTIONS)[number]>("auto");
  const [wanMode, setWanMode] = useState<(typeof WAN_MODES)[number]>("auto");
  const [torRole, setTorRole] = useState<(typeof TOR_ROLES)[number]>("client");
  const [connectStatus, setConnectStatus] = useState<StatusResponse | null>(null);
  const [setPassResult, setSetPassResult] = useState<SetPassResponse | null>(null);
  const [flowMode, setFlowMode] = useState<FlowMode>("classic");

  return {
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
  };
}

export function useOfferSlice() {
  const [offerResult, setOfferResult] = useState<OfferResponse | null>(null);
  const [offerQr, setOfferQr] = useState<string | null>(null);
  const [offerTtl, setOfferTtl] = useState<string>("");
  const [offerRoleHint, setOfferRoleHint] = useState<"host" | "client">("host");
  const [offerLocalRole, setOfferLocalRole] = useState<"host" | "client">("client");
  const [classicOffer, setClassicOffer] = useState<string>("");
  const [includeTorOffer, setIncludeTorOffer] = useState<boolean>(false);

  return {
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
  };
}

export function useHybridSlice() {
  const [hybridQrResult, setHybridQrResult] = useState<HybridQrResponse | null>(null);
  const [hybridQrImage, setHybridQrImage] = useState<string | null>(null);
  const [hybridQrTtl, setHybridQrTtl] = useState<string>("");
  const [hybridResumeTtl, setHybridResumeTtl] = useState<string>("");
  const [hybridRoleHint, setHybridRoleHint] = useState<"host" | "client">("host");
  const [hybridLocalRole, setHybridLocalRole] = useState<"host" | "client">("client");
  const [hybridIncludeTor, setHybridIncludeTor] = useState<boolean>(false);
  const [hybridRelayHints, setHybridRelayHints] = useState<string>("");
  const [hybridQrInput, setHybridQrInput] = useState<string>("");

  return {
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
  };
}

export function usePhraseSlice() {
  const [phraseInvite, setPhraseInvite] = useState<string>("");
  const [phraseQr, setPhraseQr] = useState<string | null>(null);
  const [phraseStatus, setPhraseStatus] = useState<string>("closed");
  const [joinInvite, setJoinInvite] = useState<string>("");
  const [phrasePassphrase, setPhrasePassphrase] = useState<string>("");

  return {
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
  };
}

export function useTargetSlice() {
  const [classicTarget, setClassicTarget] = useState<string>("");
  const [targetIsOnion, setTargetIsOnion] = useState<boolean>(false);
  const [targetOnion, setTargetOnion] = useState<string>("");

  return {
    classicTarget,
    setClassicTarget,
    targetIsOnion,
    setTargetIsOnion,
    targetOnion,
    setTargetOnion
  };
}

export function useGuaranteedSlice() {
  const [guaranteedPassphrase, setGuaranteedPassphrase] = useState<string>("");
  const [guaranteedEgress, setGuaranteedEgress] =
    useState<(typeof GUARANTEED_EGRESS)[number]>("public");
  const [guaranteedRelayUrl, setGuaranteedRelayUrl] = useState<string>("");

  return {
    guaranteedPassphrase,
    setGuaranteedPassphrase,
    guaranteedEgress,
    setGuaranteedEgress,
    guaranteedRelayUrl,
    setGuaranteedRelayUrl
  };
}

export function useAdvancedSlice() {
  const [pluggableProfile, setPluggableProfile] =
    useState<(typeof PLUGGABLE_PROFILES)[number]>("stable");
  const [pluggableTransport, setPluggableTransport] =
    useState<(typeof PLUGGABLE_TRANSPORTS)[number]>("none");
  const [realTlsDomain, setRealTlsDomain] = useState<string>("");
  const [stealthMode, setStealthMode] =
    useState<(typeof STEALTH_MODES)[number]>("active");
  const [assistRelays, setAssistRelays] = useState<string>("");
  const [torSocksAddr, setTorSocksAddr] = useState<string>("");
  const [torOnionAddr, setTorOnionAddr] = useState<string>("");
  const [pluggableCheck, setPluggableCheck] = useState<PluggableCheckResponse | null>(null);
  const [metrics, setMetrics] = useState<DebugMetricsResponse | null>(null);

  return {
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
  };
}

export function useSpaceSlice() {
  const [spaceBindAddr, setSpaceBindAddr] = useState<string>("0.0.0.0:0");
  const [spaceBootstrapPeers, setSpaceBootstrapPeers] = useState<string>("");
  const [spacePassphrase, setSpacePassphrase] = useState<string>("");
  const [spaceLabel, setSpaceLabel] = useState<string>("");
  const [spacePeerToAdd, setSpacePeerToAdd] = useState<string>("");
  const [spaceMessage, setSpaceMessage] = useState<string>("");
  const [spaceFileName, setSpaceFileName] = useState<string>("");
  const [spaceFileB64, setSpaceFileB64] = useState<string>("");
  const [spaceFileSize, setSpaceFileSize] = useState<number>(0);
  const [spaceChunkSize, setSpaceChunkSize] = useState<string>("1024");
  const [spaceStatus, setSpaceStatus] = useState<EtherSyncStatusResponse | null>(null);
  const [spaceJoinedId, setSpaceJoinedId] = useState<string>("");
  const [spaceEvents, setSpaceEvents] = useState<EtherSyncEvent[]>([]);

  return {
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
  };
}
