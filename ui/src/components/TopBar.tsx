import React from "react";

type TopBarProps = {
  statusLabel: string;
  universeId: string;
  brandLabel?: string;
};

export function TopBar({ statusLabel, universeId, brandLabel = "HANDSHAKE" }: TopBarProps) {
  return (
    <div className="topbar">
      <div className="brand">
        <span>{brandLabel}</span>
        <span className="universe-id">{universeId || "HS-UNSET"}</span>
      </div>
      <div className="status-pill">
        <span className={`status-dot ${statusLabel.includes("running") ? "ok" : ""}`} />
        <span>{statusLabel}</span>
      </div>
    </div>
  );
}
