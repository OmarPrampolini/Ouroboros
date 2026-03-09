use crate::config::{Config, PluggableProfile, PluggableTransportMode};

fn profile_name(profile: PluggableProfile) -> &'static str {
    match profile {
        PluggableProfile::Stable => "stable",
        PluggableProfile::Experimental => "experimental",
    }
}

pub(crate) async fn handle_pluggable_protocols() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "profiles": ["stable", "experimental"],
        "default_profile": "stable",
        "modes": [
            {"id": "none", "class": "stable", "requires_external_infra": false},
            {"id": "httpslike", "class": "stable", "requires_external_infra": false},
            {"id": "ftpdata", "class": "stable", "requires_external_infra": false},
            {"id": "dnstunnel", "class": "stable", "requires_external_infra": false},
            {"id": "realtls", "class": "experimental", "requires_external_infra": true},
            {"id": "websocket", "class": "experimental", "requires_external_infra": true},
            {"id": "quic", "class": "experimental", "requires_external_infra": false}
        ],
        "warning": "Experimental pluggable modes may require external infrastructure and can be fingerprintable if misconfigured."
    }))
}

pub(crate) async fn handle_pluggable_check() -> axum::Json<serde_json::Value> {
    let cfg = Config::from_env();
    let enabled = cfg.pluggable_transport != PluggableTransportMode::None;

    let status = if !enabled {
        "disabled"
    } else if cfg.pluggable_transport.requires_external_infra() {
        "requires_external_infrastructure"
    } else {
        "active"
    };

    let real_tls_status = match &cfg.pluggable_transport {
        PluggableTransportMode::RealTls(domain) if !domain.trim().is_empty() => "CONFIGURED",
        _ => "NOT_CONFIGURED",
    };

    let websocket_status = match cfg.pluggable_transport {
        PluggableTransportMode::WebSocket => "REQUIRES_EXTERNAL_INFRA",
        _ => "NOT_CONFIGURED",
    };

    let quic_status = match cfg.pluggable_transport {
        PluggableTransportMode::Quic => "MIMICRY_ONLY",
        _ => "NOT_CONFIGURED",
    };

    axum::Json(serde_json::json!({
        "pluggable_transport": {
            "profile": profile_name(cfg.pluggable_profile),
            "enabled": enabled,
            "mode": cfg.pluggable_transport.id(),
            "mode_class": cfg.pluggable_transport.class(),
            "status": status,
            "checklist": {
                "real_tls": real_tls_status,
                "websocket": websocket_status,
                "http2": "EXPERIMENTAL_MIMICRY",
                "quic": quic_status
            }
        }
    }))
}
