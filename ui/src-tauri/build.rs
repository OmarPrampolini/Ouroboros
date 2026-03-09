use std::path::PathBuf;

fn main() {
    ensure_sidecar_variant();
    tauri_build::build()
}

fn ensure_sidecar_variant() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let bin_dir = manifest_dir.join("bin");
    let base = if cfg!(windows) {
        bin_dir.join("handshacke.exe")
    } else {
        bin_dir.join("handshacke")
    };

    let target = std::env::var("TAURI_ENV_TARGET_TRIPLE")
        .or_else(|_| std::env::var("TARGET"))
        .unwrap_or_default();

    if target.trim().is_empty() || !base.exists() {
        return;
    }

    let mut dest = bin_dir.join(format!("handshacke-{target}"));
    if cfg!(windows) {
        dest.set_extension("exe");
    }

    if !dest.exists() {
        let _ = std::fs::copy(base, dest);
    }
}
