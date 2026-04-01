#!/usr/bin/env sh
set -eu

REPO="${OUROBOROS_REPO:-OmarPrampolini/Ouroboros}"
INSTALL_DIR="${OUROBOROS_INSTALL_DIR:-$HOME/.local/bin}"
REQUESTED_TAG="${OUROBOROS_VERSION:-latest}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd tar

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os/$arch" in
    Linux/x86_64)
      printf '%s\n' "x86_64-unknown-linux-gnu"
      ;;
    Darwin/arm64|Darwin/aarch64)
      printf '%s\n' "aarch64-apple-darwin"
      ;;
    *)
      echo "Unsupported platform: $os/$arch" >&2
      echo "Supported targets: Linux x86_64, macOS arm64" >&2
      exit 1
      ;;
  esac
}

resolve_tag() {
  if [ "$REQUESTED_TAG" != "latest" ]; then
    printf '%s\n' "$REQUESTED_TAG"
    return
  fi

  api="https://api.github.com/repos/$REPO/releases/latest"
  tag="$(
    curl -fsSL --proto '=https' --tlsv1.2 "$api" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"

  if [ -z "$tag" ]; then
    echo "Failed to resolve latest release tag from $api" >&2
    exit 1
  fi

  printf '%s\n' "$tag"
}

verify_checksum() {
  asset="$1"
  archive_path="$2"
  sums_path="$3"

  if command -v sha256sum >/dev/null 2>&1; then
    (
      cd "$(dirname "$archive_path")"
      line="$(grep "  $asset\$" "$sums_path" || true)"
      [ -n "$line" ] || {
        echo "Checksum entry missing for $asset" >&2
        exit 1
      }
      printf '%s\n' "$line" | sha256sum -c -
    )
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    expected="$(awk "/  $asset$/ {print \$1}" "$sums_path" | head -n 1)"
    [ -n "$expected" ] || {
      echo "Checksum entry missing for $asset" >&2
      exit 1
    }
    actual="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
    [ "$expected" = "$actual" ] || {
      echo "Checksum mismatch for $asset" >&2
      exit 1
    }
    return
  fi

  echo "Missing required checksum verifier (sha256sum or shasum); aborting install" >&2
  exit 1
}

download() {
  url="$1"
  out="$2"
  curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$url" -o "$out"
}

main() {
  target="$(detect_target)"
  tag="$(resolve_tag)"
  archive="handshacke-$tag-$target.tar.gz"
  base_url="https://github.com/$REPO/releases/download/$tag"

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ouroboros-install.XXXXXX")"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  archive_path="$tmp_dir/$archive"
  sums_path="$tmp_dir/SHA256SUMS"

  echo "Downloading $archive"
  download "$base_url/$archive" "$archive_path"
  download "$base_url/SHA256SUMS" "$sums_path"
  verify_checksum "$archive" "$archive_path" "$sums_path"

  mkdir -p "$INSTALL_DIR"
  tar -xzf "$archive_path" -C "$tmp_dir"

  cp "$tmp_dir/handshacke" "$INSTALL_DIR/handshacke"
  cp "$tmp_dir/hs-cli" "$INSTALL_DIR/hs-cli"
  chmod +x "$INSTALL_DIR/handshacke" "$INSTALL_DIR/hs-cli"

  echo
  echo "Installed handshacke and hs-cli to $INSTALL_DIR"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      echo "Add this to your shell profile if needed:"
      echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
      ;;
  esac
  echo
  echo "Suggested next steps:"
  echo "  handshacke"
  echo "  hs-cli doctor"
}

main "$@"
