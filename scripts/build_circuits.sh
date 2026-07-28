#!/usr/bin/env bash
set -euo pipefail

# Build Noir circuits and generate UltraHonk verification keys (and optionally proofs).
#
# Usage:
#   build_circuits.sh <path>            # compile + write_vk only
#   build_circuits.sh <path> --prove    # compile + execute + prove + write_vk
#
# <path> can be:
#   - A directory containing Nargo.toml  (builds that single circuit)
#   - A directory whose subdirectories contain Nargo.toml files (builds each one)

NOIR_VERSION="1.0.0-beta.9"
BB_VERSION="v0.87.0"

export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

# ── toolchain installers ────────────────────────────────────────────

install_nargo() {
  if command -v nargo >/dev/null 2>&1; then return; fi

  echo "installing nargo $NOIR_VERSION"
  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | \
    NOIR_VERSION="$NOIR_VERSION" bash
  export PATH="$HOME/.nargo/bin:$PATH"
  if [ -n "${GITHUB_PATH:-}" ]; then echo "$HOME/.nargo/bin" >> "$GITHUB_PATH"; fi

  noirup -v "$NOIR_VERSION"
}

install_bb() {
  if command -v bb >/dev/null 2>&1; then return; fi

  echo "installing bb $BB_VERSION"
  mkdir -p "$HOME/.bb/bin"

  uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
  uname_m=$(uname -m)
  case "${uname_s}_${uname_m}" in
    linux_x86_64)  file="barretenberg-amd64-linux.tar.gz" ;;
    darwin_arm64)  file="barretenberg-arm64-darwin.tar.gz" ;;
    darwin_x86_64) file="barretenberg-amd64-darwin.tar.gz" ;;
    *)             echo "unsupported platform: ${uname_s}_${uname_m}"; exit 1 ;;
  esac

  url="https://github.com/AztecProtocol/aztec-packages/releases/download/${BB_VERSION}/${file}"
  curl -L "$url" -o /tmp/bb.tar.gz
  tar -xzf /tmp/bb.tar.gz -C "$HOME/.bb/bin"
  chmod +x "$HOME/.bb/bin/bb"
  export PATH="$HOME/.bb/bin:$PATH"
  if [ -n "${GITHUB_PATH:-}" ]; then echo "$HOME/.bb/bin" >> "$GITHUB_PATH"; fi
}

# ── flatten bb output directories ───────────────────────────────────

flatten_artifacts() {
  # bb write_vk creates target/vk/vk — flatten to target/vk
  if [[ -d target/vk && -f target/vk/vk ]]; then
    mv target/vk/vk target/vk.tmp
    rmdir target/vk
    mv target/vk.tmp target/vk
  fi

  # bb prove creates target/proof/proof — flatten to target/proof
  if [[ -d target/proof && -f target/proof/proof ]]; then
    mv target/proof/proof target/proof.tmp
    mv target/proof/public_inputs target/public_inputs
    rmdir target/proof
    mv target/proof.tmp target/proof
  fi
}

# ── build a single circuit directory ────────────────────────────────

build_circuit() {
  local dir="$1"
  local prove="$2"
  local name
  # Use the package name from Nargo.toml (nargo names artifacts after the package, not the directory)
  name=$(grep '^name' "$dir/Nargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')

  echo "building $name (prove=$prove)"
  pushd "$dir" >/dev/null

  local json="target/${name}.json"

  if [[ "$prove" == "true" ]]; then
    # Full build: compile with witness → prove → write_vk
    [ -f Prover.toml ] || nargo check --overwrite
    nargo execute

    local gz="target/${name}.gz"

    bb prove -b "$json" -w "$gz" -o target \
      --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields

    bb write_vk -b "$json" -o target \
      --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields
  else
    # Compile-only: compile → write_vk (no proof generation)
    nargo compile

    bb write_vk -b "$json" -o target \
      --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields
  fi

  flatten_artifacts
  popd >/dev/null
}

# ── main ────────────────────────────────────────────────────────────

usage() {
  echo "Usage: $0 <path> [--prove]"
  echo ""
  echo "  <path>    Directory with Nargo.toml, or parent of such directories"
  echo "  --prove   Also generate proofs (requires Prover.toml in each circuit)"
  exit 1
}

[[ $# -lt 1 ]] && usage

[[ -d "$1" ]] || { echo "error: path '$1' does not exist or is not a directory"; exit 1; }
TARGET_PATH="$(cd "$1" && pwd)"
PROVE="false"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prove) PROVE="true"; shift ;;
    *)       echo "unknown flag: $1"; usage ;;
  esac
done

install_nargo
install_bb

if [[ -f "$TARGET_PATH/Nargo.toml" ]]; then
  # Single circuit directory
  build_circuit "$TARGET_PATH" "$PROVE"
else
  # Parent directory — iterate subdirectories
  found=0
  for dir in "$TARGET_PATH"/*/; do
    [ -d "$dir" ] || continue
    [ -f "$dir/Nargo.toml" ] || continue
    build_circuit "$dir" "$PROVE"
    found=1
  done
  [[ $found -eq 0 ]] && echo "no Nargo.toml found in $TARGET_PATH or its subdirectories" && exit 1
fi

echo "done! Generated artifacts:"
find "$TARGET_PATH" -type f \( -name "vk" -o -name "proof" -o -name "public_inputs" \) 2>/dev/null | sort
