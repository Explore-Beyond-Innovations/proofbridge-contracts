#!/usr/bin/env bash
set -euo pipefail

# Build Noir circuits and generate UltraHonk verification keys (and optionally proofs).
#
# Usage:
#   build_circuits.sh <path>            # compile + write_vk only
#   build_circuits.sh <path> --prove    # compile + execute + prove + write_vk
#   build_circuits.sh --install         # install the pinned nargo + bb only
#
# <path> can be:
#   - A directory containing Nargo.toml  (builds that single circuit)
#   - A directory whose subdirectories contain Nargo.toml files (builds each one)

NOIR_VERSION="1.0.0-beta.9"
BB_VERSION="v0.87.0"

export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

# ── toolchain installers ────────────────────────────────────────────
# Both come from their GitHub release by exact version and are checked against a sha256 kept here,
# never `releases/latest`. nargo is fetched directly: noirup downloads its tarball with no checksum.
# Bumping a pin: download each platform's asset from two places, and update the version + hashes together.

nargo_sha256() {
  case "$1" in
    x86_64-unknown-linux-gnu)  echo "7a7fce332e72a5e81b20570ccdcb8f2b1dfea86e3c724910ddc3133c838a09a2" ;;
    aarch64-unknown-linux-gnu) echo "12e404881621530c095a988ad67fb3883450058f8d448c1ada6dc4a1fa9a57bb" ;;
    x86_64-apple-darwin)       echo "4b4bb88b777f720891068c15a1594094168a0ed4f215521858b7a338562929bc" ;;
    aarch64-apple-darwin)      echo "50203fcdc9b987aa9b470f776bd497914893c0d39ae5bc09d320b6c5511fde91" ;;
  esac
}

bb_sha256() {
  case "$1" in
    amd64-linux)  echo "829b714287085ff4562ba2c64f9c8128463650d833bdd1db5d5a33471dcd67cb" ;;
    amd64-darwin) echo "a996534031c898b65123197979284aa92bd377c1ebc13318a82476a82f9cc781" ;;
    arm64-darwin) echo "29007919d4badea047f660f55bcbc38acd6e88f07722cc63f84baec816be1751" ;;
  esac
}

# Download $1 to $2 and refuse it unless its sha256 is $3.
fetch_verified() {
  local url="$1" dest="$2" want="$3" got
  if [[ -z "$want" ]]; then echo "error: no pinned sha256 for $url" >&2; exit 1; fi
  curl -fsSL "$url" -o "$dest"
  got="$( (sha256sum "$dest" 2>/dev/null || shasum -a 256 "$dest") | cut -d' ' -f1)"
  if [[ "$got" != "$want" ]]; then
    echo "error: $url has sha256 $got, pinned $want; refusing it" >&2; exit 1
  fi
}

install_nargo() {
  if command -v nargo >/dev/null 2>&1; then return; fi

  echo "installing nargo $NOIR_VERSION"
  local arch platform target tmp
  arch="$(uname -m)"; [[ "$arch" == "arm64" ]] && arch="aarch64"
  case "$(uname -s)" in
    Linux)  platform="unknown-linux-gnu" ;;
    Darwin) platform="apple-darwin" ;;
    *)      echo "unsupported platform: $(uname -s)"; exit 1 ;;
  esac
  target="${arch}-${platform}"
  tmp="$(mktemp -d)"
  fetch_verified "https://github.com/noir-lang/noir/releases/download/v${NOIR_VERSION}/nargo-${target}.tar.gz" \
    "$tmp/nargo.tar.gz" "$(nargo_sha256 "$target")"
  mkdir -p "$HOME/.nargo/bin"
  tar -xzf "$tmp/nargo.tar.gz" -C "$HOME/.nargo/bin"
  chmod +x "$HOME/.nargo/bin/nargo"
  rm -rf "$tmp"
  export PATH="$HOME/.nargo/bin:$PATH"
  if [ -n "${GITHUB_PATH:-}" ]; then echo "$HOME/.nargo/bin" >> "$GITHUB_PATH"; fi
}

install_bb() {
  if command -v bb >/dev/null 2>&1; then return; fi

  echo "installing bb $BB_VERSION"
  mkdir -p "$HOME/.bb/bin"

  uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
  uname_m=$(uname -m)
  case "${uname_s}_${uname_m}" in
    linux_x86_64)  asset="amd64-linux" ;;
    darwin_arm64)  asset="arm64-darwin" ;;
    darwin_x86_64) asset="amd64-darwin" ;;
    *)             echo "unsupported platform: ${uname_s}_${uname_m}"; exit 1 ;;
  esac

  local tmp
  tmp="$(mktemp -d)"
  fetch_verified "https://github.com/AztecProtocol/aztec-packages/releases/download/${BB_VERSION}/barretenberg-${asset}.tar.gz" \
    "$tmp/bb.tar.gz" "$(bb_sha256 "$asset")"
  tar -xzf "$tmp/bb.tar.gz" -C "$HOME/.bb/bin"
  rm -rf "$tmp"
  chmod +x "$HOME/.bb/bin/bb"
  export PATH="$HOME/.bb/bin:$PATH"
  if [ -n "${GITHUB_PATH:-}" ]; then echo "$HOME/.bb/bin" >> "$GITHUB_PATH"; fi
}

# ── the pins are enforced, not just installed ───────────────────────
# A nargo or bb already on PATH skips the install above, and a different version writes a different
# VK: the EVM Verifier bakes one, the Soroban verifier is given another, and one chain then refuses
# every proof. PROOFBRIDGE_ALLOW_TOOLCHAIN_DRIFT=1 builds anyway (never for a release or a deploy).

check_pins() {
  local nv bv
  nv="$(nargo --version 2>/dev/null | sed -n 's/^nargo version = //p' | head -1)"
  bv="$(bb --version 2>/dev/null | tr -d 'v[:space:]')"
  local bad=""
  [[ "$nv" == "$NOIR_VERSION" ]] || bad="nargo ${nv:-<none>} (pinned $NOIR_VERSION)"
  [[ "$bv" == "${BB_VERSION#v}" ]] || bad="${bad:+$bad, }bb ${bv:-<none>} (pinned ${BB_VERSION#v})"
  if [[ -n "$bad" ]]; then
    if [[ "${PROOFBRIDGE_ALLOW_TOOLCHAIN_DRIFT:-}" == "1" ]]; then
      echo "warning: toolchain drift: $bad; the VK will not match a pinned build" >&2
    else
      echo "error: toolchain drift: $bad. Install the pins (take the other nargo / bb off PATH, then $0 --install) or set PROOFBRIDGE_ALLOW_TOOLCHAIN_DRIFT=1 for a throwaway build." >&2
      exit 1
    fi
  fi
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

# --install: the pinned toolchain only (CI steps that need nargo / bb but build nothing here).
if [[ "$1" == "--install" ]]; then
  install_nargo
  install_bb
  check_pins
  exit 0
fi

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
check_pins

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
