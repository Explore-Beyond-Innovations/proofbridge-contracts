#!/usr/bin/env bash
set -euo pipefail

# Regenerates evm/src/Verifier.sol from the event circuit's key: bb's output, untouched, formatted
# with forge (CI pins 1.7.1 and the formatting depends on the version).
#
# Usage: scripts/gen-verifier.sh [--check]    (circuit built first: scripts/build_circuits.sh proof_circuits/events)
#   --check  regenerate and fail if the committed file differs (CI)
#   FORGE    forge binary to format with (default: forge on PATH)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VK="${CIRCUITS_DIR:-$ROOT/../proof_circuits}/events/target/vk"
OUT="$ROOT/evm/src/Verifier.sol"
FORGE="${FORGE:-forge}"
export PATH="$HOME/.bb/bin:$PATH"

[ -f "$VK" ] || { echo "missing $VK: run scripts/build_circuits.sh proof_circuits/events first"; exit 1; }

# written inside the project so foundry.toml's formatter settings apply
GEN="$ROOT/evm/src/.gen-verifier.sol"
trap 'rm -f "$GEN"' EXIT
bb write_solidity_verifier --scheme ultra_honk -k "$VK" -o "$GEN" >/dev/null
(cd "$ROOT/evm" && "$FORGE" fmt src/.gen-verifier.sol >/dev/null)

if [ "${1:-}" = "--check" ]; then
  cmp -s "$GEN" "$OUT" || { echo "::error::evm/src/Verifier.sol does not match the circuit's key: run scripts/gen-verifier.sh"; exit 1; }
  echo "Verifier.sol matches the event circuit's key"
else
  cp "$GEN" "$OUT"
  echo "wrote $OUT"
fi
