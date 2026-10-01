#!/usr/bin/env bash
# The deploy CLI's own check (#424): deploy → link → handover → accept → verify → link-describes,
# on two Anvils (a third, on Sepolia's id, for the testnet refusals), plus the edges its review
# found: a contract deployed after the handover is wired and named as needing its own handover; a handover with nothing to do leaves the manifest alone;
# a deploy on reuse records what the chain says; an unchanged redeploy after the handover is a
# clean exit 0; --to 0x0 is refused; (#466) a verifier on another registry, hand-wired for any
# peer, is refused by deploy and by link. Run from contracts/evm/deploy with `out/` built. Exit = FAILs.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${HANDOVER_CHECK_DIR:-$(mktemp -d)}"
K0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil #0: the deployer
A0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
K1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d   # anvil #1: the "multisig"
A1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
PA=${HANDOVER_CHECK_PORT_A:-8591}; PB=${HANDOVER_CHECK_PORT_B:-8592}; PC=${HANDOVER_CHECK_PORT_C:-8593}
fails=0; pass(){ echo "PASS  $*"; }; fail(){ echo "FAIL  $*"; fails=$((fails+1)); }
mkdir -p "$WORK/a" "$WORK/b" "$WORK/c"
anvil --port $PA --chain-id 31337 --silent & PID_A=$!
anvil --port $PB --chain-id 31338 --silent & PID_B=$!
# Sepolia's id, so a testnet env passes the chain-id check and the notary checks behind it are reached.
anvil --port $PC --chain-id 11155111 --silent & PID_C=$!
trap 'kill $PID_A $PID_B $PID_C 2>/dev/null' EXIT
sleep 3
cd "$HERE"
A(){ env EVM_RPC_URL=http://127.0.0.1:$PA EVM_ADMIN_PRIVATE_KEY=$K0 EVM_DEPLOYMENTS_DIR="$WORK/a" DEPLOY_ENV=local "$@"; }
# A-4: chain B runs on 31338, which is not a default local id — declared, as a private devnet would be.
B(){ env EVM_RPC_URL=http://127.0.0.1:$PB EVM_ADMIN_PRIVATE_KEY=$K0 EVM_DEPLOYMENTS_DIR="$WORK/b" DEPLOY_ENV=local LOCAL_EVM_CHAIN_IDS=31338 "$@"; }
nonceA(){ cast nonce $A0 --rpc-url http://127.0.0.1:$PA; }
MA="$WORK/a/31337.json"; MB="$WORK/b/31338.json"
adminOf(){ node -p "require('$MA').admin.$1"; }
addrOf(){ node -p "require('$MA').contracts.$1.address"; }
L="$WORK/log"; mkdir -p "$L"

echo "== 1. ADMIN set to someone else is refused up front, zero transactions"
n0=$(nonceA); A env ADMIN=$A1 pnpm -s run deploy > $L/1.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "is not the deployer" $L/1.log && [ "$(nonceA)" = "$n0" ] && pass "deploy refused ADMIN (exit $rc, 0 txs)" || fail "ADMIN refusal: exit $rc, txs $(( $(nonceA) - n0 ))"

echo "== 1b. an unset DEPLOY_ENV, a real env without a separate anchor notary, or a real env on a local chain, is refused up front, zero transactions"
n0=$(nonceA); A env -u DEPLOY_ENV pnpm -s run deploy > $L/1b.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "DEPLOY_ENV is unset" $L/1b.log && [ "$(nonceA)" = "$n0" ] && pass "deploy refused an unset DEPLOY_ENV (exit $rc, 0 txs)" || fail "unset DEPLOY_ENV: exit $rc, txs $(( $(nonceA) - n0 ))"
C(){ env EVM_RPC_URL=http://127.0.0.1:$PC EVM_ADMIN_PRIVATE_KEY=$K0 EVM_DEPLOYMENTS_DIR="$WORK/c" DEPLOY_ENV=testnet DISPUTE_ARBITER=$A1 DISPUTE_FEE_POOL=$A1 "$@"; }
nonceC(){ cast nonce $A0 --rpc-url http://127.0.0.1:$PC; }
# C-24: on a testnet chain id, the notary must be named ...
n0=$(nonceC); C pnpm -s run deploy > $L/1c.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "ANCHOR_PUBLISHER is unset for DEPLOY_ENV=testnet" $L/1c.log && [ "$(nonceC)" = "$n0" ] && pass "deploy refused testnet without ANCHOR_PUBLISHER (exit $rc, 0 txs)" || fail "testnet without ANCHOR_PUBLISHER: exit $rc, txs $(( $(nonceC) - n0 )), $(grep -m1 -i error $L/1c.log | cut -c1-140)"
# ... (A-8) and may not be the deployer.
n0=$(nonceC); C env ANCHOR_PUBLISHER=$A0 pnpm -s run deploy > $L/1c2.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "ANCHOR_PUBLISHER names the deployer" $L/1c2.log && [ "$(nonceC)" = "$n0" ] && pass "deploy refused the deployer as notary outside local (exit $rc, 0 txs)" || fail "deployer as notary: exit $rc, txs $(( $(nonceC) - n0 )), $(grep -m1 -i error $L/1c2.log | cut -c1-140)"
# A-4: with every role named, testnet on Anvil (31337) is refused for the chain id alone.
n0=$(nonceA); A env DEPLOY_ENV=testnet ANCHOR_PUBLISHER=$A1 DISPUTE_ARBITER=$A1 DISPUTE_FEE_POOL=$A1 pnpm -s run deploy > $L/1d.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "DEPLOY_ENV=testnet but the RPC is chain 31337, which is a local chain" $L/1d.log && [ "$(nonceA)" = "$n0" ] && pass "deploy refused testnet on a local chain id (exit $rc, 0 txs)" || fail "testnet on 31337: exit $rc, txs $(( $(nonceA) - n0 )), $(grep -m1 -i error $L/1d.log | cut -c1-140)"

echo "== 2. deploy both, link both ways"
A pnpm -s run deploy > $L/2a.log 2>&1 && B pnpm -s run deploy > $L/2b.log 2>&1 && pass "both deployed" || fail "deploy: $(grep -m1 Error $L/2a.log $L/2b.log)"
[ "$(adminOf current)" = "$A0" ] && pass "admin.current is the deployer" || fail "admin block: $(node -p "JSON.stringify(require('$MA').admin)")"
A pnpm -s cli link --peer $MB > $L/2l.log 2>&1; rc=$?; [ $rc -eq 0 ] && ! grep -q "\[describe\]" $L/2l.log && pass "link A→B sent, exit 0" || fail "link A→B exit $rc"
B pnpm -s cli link --peer $MA > $L/2m.log 2>&1 && pass "link B→A sent" || fail "link B→A"
# C-1: a plain link (no flag) wires the root gate on both escrows; without it no unlock could settle.
for e in adManager orderPortal; do
  [ "$(cast call --rpc-url http://127.0.0.1:$PA $(addrOf $e) 'rootVerifier(uint256)(address)' 31338)" = "$(addrOf counterpartyVerifier)" ] && pass "plain link wired $e.rootVerifier(31338)" || fail "plain link left $e without a root verifier"
done

echo "== 2a. (C-10) a follower backstop shorter than the primary's worst-case dispute is refused before anything is sent"
n0=$(nonceA); A env ROUTE_LONG_BACKSTOP_S=3600 pnpm -s cli link --peer $MB > $L/2a.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "this chain as follower" $L/2a.log && [ "$(nonceA)" = "$n0" ] && pass "link refused a 1-hour backstop against a 1-hour challenge period (exit $rc, 0 txs)" || fail "short backstop: exit $rc, txs $(( $(nonceA) - n0 )), $(grep -m1 -i 'error' $L/2a.log | cut -c1-140)"

echo "== 2b. (#466) a verifier on another registry, wired by hand for any peer, is refused by deploy and link"
RPA=http://127.0.0.1:$PA
A pnpm -s cli link --peer $MB > $L/2b0.log 2>&1 && [ "$(cast call --rpc-url $RPA $(addrOf adManager) 'rootVerifier(uint256)(address)' 31338)" = "$(addrOf counterpartyVerifier)" ] && pass "link wired the good verifier for 31338" || fail "link: $(grep -m1 -i error $L/2b0.log | cut -c1-120)"
# A second suite on the same chain, in its own manifest: the CLI links the registry's libraries.
mkdir -p "$WORK/a2"; env EVM_RPC_URL=$RPA EVM_ADMIN_PRIVATE_KEY=$K0 EVM_DEPLOYMENTS_DIR="$WORK/a2" DEPLOY_ENV=local pnpm -s run deploy > $L/2b-suite2.log 2>&1
REG2=$(node -p "require('$WORK/a2/31337.json').contracts.blsKeyRegistry.address" 2>/dev/null); BADV=$(node -p "require('$WORK/a2/31337.json').contracts.counterpartyVerifier.address" 2>/dev/null)
[ -n "$REG2" ] && [ -n "$BADV" ] && [ "$REG2" != "$(addrOf blsKeyRegistry)" ] && [ "$(cast call --rpc-url $RPA $BADV 'registry()(address)')" = "$REG2" ] && pass "a second registry and a verifier on it deployed" || fail "second registry/verifier: REG2=$REG2 BADV=$BADV"
cast send --rpc-url $RPA --private-key $K0 $(addrOf adManager) 'setRootVerifier(uint256,address)' 999 $BADV > /dev/null 2>&1
A pnpm -s run deploy > $L/2b1.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "AdManager peer 999: registry split" $L/2b1.log && pass "(a) deploy refused the hand-wired peer 999 (not in the manifest), exit $rc" || fail "(a) deploy: exit $rc, $(grep -m1 -i 'error\|split' $L/2b1.log | cut -c1-140)"
cast send --rpc-url $RPA --private-key $K0 $(addrOf adManager) 'setRootVerifier(uint256,address)' 999 $(addrOf counterpartyVerifier) > /dev/null 2>&1
cast send --rpc-url $RPA --private-key $K0 $(addrOf orderPortal) 'setRootVerifier(uint256,address)' 998 $BADV > /dev/null 2>&1
A pnpm -s cli link --peer $MB > $L/2b2.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "OrderPortal peer 998: registry split" $L/2b2.log && pass "(b) link refused a split on another listed peer, exit $rc" || fail "(b) link: exit $rc, $(grep -m1 -i 'error\|split' $L/2b2.log | cut -c1-140)"
cast send --rpc-url $RPA --private-key $K0 $(addrOf orderPortal) 'setRootVerifier(uint256,address)' 998 $(addrOf counterpartyVerifier) > /dev/null 2>&1
A pnpm -s run deploy > $L/2b3.log 2>&1 && A pnpm -s cli link --peer $MB > $L/2b4.log 2>&1 && pass "wiring restored: deploy and link pass again" || fail "restore: $(grep -m1 -i 'error\|split' $L/2b3.log $L/2b4.log | cut -c1-140)"

echo "== 3. --to 0x0 is refused; handover to $A1; rerun sends nothing"
n0=$(nonceA); A pnpm -s cli handover --to 0x0000000000000000000000000000000000000000 > $L/3z.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "is not a usable address" $L/3z.log && [ "$(nonceA)" = "$n0" ] && pass "--to 0x0 refused by name, 0 txs" || fail "--to 0x0: exit $rc, txs $(( $(nonceA) - n0 )), $(grep -m1 -i error $L/3z.log | cut -c1-120)"
n0=$(nonceA); A pnpm -s cli handover --to $A1 > $L/3.log 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(grep -c '\[nominate\]' $L/3.log)" = "6" ] && grep -q "no code on chain" $L/3.log && pass "6 nominated, EOA target named" || fail "handover: exit $rc, $(grep -c '\[nominate\]' $L/3.log) nominated"
[ "$(adminOf pending)" = "$A1" ] && pass "admin.pending recorded" || fail "pending: $(node -p "JSON.stringify(require('$MA').admin)")"
n0=$(nonceA); A pnpm -s cli handover --to $A1 > $L/3b.log 2>&1; rc=$?; [ $rc -eq 0 ] && [ "$(nonceA)" = "$n0" ] && [ "$(grep -c '\[pending\]' $L/3b.log)" = "6" ] && pass "handover rerun: exit 0, 6 pending, sends nothing" || fail "rerun: exit $rc, sent $(( $(nonceA) - n0 ))"

echo "== 4. the nominee accepts on all six; verify records it"
for key in merkleManager adManager orderPortal blsKeyRegistry rootAnchor disputeManager; do
  cast send --rpc-url http://127.0.0.1:$PA --private-key $K1 $(addrOf $key) "acceptAdmin()" > /dev/null 2>&1 || fail "acceptAdmin on $key"
done
A pnpm -s cli handover --verify > $L/4.log 2>&1; [ "$(grep -c '\[accepted\]' $L/4.log)" = "6" ] && [ "$(adminOf current)" = "$A1" ] && [ "$(adminOf pending)" = "undefined" ] && pass "verify: 6 accepted, current=$A1, pending cleared" || fail "verify: $(node -p "JSON.stringify(require('$MA').admin)")"
[ "$(cast call --rpc-url http://127.0.0.1:$PA $(addrOf merkleManager) 'hasRole(bytes32,address)(bool)' 0x0000000000000000000000000000000000000000000000000000000000000000 $A1)" = "true" ] && pass "DEFAULT_ADMIN_ROLE moved on the MerkleManager" || fail "DEFAULT_ADMIN_ROLE did not move"

echo "== 5. (H2) a handover rerun after full acceptance leaves the manifest alone"
cp $MA $WORK/ma.5; A pnpm -s cli handover --to $A1 > $L/5.log 2>&1; rc=$?
[ $rc -eq 0 ] && diff -q $MA $WORK/ma.5 >/dev/null && [ "$(adminOf current)" = "$A1" ] && pass "rerun: exit 0, manifest byte-identical, current still $A1" || fail "rerun rewrote the manifest: $(node -p "JSON.stringify(require('$MA').admin)")"

echo "== 6. (H6) an unchanged redeploy after the handover is a clean exit 0"
n0=$(nonceA); A pnpm -s run deploy > $L/6.log 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(nonceA)" = "$n0" ] && ! grep -q "\[describe\]" $L/6.log && pass "redeploy: exit 0, 0 txs, nothing described" || fail "redeploy: exit $rc, txs $(( $(nonceA) - n0 )), described $(grep -c '\[describe\]' $L/6.log)"
[ "$(adminOf current)" = "$A1" ] && pass "admin block left as it was (already true)" || fail "admin after redeploy: $(node -p "JSON.stringify(require('$MA').admin)")"

echo "== 7. (H3) a manifest whose admin block is stale is corrected from the chain"
node -e "const fs=require('fs'),m=JSON.parse(fs.readFileSync('$MA'));m.admin={current:'$A0'};fs.writeFileSync('$MA',JSON.stringify(m,null,2))"
A pnpm -s run deploy > $L/7.log 2>&1; [ "$(adminOf current)" = "$A1" ] && pass "stale current=deployer rewritten to the chain's $A1" || fail "stale block kept: $(node -p "JSON.stringify(require('$MA').admin)")"

echo "== 8. after the handover, link describes instead of sending"
cp $MA $WORK/ma.8; n0=$(nonceA); A env ANCHOR_DELAY_S=120 pnpm -s cli link --peer $MB > $L/8.log 2>&1; rc=$?
[ $rc -eq 2 ] && [ "$(nonceA)" = "$n0" ] && grep -q "RootAnchor.setAnchorDelay" $L/8.log && grep -q "data: 0x" $L/8.log && pass "link exit 2, 0 txs, setAnchorDelay described with calldata" || fail "link after handover: exit $rc, txs $(( $(nonceA) - n0 ))"
diff -q $MA $WORK/ma.8 >/dev/null && pass "manifest untouched by a described link" || fail "manifest changed by a described link"

echo "== 9. (H1) a contract deployed after the handover is wired now and named as needing a handover"
node -e "const fs=require('fs'),m=JSON.parse(fs.readFileSync('$MA'));delete m.contracts.disputeManager;m.disputeParams={};fs.writeFileSync('$MA',JSON.stringify(m,null,2))"
A pnpm -s run deploy > $L/9.log 2>&1; rc=$?
DM=$(addrOf disputeManager); ARB=$(cast call --rpc-url http://127.0.0.1:$PA $DM 'arbiter()(address)')
[ $rc -eq 0 ] && [ "$ARB" = "$A0" ] && pass "mixed deploy exit 0; new DisputeManager wired: arbiter set (local default: the deployer)" || fail "mixed deploy: exit $rc, arbiter=$ARB"
[ "$(cast call --rpc-url http://127.0.0.1:$PA $DM 'admin()(address)')" = "$A0" ] && grep -q "have the deployer as admin" $L/9.log && pass "run says the new contract needs its own handover" || fail "no handover notice for the new contract"
[ "$(adminOf current)" = "$A1" ] && pass "admin.current still the multisig (the reused contracts agree)" || fail "admin after mixed deploy: $(node -p "JSON.stringify(require('$MA').admin)")"

echo "== 10. chain B, never handed over: link again sends nothing (every escrow wire is check-first)"
nonceB(){ cast nonce $A0 --rpc-url http://127.0.0.1:$PB; }
n0=$(nonceB); B pnpm -s cli link --peer $MA > $L/10.log 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(nonceB)" = "$n0" ] && ! grep -q "\[describe\]" $L/10.log && pass "chain B link: exit 0, 0 txs on chain B" || fail "chain B link: exit $rc, txs $(( $(nonceB) - n0 ))"
echo; echo "fails: $fails"; exit $fails
