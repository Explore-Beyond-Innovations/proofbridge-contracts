#!/usr/bin/env bash
# The deploy CLI's own check (#424): deploy → link → handover → accept → verify → link-describes,
# on two Anvils, plus the edges its review found: a contract deployed after the handover is wired
# and named as needing its own handover; a handover with nothing to do leaves the manifest alone;
# a deploy on reuse records what the chain says; an unchanged redeploy after the handover is a
# clean exit 0; --to 0x0 is refused. Run from contracts/evm/deploy with `out/` built. Exit = FAILs.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${HANDOVER_CHECK_DIR:-$(mktemp -d)}"
K0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil #0: the deployer
A0=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
K1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d   # anvil #1: the "multisig"
A1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
PA=${HANDOVER_CHECK_PORT_A:-8591}; PB=${HANDOVER_CHECK_PORT_B:-8592}
fails=0; pass(){ echo "PASS  $*"; }; fail(){ echo "FAIL  $*"; fails=$((fails+1)); }
mkdir -p "$WORK/a" "$WORK/b"
anvil --port $PA --chain-id 31337 --silent & PID_A=$!
anvil --port $PB --chain-id 31338 --silent & PID_B=$!
trap 'kill $PID_A $PID_B 2>/dev/null' EXIT
sleep 3
cd "$HERE"
A(){ env EVM_RPC_URL=http://127.0.0.1:$PA EVM_ADMIN_PRIVATE_KEY=$K0 EVM_DEPLOYMENTS_DIR="$WORK/a" DEPLOY_ENV=local "$@"; }
B(){ env EVM_RPC_URL=http://127.0.0.1:$PB EVM_ADMIN_PRIVATE_KEY=$K0 EVM_DEPLOYMENTS_DIR="$WORK/b" DEPLOY_ENV=local "$@"; }
nonceA(){ cast nonce $A0 --rpc-url http://127.0.0.1:$PA; }
MA="$WORK/a/31337.json"; MB="$WORK/b/31338.json"
adminOf(){ node -p "require('$MA').admin.$1"; }
addrOf(){ node -p "require('$MA').contracts.$1.address"; }
L="$WORK/log"; mkdir -p "$L"

echo "== 1. ADMIN set to someone else is refused up front, zero transactions"
n0=$(nonceA); A env ADMIN=$A1 pnpm -s run deploy > $L/1.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "is not the deployer" $L/1.log && [ "$(nonceA)" = "$n0" ] && pass "deploy refused ADMIN (exit $rc, 0 txs)" || fail "ADMIN refusal: exit $rc, txs $(( $(nonceA) - n0 ))"

echo "== 2. deploy both, link both ways"
A pnpm -s run deploy > $L/2a.log 2>&1 && B pnpm -s run deploy > $L/2b.log 2>&1 && pass "both deployed" || fail "deploy: $(grep -m1 Error $L/2a.log $L/2b.log)"
[ "$(adminOf current)" = "$A0" ] && pass "admin.current is the deployer" || fail "admin block: $(node -p "JSON.stringify(require('$MA').admin)")"
A pnpm -s cli link --peer $MB > $L/2l.log 2>&1; rc=$?; [ $rc -eq 0 ] && ! grep -q "\[describe\]" $L/2l.log && pass "link A→B sent, exit 0" || fail "link A→B exit $rc"
B pnpm -s cli link --peer $MA > $L/2m.log 2>&1 && pass "link B→A sent" || fail "link B→A"

echo "== 3. --to 0x0 is refused; handover to $A1; rerun sends nothing"
n0=$(nonceA); A pnpm -s cli handover --to 0x0000000000000000000000000000000000000000 > $L/3z.log 2>&1; rc=$?
[ $rc -ne 0 ] && [ "$(nonceA)" = "$n0" ] && pass "--to 0x0 refused, 0 txs" || fail "--to 0x0: exit $rc, txs $(( $(nonceA) - n0 ))"
n0=$(nonceA); A pnpm -s cli handover --to $A1 > $L/3.log 2>&1; rc=$?
[ $rc -eq 0 ] && [ "$(grep -c '\[nominate\]' $L/3.log)" = "6" ] && grep -q "no code on chain" $L/3.log && pass "6 nominated, EOA target named" || fail "handover: exit $rc, $(grep -c '\[nominate\]' $L/3.log) nominated"
[ "$(adminOf pending)" = "$A1" ] && pass "admin.pending recorded" || fail "pending: $(node -p "JSON.stringify(require('$MA').admin)")"
n0=$(nonceA); A pnpm -s cli handover --to $A1 > $L/3b.log 2>&1; [ "$(nonceA)" = "$n0" ] && pass "handover rerun sends nothing" || fail "rerun sent $(( $(nonceA) - n0 ))"

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
[ "$(adminOf current)" = "$A1" ] && pass "(H3) admin.current still what the chain says" || fail "admin after redeploy: $(node -p "JSON.stringify(require('$MA').admin)")"

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
[ "$ARB" = "$A0" ] && pass "new DisputeManager wired: arbiter set (local default: the deployer)" || fail "new DisputeManager not wired: arbiter=$ARB"
[ "$(cast call --rpc-url http://127.0.0.1:$PA $DM 'admin()(address)')" = "$A0" ] && grep -q "have the deployer as admin" $L/9.log && pass "run says the new contract needs its own handover" || fail "no handover notice for the new contract"
[ "$(adminOf current)" = "$A1" ] && pass "admin.current still the multisig (the reused contracts agree)" || fail "admin after mixed deploy: $(node -p "JSON.stringify(require('$MA').admin)")"

echo "== 10. chain B, never handed over: link again is a no-op exit 0"
B pnpm -s cli link --peer $MA > $L/10.log 2>&1; rc=$?; [ $rc -eq 0 ] && ! grep -q "\[describe\]" $L/10.log && pass "chain B link exit 0" || fail "chain B link exit $rc"
echo; echo "fails: $fails"; exit $fails
