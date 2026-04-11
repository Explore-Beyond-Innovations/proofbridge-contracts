import { bls12_381 as bls } from "@noble/curves/bls12-381";
import {
  Wallet,
  keccak256,
  toUtf8Bytes,
  getBytes,
  toBeHex,
  concat,
} from "ethers";

// BLS12-381 scalar field order (r)
const BLS_R = BigInt(
  "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
);

// ---- helpers ----
function mod(a: bigint, n: bigint) {
  const r = a % n;
  return r >= 0n ? r : r + n;
}
/** Deterministically derive a 32-byte BLS secret from an EOA signature + context. */
function deriveBlsSkFromEoaSig(eoaSigHex: string, context: string): Uint8Array {
  // Hash(signature || context) with keccak256 (Ethereum-style)
  const seedHex = keccak256(
    concat([getBytes(eoaSigHex), toUtf8Bytes(context)])
  );

  // Map to [1..r-1]
  const k = mod(BigInt(seedHex), BLS_R - 1n) + 1n;
  return getBytes(toBeHex(k, 32)); // 32-byte big-endian
}
const hex = (u8: Uint8Array) => "0x" + Buffer.from(u8).toString("hex");

async function main() {
  // === 1) Users sign a one-time binding message with their EOA keys ===
  const eoa1 = new Wallet(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
  ); // demo
  const eoa2 = new Wallet(
    "0x8b3a350cf5c34c9194ca3a9d8b1f8fddac8f9f8baf2a2a6b0c04f2bde7c6a5b9"
  ); // demo

  const BIND_MSG = "Bind BLS key v1";
  // Include per-user nonce & domain for rotation/replay safety
  const ctx1 = `BLS-KEY-DERIVE-v1|acct:${await eoa1.getAddress()}|nonce:0`;
  const ctx2 = `BLS-KEY-DERIVE-v1|acct:${await eoa2.getAddress()}|nonce:0`;

  const sig1 = await eoa1.signMessage(`${BIND_MSG}|${ctx1}`);
  const sig2 = await eoa2.signMessage(`${BIND_MSG}|${ctx2}`);

  // === 2) Derive BLS secret keys from those EOA signatures ===
  const sk1 = deriveBlsSkFromEoaSig(sig1, ctx1);
  const sk2 = deriveBlsSkFromEoaSig(sig2, ctx2);

  // Public keys (compressed, 48 bytes each)
  const pk1 = bls.shortSignatures.getPublicKey(sk1);
  const pk2 = bls.shortSignatures.getPublicKey(sk2);

  console.log("pk1:", hex(pk1.toBytes(true)));
  console.log("pk2:", hex(pk2.toBytes(true)));

  // === 3) Sign a message with BLS and verify ===
  const msg = toUtf8Bytes("Hello");
  const msgHash = bls.shortSignatures.hash(msg);

  const sigBls1 = bls.shortSignatures.sign(msgHash, sk1); // Uint8Array
  const sigBls2 = bls.shortSignatures.sign(msgHash, sk2);

  const ok1 = bls.shortSignatures.verify(sigBls1, msgHash, pk1);
  const ok2 = bls.shortSignatures.verify(sigBls2, msgHash, pk2);
  console.log("verify1:", ok1, "verify2:", ok2);

  // === 4) Aggregate signatures & public keys (same-message aggregation) ===
  const sigAgg = bls.shortSignatures.aggregateSignatures([sigBls1, sigBls2]);
  const pkAgg = bls.shortSignatures.aggregatePublicKeys([pk1, pk2]);

  const okAgg = bls.shortSignatures.verify(sigAgg, msgHash, pkAgg);
  console.log("aggregate verify:", okAgg);
  console.log("sig1:", hex(sigBls1.toBytes(true)));
  console.log("sig2:", hex(sigBls2.toBytes(true)));
  console.log("sigAgg:", hex(sigAgg.toBytes(true)));
  console.log("sigAgg len:", sigAgg.toBytes(true).length);
  console.log("pkAgg:", hex(pkAgg.toBytes(true)));
  console.log("pkAgg len:", pkAgg.toBytes(true).length);
}

main().catch(console.error);
