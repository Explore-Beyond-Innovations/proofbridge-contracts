/**
 * Generate proof fixtures for Stellar/Soroban integration tests.
 *
 * Computes the EIP-712 order hash the same way the Stellar contracts do
 * (full 32-byte addresses, not truncated to 20 bytes like EVM).
 *
 * Produces binary files that Rust tests load via include_bytes!:
 *   - proof_bridger.bin          (14592 bytes)
 *   - proof_ad_creator.bin       (14592 bytes)
 *   - public_inputs_bridger.bin  (128 bytes)
 *   - public_inputs_ad_creator.bin (128 bytes)
 *   - test_params.json           (JSON with all test parameters)
 *
 * Run from tests/fixtures:
 *   npx tsx generate_fixtures.ts
 */

import { Barretenberg, Fr, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import {
  MerkleMountainRange as MMR,
  LevelDB,
  Poseidon2Hasher,
} from "proofbridge-mmr";
import { keccak256 as ethersKeccak256 } from "ethers";
import * as fs from "fs";
import * as path from "path";

// ---------- constants ----------

const CIRCUIT_PATH = path.resolve(
  __dirname,
  "../../../../proof_circuits/deposits/target/deposit_circuit.json"
);

const OUTPUT_DIR = path.resolve(__dirname);

// ---------- Stellar strkey encoding ----------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let result = "";
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return result;
}

function crc16xmodem(data: Uint8Array): number {
  let crc = 0x0000;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      if (crc & 0x8000) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  }
  return crc;
}

// Stellar strkey version bytes
const STRKEY_ED25519_PUBLIC = 6 << 3; // 48 → 'G' prefix
const STRKEY_CONTRACT = 2 << 3;       // 16 → 'C' prefix

function encodeStrkey(versionByte: number, payload: Buffer): string {
  const body = Buffer.concat([Buffer.from([versionByte]), payload]);
  const checksum = crc16xmodem(body);
  const full = Buffer.concat([body, Buffer.from([checksum & 0xff, (checksum >> 8) & 0xff])]);
  return base32Encode(full);
}

/** Encode 32-byte hex as Stellar G... (ed25519 public key) address */
function toStellarAccountAddress(hex32: string): string {
  return encodeStrkey(STRKEY_ED25519_PUBLIC, hexToBytes32(hex32));
}

/** Encode 32-byte hex as Stellar C... (contract) address */
function toStellarContractAddress(hex32: string): string {
  return encodeStrkey(STRKEY_CONTRACT, hexToBytes32(hex32));
}

// ---------- EIP-712 constants (matching proofbridge-core/src/eip712.rs) ----------

// keccak256("EIP712Domain(string name,string version)")
const DOMAIN_TYPEHASH_MIN = keccak256(
  Buffer.from("EIP712Domain(string name,string version)")
);
// keccak256("Proofbridge")
const NAME_HASH = keccak256(Buffer.from("Proofbridge"));
// keccak256("1")
const VERSION_HASH = keccak256(Buffer.from("1"));
// keccak256("Order(bytes32 orderChainToken,...)")
const ORDER_TYPEHASH = keccak256(
  Buffer.from(
    "Order(bytes32 orderChainToken,bytes32 adChainToken,uint256 amount,bytes32 bridger,uint256 orderChainId,bytes32 orderPortal,bytes32 orderRecipient,uint256 adChainId,bytes32 adManager,string adId,bytes32 adCreator,bytes32 adRecipient,uint256 salt)"
  )
);

// ---------- helpers ----------

function keccak256(data: Buffer): Buffer {
  // ethers keccak256 returns hex string, convert to Buffer
  return Buffer.from(
    ethersKeccak256(data).replace(/^0x/, ""),
    "hex"
  );
}

function modOrderHash(orderHash: string): Fr {
  const buff = Buffer.from(orderHash.replace(/^0x/i, ""), "hex");
  return Fr.fromBufferReduce(buff);
}

function padArray(arr: string[], targetLen = 20): string[] {
  const ZERO = `0x${"0".repeat(64)}`;
  return [...arr.map(String), ...Array(targetLen - arr.length).fill(ZERO)];
}

function hexToBytes32(hex: string): Buffer {
  const clean = hex.replace(/^0x/i, "").padStart(64, "0");
  return Buffer.from(clean, "hex");
}

// ABI encode address: full 32 bytes (Stellar-compatible, NOT truncated to 20 bytes)
function abiEncodeAddress(bytes32Hex: string): Buffer {
  return hexToBytes32(bytes32Hex);
}

// ABI encode uint256: u128 → 32 bytes big-endian
function abiEncodeUint256(value: bigint): Buffer {
  const buf = Buffer.alloc(32, 0);
  const hex = value.toString(16).padStart(64, "0");
  Buffer.from(hex, "hex").copy(buf);
  return buf;
}

// Compute EIP-712 domain separator (minimal: name + version only)
function domainSeparator(): Buffer {
  const data = Buffer.concat([DOMAIN_TYPEHASH_MIN, NAME_HASH, VERSION_HASH]);
  return keccak256(data);
}

// Compute struct hash for Order (matching Stellar contract's eip712.rs)
function structHashOrder(params: {
  orderChainToken: string;
  adChainToken: string;
  amount: bigint;
  bridger: string;
  orderChainId: bigint;
  orderPortal: string;
  orderRecipient: string;
  adChainId: bigint;
  adManager: string;
  adId: string;
  adCreator: string;
  adRecipient: string;
  salt: bigint;
}): Buffer {
  const data = Buffer.concat([
    ORDER_TYPEHASH,
    abiEncodeAddress(params.orderChainToken),
    abiEncodeAddress(params.adChainToken),
    abiEncodeUint256(params.amount),
    abiEncodeAddress(params.bridger),
    abiEncodeUint256(params.orderChainId),
    abiEncodeAddress(params.orderPortal),
    abiEncodeAddress(params.orderRecipient),
    abiEncodeUint256(params.adChainId),
    abiEncodeAddress(params.adManager),
    keccak256(Buffer.from(params.adId)),
    abiEncodeAddress(params.adCreator),
    abiEncodeAddress(params.adRecipient),
    abiEncodeUint256(params.salt),
  ]);
  return keccak256(data);
}

// Compute EIP-712 typed data hash
function hashTypedDataV4(structHash: Buffer): Buffer {
  const prefix = Buffer.from([0x19, 0x01]);
  const data = Buffer.concat([prefix, domainSeparator(), structHash]);
  return keccak256(data);
}

// Build public_inputs bytes (128 bytes)
function buildPublicInputs(
  nullifierHash: string,
  orderHashMod: string,
  targetRoot: string,
  chainFlag: number
): Buffer {
  const buf = Buffer.alloc(128);
  hexToBytes32(nullifierHash).copy(buf, 0);
  hexToBytes32(orderHashMod).copy(buf, 32);
  hexToBytes32(targetRoot).copy(buf, 64);
  const flagBuf = Buffer.alloc(32, 0);
  flagBuf[31] = chainFlag;
  flagBuf.copy(buf, 96);
  return buf;
}

// ---------- main ----------

async function main() {
  console.log("Loading deposit circuit...");
  const circuit = JSON.parse(fs.readFileSync(CIRCUIT_PATH, "utf8"));

  console.log("Initializing Barretenberg...");
  const bb = await Barretenberg.new();

  // ----- Test Parameters -----
  // Deterministic secret
  const secretHex =
    "0x220397148885a7c7651c5862e1583322f68c2f0ea26945c0d2a5faa8e5941820";
  const secret = Fr.fromString(secretHex).toBuffer();

  // Split secret
  const leftSide = Buffer.concat([secret.slice(0, 16), Buffer.alloc(16, 0)]);
  const rightSide = Buffer.concat([Buffer.alloc(16, 0), secret.slice(16, 32)]);
  const leftField = Fr.fromBufferReduce(leftSide);
  const rightField = Fr.fromBufferReduce(rightSide);

  // Deterministic 32-byte addresses (used in both fixture generator and Rust test)
  // Raw hex is used for EIP-712 hashing; Stellar strkey is used in JSON output
  const adManagerHex = "0x" + "a1".repeat(32);   // ad-manager contract
  const orderPortalHex = "0x" + "b2".repeat(32); // order-portal contract

  // Token hex (contracts → C... addresses)
  const orderChainTokenHex = "0x" + "c3".repeat(32);
  const adChainTokenHex = "0x" + "d4".repeat(32);

  // User hex (ed25519 keys → G... addresses)
  const bridgerHex = "0x" + "e5".repeat(32);
  const orderRecipientHex = "0x" + "f6".repeat(32);
  const adCreatorHex = "0x" + "17".repeat(32);
  const adRecipientHex = "0x" + "28".repeat(32);

  // Stellar strkey addresses for JSON output
  const adManagerAddr = toStellarContractAddress(adManagerHex);
  const orderPortalAddr = toStellarContractAddress(orderPortalHex);
  const orderChainToken = toStellarContractAddress(orderChainTokenHex);
  const adChainToken = toStellarContractAddress(adChainTokenHex);
  const bridger = toStellarAccountAddress(bridgerHex);
  const orderRecipient = toStellarAccountAddress(orderRecipientHex);
  const adCreator = toStellarAccountAddress(adCreatorHex);
  const adRecipient = toStellarAccountAddress(adRecipientHex);
  const amount = BigInt(1000000);
  const orderChainId = BigInt(1);
  const adChainId = BigInt(2);
  const adId = "test-ad-1";
  const salt = BigInt(12345);

  // ----- Compute order hash using Stellar-compatible EIP-712 -----
  // Ad-manager computes: hash_order(params, config.chain_id, contract_address_to_bytes32)
  //   where config.chain_id = adChainId, contract_address = adManagerAddr
  // The struct hash uses: orderChainId, srcOrderPortal(=orderPortalAddr), adChainId, adManager(=adManagerAddr)
  // Raw hex addresses for EIP-712 hashing (must match contract's hash computation)
  const orderParamsHex = {
    orderChainToken: orderChainTokenHex,
    adChainToken: adChainTokenHex,
    amount,
    bridger: bridgerHex,
    orderChainId,
    orderPortal: orderPortalHex,
    orderRecipient: orderRecipientHex,
    adChainId,
    adManager: adManagerHex,
    adId,
    adCreator: adCreatorHex,
    adRecipient: adRecipientHex,
    salt,
  };

  const structHash = structHashOrder(orderParamsHex);
  const orderHashBuf = hashTypedDataV4(structHash);
  const orderHash = "0x" + orderHashBuf.toString("hex");
  console.log("Order hash (Stellar-compatible):", orderHash);

  const orderHashMod = modOrderHash(orderHash);
  console.log("Order hash (field mod):", orderHashMod.toString());

  // ----- Build MMR and append order hash -----
  console.log("Building MMR...");
  const dbPath = path.join("/tmp", "proofbridge-fixture-mmr-" + Date.now());
  const db = new LevelDB(dbPath);
  await db.init();
  const hasher = new Poseidon2Hasher();
  const mmrId = "fixture-" + Date.now();
  const mmr = new MMR(mmrId, db, hasher);

  // Append order hash (field_mod applied internally by MMR)
  const elementIndex = await mmr.append(orderHashMod.toString());
  console.log("Element index:", elementIndex);

  const merkleProof = await mmr.getMerkleProof(elementIndex);
  const targetRoot = await mmr.getHexRoot();
  console.log("Target root:", targetRoot);
  console.log("Width:", merkleProof.width);
  console.log("Peaks:", merkleProof.peaks.length);
  console.log("Siblings:", merkleProof.siblings.length);

  // ----- Compute nullifiers -----
  const bridgerNullifier = await bb.poseidon2Hash([leftField, orderHashMod]);
  console.log("Bridger nullifier:", bridgerNullifier.toString());

  const adCreatorNullifier = await bb.poseidon2Hash([orderHashMod, rightField]);
  console.log("Ad creator nullifier:", adCreatorNullifier.toString());

  // ----- Generate proofs (keccak: true for Soroban verifier) -----
  const noir = new Noir(circuit);
  const honk = new UltraHonkBackend(circuit.bytecode, { threads: 2 });

  const commonInput = {
    order_hash: orderHashMod.toString(),
    secret: secretHex,
    target_index: elementIndex.toString(),
    tree_width: merkleProof.width.toString(),
    target_sibling_hashes_len: merkleProof.siblings.length.toString(),
    target_sibling_hashes: padArray(
      merkleProof.siblings.map((s: any) => s.toString())
    ),
    target_peak_hashes_len: merkleProof.peaks.length.toString(),
    target_peak_hashes: padArray(
      merkleProof.peaks.map((p: any) => p.toString())
    ),
  };

  // Bridger proof (ad_contract = true, chain_flag = 1)
  console.log("\nGenerating bridger proof (ad chain, chain_flag=1)...");
  const { witness: bridgerWitness } = await noir.execute({
    ...commonInput,
    nullifier_hash: bridgerNullifier.toString(),
    target_root: targetRoot,
    ad_contract: true,
  });
  const bridgerResult = await honk.generateProof(bridgerWitness, {
    keccak: true,
  });
  console.log("Bridger proof size:", bridgerResult.proof.length, "bytes");

  // Ad creator proof (ad_contract = false, chain_flag = 0)
  console.log("Generating ad creator proof (order chain, chain_flag=0)...");
  const { witness: adCreatorWitness } = await noir.execute({
    ...commonInput,
    nullifier_hash: adCreatorNullifier.toString(),
    target_root: targetRoot,
    ad_contract: false,
  });
  const adCreatorResult = await honk.generateProof(adCreatorWitness, {
    keccak: true,
  });
  console.log("Ad creator proof size:", adCreatorResult.proof.length, "bytes");

  // ----- Build public inputs bytes -----
  const bridgerPubInputs = buildPublicInputs(
    bridgerNullifier.toString(),
    orderHashMod.toString(),
    targetRoot,
    1
  );
  const adCreatorPubInputs = buildPublicInputs(
    adCreatorNullifier.toString(),
    orderHashMod.toString(),
    targetRoot,
    0
  );

  // ----- Write fixtures -----
  console.log("\nWriting fixtures to:", OUTPUT_DIR);

  fs.writeFileSync(
    path.join(OUTPUT_DIR, "proof_bridger.bin"),
    Buffer.from(bridgerResult.proof)
  );
  fs.writeFileSync(
    path.join(OUTPUT_DIR, "proof_ad_creator.bin"),
    Buffer.from(adCreatorResult.proof)
  );
  fs.writeFileSync(
    path.join(OUTPUT_DIR, "public_inputs_bridger.bin"),
    bridgerPubInputs
  );
  fs.writeFileSync(
    path.join(OUTPUT_DIR, "public_inputs_ad_creator.bin"),
    adCreatorPubInputs
  );

  const vkSrc = path.resolve(
    __dirname,
    "../../../../proof_circuits/deposits/target/vk"
  );
  fs.copyFileSync(vkSrc, path.join(OUTPUT_DIR, "vk"));

  // Write test params (Stellar strkey addresses for display, used by Rust tests)
  const testParams = {
    secret: secretHex,
    orderHash,
    orderHashMod: orderHashMod.toString(),
    targetRoot,
    bridgerNullifier: bridgerNullifier.toString(),
    adCreatorNullifier: adCreatorNullifier.toString(),
    elementIndex,
    width: merkleProof.width,
    // Contract addresses (Stellar C... format, must match register_at in Rust test)
    contractAddresses: {
      adManager: adManagerAddr,
      orderPortal: orderPortalAddr,
    },
    // Order params (Stellar addresses: C... for contracts/tokens, G... for users)
    orderParams: {
      orderChainToken,
      adChainToken,
      amount: amount.toString(),
      bridger,
      orderChainId: orderChainId.toString(),
      orderPortal: orderPortalAddr,
      orderRecipient,
      adChainId: adChainId.toString(),
      adManager: adManagerAddr,
      adId,
      adCreator,
      adRecipient,
      salt: salt.toString(),
    },
    chainIds: {
      orderChainId: Number(orderChainId),
      adChainId: Number(adChainId),
    },
  };

  fs.writeFileSync(
    path.join(OUTPUT_DIR, "test_params.json"),
    JSON.stringify(testParams, null, 2)
  );

  // Cleanup
  fs.rmSync(dbPath, { recursive: true, force: true });

  console.log("\nFixtures generated successfully!");
  console.log("  proof_bridger.bin:", bridgerResult.proof.length, "bytes");
  console.log("  proof_ad_creator.bin:", adCreatorResult.proof.length, "bytes");
  console.log("  public_inputs_bridger.bin:", bridgerPubInputs.length, "bytes");
  console.log(
    "  public_inputs_ad_creator.bin:",
    adCreatorPubInputs.length,
    "bytes"
  );
  console.log("  vk:", fs.statSync(path.join(OUTPUT_DIR, "vk")).size, "bytes");

  await bb.destroy();
  process.exit(0);
}

main().catch((err) => {
  console.error("Error generating fixtures:", err);
  process.exit(1);
});
