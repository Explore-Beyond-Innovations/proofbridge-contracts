import { Barretenberg, Fr } from "@aztec/bb.js";
import { AbiCoder, hexlify } from "ethers";
import { modOrderHash } from "../utils";

/**
 * Generates both ad creator and bridger deposit nullifiers using Poseidon hash and a single random secret
 *
 * The function takes one command line argument:
 * - orderHash string
 *
 * Uses a single 32-byte secret split into two parts:
 * - Left 16 bytes used for bridger nullifier
 * - Right 16 bytes used for ad creator nullifier
 *
 * @returns Promise<string> - ABI encoded tuple of [adCreatorNullifier, adCreatorSecret, bridgerNullifier, bridgerSecret] as bytes32 values
 */
async function generateDepositNullifier(): Promise<string> {
  const inputs = process.argv.slice(2);
  const orderHash = inputs[0];
  const bb = await Barretenberg.new();

  // Example secret for testing!!!;
  // const secret = Fr.fromString(
  //   "0x220397148885a7c7651c5862e1583322f68c2f0ea26945c0d2a5faa8e5941820"
  // ).toBuffer();

  const secret = Fr.random().toBuffer();

  const leftSide = Buffer.concat([secret.slice(0, 16), Buffer.alloc(16, 0)]);

  const rightSide = Buffer.concat([Buffer.alloc(16, 0), secret.slice(16, 32)]);

  const leftField = Fr.fromBufferReduce(leftSide);
  const rightField = Fr.fromBufferReduce(rightSide);

  const orderHashField = modOrderHash(orderHash);

  // Generate bridger nullifier using left side
  const bridgerNullifier = await bb.poseidon2Hash([leftField, orderHashField]);

  // Generate ad creator nullifier using right side
  const adCreatorNullifier = await bb.poseidon2Hash([
    orderHashField,
    rightField,
  ]);

  const result = AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "bytes32"],
    [
      adCreatorNullifier.toString(),
      bridgerNullifier.toString(),
      hexlify(secret),
    ]
  );
  return result;
}

(async () => {
  generateDepositNullifier()
    .then((result) => {
      process.stdout.write(result);
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
})();
