import { Barretenberg, Fr } from "@aztec/bb.js";
import { AbiCoder } from "ethers";

export default async function hashPoseidon(): Promise<string> {
  const inputs = process.argv.slice(2);
  const nullifier = inputs[0];
  const bb = await Barretenberg.new();
  const nullifier_buffer = Buffer.from(nullifier.replace(/^0x/, ""), "hex");
  const rs_buffer = nullifier_buffer.subarray(0, 64);
  let buffer = reduceRS(rs_buffer);
  const nullifierHash = await bb.poseidon2Hash([Fr.fromString(buffer)]);
  const result = AbiCoder.defaultAbiCoder().encode(
    ["bytes32"],
    [nullifierHash.toString()]
  );
  return result;
}

const P = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
function reduceRS(rs: Buffer) {
  let x = 0n;
  for (const b of rs) x = (x << 8n) | BigInt(b);
  const fr = x % P;
  return "0x" + fr.toString(16).padStart(64, "0");
}

(async () => {
  hashPoseidon()
    .then((result) => {
      process.stdout.write(result);
      process.exit(0);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
})();
