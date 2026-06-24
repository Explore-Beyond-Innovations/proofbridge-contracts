import { UltraHonkBackend } from "@aztec/bb.js";
import { ethers } from "ethers";
import { Noir } from "@noir-lang/noir_js";
import path from "path";
import fs from "fs";
import { merkleTree } from "./merkleTree";
import { modOrderHash, padArray } from "../utils";

const circuitPath = path.resolve(
  __dirname,
  "../../../../proof_circuits/deposits/target/deposit_circuit.json"
);

const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf8"));

const padBool = (arr: boolean[], n: number): boolean[] => [
  ...arr,
  ...Array(n - arr.length).fill(false),
];

export default async function generateProof(): Promise<string> {
  const inputs = process.argv.slice(2);

  // extract inputs
  const nullifierHash = inputs[0];
  const orderHash = inputs[1];
  const isAdContract = inputs[2] === "true";
  const secret = inputs[3];
  const leaves = inputs.slice(4);

  // single-side tree: every leaf carries this side (1 = ad, 0 = order)
  const side = isAdContract ? 1 : 0;

  const tree = await merkleTree(leaves, side);
  const elementIndex = tree.getIndex(orderHash);
  const merkleProof = await tree.genProof(elementIndex, orderHash);

  try {
    const noir = new Noir(circuit);
    const honk = new UltraHonkBackend(circuit.bytecode, { threads: 2 });

    // lean circuit: navigation is supplied as untrusted hints (directions / parent indices / chosen peak)
    const input = {
      nullifier_hash: nullifierHash,
      order_hash: modOrderHash(orderHash).toString(),
      target_root: merkleProof.root,
      ad_contract: isAdContract,
      secret: secret,
      leaf_index: merkleProof.elementIndex.toString(),
      width: merkleProof.width.toString(),
      path_len: merkleProof.siblings.length.toString(),
      siblings: padArray(merkleProof.siblings, 32),
      sib_is_left: padBool(merkleProof.directions, 32),
      parent_index: padArray(merkleProof.parentIndices.map(String), 32),
      peaks: padArray(merkleProof.peaks, 32),
      peaks_len: merkleProof.peaks.length.toString(),
      chosen_peak: merkleProof.chosenPeak.toString(),
    };

    const { witness } = await noir.execute(input);
    const { proof, publicInputs } = await honk.generateProof(witness, {
      keccak: true,
    });

    const result = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes32[]"],
      [proof, publicInputs]
    );
    return result;
  } catch (e) {
    console.log(e);
    throw e;
  }
}

(async () => {
  generateProof()
    .then((result) => {
      process.stdout.write(result);
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
})();
