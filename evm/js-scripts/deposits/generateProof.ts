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

export default async function generateProof(): Promise<string> {
  const inputs = process.argv.slice(2);

  // extract inputs
  const nullifierHash = inputs[0];
  const orderHash = inputs[1];
  const isAdContract = inputs[2];
  const secret = inputs[3];

  const leaves = inputs.slice(4);

  const tree = await merkleTree(leaves);
  const elementIndex = tree.getIndex(orderHash);

  if (elementIndex === undefined) {
    throw new Error("orderHash not found in provided leaves");
  }

  const merkleProof = await tree.genProof(elementIndex, orderHash);
  const targetRoot = await tree.getRoot();

  try {
    const noir = new Noir(circuit);
    const honk = new UltraHonkBackend(circuit.bytecode, { threads: 2 });

    const input = {
      nullifier_hash: nullifierHash,
      order_hash: modOrderHash(orderHash).toString(),
      target_root: targetRoot,
      ad_contract: isAdContract == "true" ? true : false,
      secret: secret,
      target_index: elementIndex,
      tree_width: merkleProof.width.toString(),
      target_sibling_hashes_len: merkleProof.siblings.length.toString(),
      target_sibling_hashes: padArray(
        merkleProof.siblings.map((i) => i.toString())
      ),
      target_peak_hashes_len: merkleProof.peaks.length.toString(),
      target_peak_hashes: padArray(merkleProof.peaks.map((i) => i.toString())),
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
