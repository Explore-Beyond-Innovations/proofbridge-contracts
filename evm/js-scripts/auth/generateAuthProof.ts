import { UltraHonkBackend } from "@aztec/bb.js";
import { ethers, SigningKey } from "ethers";
import { Noir } from "@noir-lang/noir_js";
import path from "path";
import fs from "fs";
import { hexToArr } from "../utils";

const circuitPath = path.resolve(
  __dirname,
  "../../../proof_circuits/auth/target/auth_circuit.json"
);

const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf8"));

export default async function generateProof(): Promise<string> {
  const inputs = process.argv.slice(2);

  // extract inputs
  const nullifierHash = inputs[0];
  const maker = inputs[1];
  const makerSig = inputs[2];
  const bridger = inputs[3];
  const bridgerSig = inputs[4];
  const isAdContract = inputs[5];
  const orderHash = inputs[6];

  // make maker public key from signature
  const makerPublicKey = SigningKey.recoverPublicKey(orderHash, makerSig);

  // get bridger public key from signature
  const bridgerPublicKey = SigningKey.recoverPublicKey(orderHash, bridgerSig);

  try {
    const noir = new Noir(circuit);
    const honk = new UltraHonkBackend(circuit.bytecode, { threads: 1 });

    const input = {
      // Public inputs
      nullifier_hash: nullifierHash,
      ad_creator: maker,
      bridger: bridger,
      ad_contract: isAdContract == "true" ? true : false,
      msg_hash: hexToArr(orderHash),

      // Private Inputs
      ad_creator_pub_key: hexToArr(makerPublicKey),
      ad_creator_sig: hexToArr(makerSig, true),
      bridger_pub_key: hexToArr(bridgerPublicKey),
      bridger_sig: hexToArr(bridgerSig, true),
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
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
})();
