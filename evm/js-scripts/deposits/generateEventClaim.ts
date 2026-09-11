import { UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { ethers } from "ethers";
import path from "path";
import fs from "fs";
import {
  MemoryStore,
  MerkleMountainRange,
  Poseidon2Hasher,
  encodeLeaf,
  leanInputs,
} from "proofbridge-mmr";
import { modOrderHash } from "../utils";

const circuitPath = path.resolve(
  __dirname,
  "../../../../proof_circuits/events/target/event_circuit.json"
);

const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf8"));

// args: <leafDomain> <subject>. An event claim: no secret, nullifier 0. The tree also holds the
// subject's two deposit leaves, so the claim sits next to the leaves it must never be confused with.
export default async function generateEventClaim(): Promise<string> {
  const [domainArg, subjectArg] = process.argv.slice(2);
  const domain = Number(domainArg);
  const subject = modOrderHash(subjectArg).toString();

  const hasher = new Poseidon2Hasher();
  const mmr = new MerkleMountainRange("claim", new MemoryStore(), hasher);
  await mmr.init();
  await mmr.append(encodeLeaf(subject, 0, hasher));
  await mmr.append(encodeLeaf(subject, 1, hasher));
  const elementIndex = await mmr.append(encodeLeaf(subject, domain, hasher));
  const merkleProof = await mmr.getMerkleProof(elementIndex);

  const noir = new Noir(circuit);
  const honk = new UltraHonkBackend(circuit.bytecode, { threads: 2 });
  const { witness } = await noir.execute({
    nullifier_hash: "0",
    order_hash: subject,
    target_root: merkleProof.root,
    leaf_domain: String(domain),
    secret: "0",
    ...leanInputs(merkleProof),
  });
  const { proof, publicInputs } = await honk.generateProof(witness, {
    keccak: true,
  });

  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes32[]"],
    [proof, publicInputs]
  );
}

(async () => {
  generateEventClaim()
    .then((result) => {
      process.stdout.write(result);
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
})();
