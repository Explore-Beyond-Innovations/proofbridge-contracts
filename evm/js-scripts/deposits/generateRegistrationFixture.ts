import { execFileSync } from "child_process";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";

// Writes test/fixtures/registration-claim.json: a domain-4 inclusion proof of the vector maker's
// epoch-0 registration subject at the registry the vectors pin (chains.sepolia), mirroring
// RegistrationSubject.subject. Rerun whenever the subject bytes change:
//   npx tsx js-scripts/deposits/generateRegistrationFixture.ts
const TAG = ethers.keccak256(ethers.toUtf8Bytes("ProofBridge.BLSKeyRegistry.RegistrationLeaf.v1"));
const vectors = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../../../test-vectors/bls-encodings.json"), "utf8")
);
const chain = vectors.chains.sepolia;
const reg = vectors.registration.makerOnSepolia;
const epoch = 0n;

const subject = ethers.keccak256(
  ethers.concat([
    TAG,
    ethers.zeroPadValue(ethers.toBeHex(BigInt(chain.chainId)), 32),
    chain.registryId,
    reg.account,
    ethers.keccak256(reg.pkNative),
    ethers.zeroPadValue(ethers.toBeHex(epoch), 32),
  ])
);

const out = execFileSync(
  "npx",
  ["tsx", path.join(__dirname, "generateEventClaim.ts"), "4", subject],
  { maxBuffer: 1 << 26 }
).toString();
const [proof, pub] = ethers.AbiCoder.defaultAbiCoder().decode(["bytes", "bytes32[]"], out);

const outPath = path.resolve(__dirname, "../../test/fixtures/registration-claim.json");
fs.writeFileSync(
  outPath,
  JSON.stringify({ subject, epoch: epoch.toString(), root: pub[2], proof }, null, 2) + "\n"
);
console.log(`wrote ${outPath} (subject ${subject})`);
