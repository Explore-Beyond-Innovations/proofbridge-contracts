import * as fs from "fs";
import * as path from "path";
import { ethers } from "ethers";
import { artifactsDir } from "./common.js";

interface LinkReference {
  start: number;
  length: number;
}

interface Artifact {
  abi: any[];
  bytecode: {
    object: string;
    linkReferences?: Record<string, Record<string, LinkReference[]>>;
  };
}

function loadArtifact(contractFile: string, contractName: string): Artifact {
  const p = path.join(
    artifactsDir(),
    `${contractFile}.sol`,
    `${contractName}.json`,
  );
  if (!fs.existsSync(p)) {
    throw new Error(
      `Foundry artifact not found: ${p} — run 'forge build' in contracts/evm or point EVM_OUT_DIR at an extracted bundle`,
    );
  }
  return JSON.parse(fs.readFileSync(p, "utf8")) as Artifact;
}

export function getAbi(contractFile: string, contractName: string): any[] {
  return loadArtifact(contractFile, contractName).abi;
}

export function contractFactory(
  contractFile: string,
  contractName: string,
  signer: ethers.Wallet,
): ethers.ContractFactory {
  const { abi, bytecode } = loadArtifact(contractFile, contractName);
  return new ethers.ContractFactory(abi, bytecode.object, signer);
}

/**
 * Factory for a contract whose bytecode references deployed libraries.
 * `libraries` maps the library name (as it appears in the artifact's
 * linkReferences, e.g. "SCL_EIP6565") to its deployed address; the
 * placeholder bytes are substituted at the offsets the artifact records.
 */
export function contractFactoryLinked(
  contractFile: string,
  contractName: string,
  signer: ethers.Wallet,
  libraries: Record<string, string>,
): ethers.ContractFactory {
  const { abi, bytecode } = loadArtifact(contractFile, contractName);
  const refs = bytecode.linkReferences ?? {};
  let code = bytecode.object.replace(/^0x/, "");

  const unresolved: string[] = [];
  for (const [file, libs] of Object.entries(refs)) {
    for (const [libName, sites] of Object.entries(libs)) {
      const addr = libraries[libName];
      if (!addr) {
        unresolved.push(`${file}:${libName}`);
        continue;
      }
      const clean = addr.replace(/^0x/, "").toLowerCase();
      if (clean.length !== 40) {
        throw new Error(`invalid library address for ${libName}: ${addr}`);
      }
      for (const { start, length } of sites) {
        code =
          code.slice(0, start * 2) + clean + code.slice((start + length) * 2);
      }
    }
  }
  if (unresolved.length > 0) {
    throw new Error(
      `unlinked library reference(s) in ${contractName}: ${unresolved.join(", ")}`,
    );
  }
  return new ethers.ContractFactory(abi, "0x" + code, signer);
}

export function attachContract(
  address: string,
  contractFile: string,
  contractName: string,
  signer: ethers.Wallet,
): ethers.Contract {
  return new ethers.Contract(address, getAbi(contractFile, contractName), signer);
}
