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
  methodIdentifiers?: Record<string, string>;
  deployedBytecode?: {
    object?: string;
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

/**
 * The runtime code a fresh deploy of this artifact leaves on chain, asked of the node itself: the
 * creation code (with the deploy's constructor args) runs as an `eth_call`, so immutables are filled
 * exactly as a deploy fills them and the answer compares byte for byte with `getCode`.
 */
export async function runtimeCodeOf(
  provider: ethers.Provider,
  contractFile: string,
  contractName: string,
  constructorArgs: unknown[] = [],
): Promise<string> {
  const { abi, bytecode } = loadArtifact(contractFile, contractName);
  if (Object.keys(bytecode.linkReferences ?? {}).length > 0) {
    throw new Error(`runtimeCodeOf: ${contractName} links libraries; link it before simulating the deploy`);
  }
  const tx = await new ethers.ContractFactory(abi, bytecode.object).getDeployTransaction(...constructorArgs);
  return provider.call({ data: tx.data });
}

export function getAbi(contractFile: string, contractName: string): any[] {
  return loadArtifact(contractFile, contractName).abi;
}

/**
 * A function's selector as solc computed it, by the signature `forge inspect <name> methodIdentifiers`
 * prints. Needed where a client cannot derive it: a library's `public` function that takes a struct
 * is hashed by the struct's declared name (`digest(OrderHash.Order)`), not the tuple the ABI lists, so
 * ethers and cast both call a selector the library does not have.
 */
export function methodIdentifier(contractFile: string, contractName: string, signature: string): string {
  const id = loadArtifact(contractFile, contractName).methodIdentifiers?.[signature];
  if (!id) throw new Error(`artifact ${contractFile}.sol/${contractName}.json records no selector for ${signature}`);
  return "0x" + id;
}

/** The artifact's runtime bytecode, as `forge build` recorded it (link placeholders unresolved). */
export function deployedCode(contractFile: string, contractName: string): string {
  const code = loadArtifact(contractFile, contractName).deployedBytecode?.object;
  if (!code) throw new Error(`artifact ${contractFile}.sol/${contractName}.json records no deployedBytecode`);
  return code;
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

/**
 * The library address a deployed contract was linked with, read out of its on-chain code at the
 * offset the artifact records for the runtime bytecode. Null when the artifact has no such
 * reference or the code is too short to hold it (a different build, or not this contract).
 */
export function linkedLibraryIn(
  contractFile: string,
  contractName: string,
  libName: string,
  runtimeCode: string,
): string | null {
  const refs = loadArtifact(contractFile, contractName).deployedBytecode?.linkReferences ?? {};
  for (const libs of Object.values(refs)) {
    const spot = libs[libName]?.[0];
    if (!spot) continue;
    const hex = runtimeCode.slice(2 + spot.start * 2, 2 + (spot.start + spot.length) * 2);
    return hex.length === spot.length * 2 ? ethers.getAddress("0x" + hex) : null;
  }
  return null;
}
