import * as fs from "fs";
import * as path from "path";
import { ethers } from "ethers";
import { artifactsDir } from "./common.js";

interface Artifact {
  abi: any[];
  bytecode: { object: string };
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

export function attachContract(
  address: string,
  contractFile: string,
  contractName: string,
  signer: ethers.Wallet,
): ethers.Contract {
  return new ethers.Contract(address, getAbi(contractFile, contractName), signer);
}
