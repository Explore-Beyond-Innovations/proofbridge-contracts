import { Fr } from "@aztec/bb.js";
const fs = require("fs");
const path = require("path");
import {
  MerkleMountainRange as MMR,
  LevelDB,
  Poseidon2Hasher,
} from "proofbridge-mmr";

export class MerkleTree {
  private db: LevelDB;
  private mmr: MMR;
  private elementIndexMap: Map<string, number> = new Map();
  private hasher = new Poseidon2Hasher();

  constructor() {
    this.db = new LevelDB("./merkle_tree_db");
  }

  async init(id: string, defaultLeaves: string[] = []) {
    await this.db.init();

    this.mmr = new MMR(id, this.db, this.hasher);

    for (const leaf of defaultLeaves) {
      await this.append(leaf);
    }
  }

  async append(value: string) {
    const x = this.mod(value);
    const elementIndex = await this.mmr.append(x.toString());
    this.elementIndexMap.set(x.toString(), elementIndex);
    return { elementIndex, x };
  }

  getIndex(value: string) {
    const x = this.mod(value);
    const idx = this.elementIndexMap.get(x.toString());
    if (idx === undefined) throw new Error("Element not found in tree");
    return idx;
  }

  async genProof(elementIndex: number, orderHash: string) {
    const x = this.mod(orderHash);
    const proof = await this.mmr.getMerkleProof(elementIndex);
    const isValid = this.mmr.verify(
      proof.root,
      proof.width,
      elementIndex,
      orderHash,
      proof.peaks,
      proof.siblings
    );
    if (!isValid) {
      throw new Error("Invalid proof generated");
    }
    return proof;
  }

  async getRoot() {
    return this.mmr.getHexRoot();
  }

  private mod(n: string) {
    const buff = Buffer.from(n.replace(/^0x/i, ""), "hex");
    return Fr.fromBufferReduce(buff);
  }
}

export async function merkleTree(leaves: string[]) {
  const tree = new MerkleTree();

  const id = Math.random().toString(36).substring(2, 15);

  // Initialize tree with no leaves (all zeros)
  await tree.init(id);

  // Insert some leaves (from input)
  for (const leaf of leaves) {
    await tree.append(leaf);
  }

  return tree;
}
