import { Fr } from "@aztec/bb.js";
import {
  MerkleMountainRange as MMR,
  LevelDB,
  Poseidon2Hasher,
  encodeLeaf,
} from "proofbridge-mmr";

export class MerkleTree {
  private db: LevelDB;
  private mmr: MMR;
  private elementIndexMap: Map<string, number> = new Map();
  private hasher = new Poseidon2Hasher();
  private side = 0; // 1 = ad, 0 = order; drives the leaf-side binding

  constructor() {
    this.db = new LevelDB("./merkle_tree_db");
  }

  async init(id: string, side: number, defaultLeaves: string[] = []) {
    await this.db.init();
    this.side = side;
    this.mmr = new MMR(id, this.db, this.hasher);
    for (const leaf of defaultLeaves) {
      await this.append(leaf);
    }
  }

  // leaf-side binding: the appended value is poseidon2(orderHash, side)
  async append(orderHash: string) {
    const leaf = encodeLeaf(orderHash, this.side, this.hasher);
    const elementIndex = await this.mmr.append(leaf);
    this.elementIndexMap.set(this.mod(orderHash).toString(), elementIndex);
    return { elementIndex };
  }

  getIndex(orderHash: string) {
    const idx = this.elementIndexMap.get(this.mod(orderHash).toString());
    if (idx === undefined) throw new Error("Element not found in tree");
    return idx;
  }

  async genProof(elementIndex: number, orderHash: string) {
    const value = "0x" + encodeLeaf(orderHash, this.side, this.hasher).toString("hex");
    const proof = await this.mmr.getMerkleProof(elementIndex);
    const isValid = this.mmr.verify(
      proof.root,
      proof.width,
      elementIndex,
      value,
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

export async function merkleTree(leaves: string[], side: number) {
  const tree = new MerkleTree();
  const id = Math.random().toString(36).substring(2, 15);

  await tree.init(id, side);
  for (const leaf of leaves) {
    await tree.append(leaf);
  }

  return tree;
}
