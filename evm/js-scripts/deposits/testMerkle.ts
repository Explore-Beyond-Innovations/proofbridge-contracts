import { Barretenberg, Fr } from "@aztec/bb.js";
import { toBeHex, zeroPadValue } from "ethers";
import {
  MerkleMountainRange as MMR,
  LevelDB,
  Poseidon2Hasher,
} from "proofbridge-mmr";
import fs from "fs";

async function run() {
  const bb = await Barretenberg.new();

  if (fs.existsSync("./test-db")) {
    fs.rmSync("./test-db", { recursive: true, force: true });
  }

  const db = new LevelDB("./test-db");
  await db.init();

  const hasher = new Poseidon2Hasher();
  const mmr = new MMR("test-mmr", db, hasher);

  let lastElem = 0;
  let lastOrderHash = Fr.ZERO;
  const hashes: string[] = [];
  const elementIndexes: number[] = [];

  for (let i = 0; i < 5; i++) {
    let x = hex(i);

    console.log(`element value ${i}:`, x);

    let hash = await bb.poseidon2Hash([Fr.fromString(x)]);
    hashes.push(hash.toString());
    const elementIndex = await mmr.append(hash.toString());
    elementIndexes.push(elementIndex);
    console.log(`element index: ${elementIndex}`);

    // Get root after each append
    const currentRoot = mmr.getHexRoot();
    console.log(`root after append ${i}: ${currentRoot}`);
    console.log(`hash: ${hash.toString()}`);
    console.log("---");

    lastElem = elementIndex;
    lastOrderHash = hash;
  }

  console.log("\n=== Summary ===");
  console.log("Width (leaf count):", mmr.width);
  console.log("Size (total nodes):", mmr.size);
  console.log("Final root:", mmr.getHexRoot());
  console.log("\nElement indexes:", elementIndexes);
  console.log("\nHashes:");
  hashes.forEach((h, i) => console.log(`  ${i}: ${h}`));

  // mmr.clear();
}

const hex = (n: number) => {
  return zeroPadValue(toBeHex(n), 32);
};

(async () => {
  run()
    .then(() => {
      process.exit(0);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
})();
