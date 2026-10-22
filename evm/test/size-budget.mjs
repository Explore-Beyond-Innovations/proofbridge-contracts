#!/usr/bin/env node
// 81-b3: every contract under src/ that ships runtime code stays BUDGET bytes under EIP-170 (24,576), so a change
// that would push one over fails here, while there's still room to fix it, not at deploy. Run from contracts/evm
// after `forge build --skip test`.
import fs from "fs";
import path from "path";

const LIMIT = 24_576;
const BUDGET = Number(process.env.SIZE_BUDGET ?? 256);
const out = process.env.FORGE_OUT ?? "out";

const over = [];
const rows = [];
for (const dir of fs.readdirSync(out)) {
  const d = path.join(out, dir);
  if (!fs.statSync(d).isDirectory()) continue;
  for (const f of fs.readdirSync(d)) {
    if (!f.endsWith(".json")) continue;
    const a = JSON.parse(fs.readFileSync(path.join(d, f), "utf8"));
    const src = Object.keys(a.metadata?.settings?.compilationTarget ?? {})[0];
    if (typeof src !== "string" || !src.startsWith("src/")) continue;
    // a linked library's placeholder is 40 hex chars, the same 20 bytes as the address it becomes
    const hex = (a.deployedBytecode?.object ?? "").replace(/^0x/, "");
    if (hex.length === 0) continue;
    const size = hex.length / 2;
    rows.push([f.replace(/\.json$/, ""), size]);
    if (size > LIMIT - BUDGET) over.push(`${f.replace(/\.json$/, "")}: ${size} B, ${LIMIT - size} B under EIP-170 (budget ${BUDGET})`);
  }
}
if (rows.length === 0) {
  console.error(`size-budget: no src/ artifacts in ${out}; run forge build first`);
  process.exit(2);
}
if (over.length) {
  for (const o of over) console.error(`size-budget: ${o}`);
  process.exit(1);
}
rows.sort((x, y) => y[1] - x[1]);
console.log(`size-budget: ${rows.length} contracts each at least ${BUDGET} B under EIP-170; tightest ${rows[0][0]} at ${rows[0][1]} B`);
