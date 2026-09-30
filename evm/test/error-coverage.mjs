#!/usr/bin/env node
// 49E-3: every custom error in the escrow contracts' ABIs (out/*.json, so nothing is listed by hand)
// must be named by some test, as `X.Name` or `Name.selector`. A new error fails this until a test
// names it, or it is exempted below with the reason it cannot be reached. Run from contracts/evm.
import fs from "fs";
import path from "path";

const CONTRACTS = ["AdManager", "OrderPortal", "DisputeManager"];
// Errors no test can reach, each with why. Keep this short: an entry here is a claim someone checked.
const UNREACHABLE = {};

const out = process.env.FORGE_OUT ?? "out";
const testSrc = [];
const walk = (d) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith(".sol")) testSrc.push(fs.readFileSync(p, "utf8"));
  }
};
walk("test");
const tests = testSrc.join("\n");

const missing = [];
let total = 0;
for (const c of CONTRACTS) {
  const f = path.join(out, `${c}.sol`, `${c}.json`);
  if (!fs.existsSync(f)) {
    console.error(`error-coverage: ${f} not found; run forge build`);
    process.exit(2);
  }
  const names = [...new Set(JSON.parse(fs.readFileSync(f, "utf8")).abi.filter((x) => x.type === "error").map((x) => x.name))];
  if (names.length === 0) {
    console.error(`error-coverage: ${c} has no errors in its ABI; the gate would check nothing`);
    process.exit(2);
  }
  total += names.length;
  for (const n of names) {
    if (n in UNREACHABLE) continue;
    if (!new RegExp(`(\\.\\s*${n}\\b|\\b${n}\\s*\\.\\s*selector)`).test(tests)) missing.push(`${c}.${n}`);
  }
}
if (missing.length) {
  console.error(`error-coverage: ${missing.length} escrow error(s) no test names: ${missing.join(", ")}`);
  process.exit(1);
}
console.log(`error-coverage: ${total} errors across ${CONTRACTS.join(", ")}, every one named by a test`);
