import { spawn, type ChildProcess } from "child_process";
import * as net from "net";
import { ethers } from "ethers";

// A real Anvil per test file: the call-site specs drive the CLI's own entry points against a node,
// so deleting a check at its call site turns them red. Needs `anvil` on PATH (Foundry).

/** Anvil's funded account #0 (the deployer in every spec) and #1. */
export const K0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const A0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
export const A1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

export interface Anvil {
  url: string;
  provider: ethers.JsonRpcProvider;
  /** The deployer's transaction count: equal before and after means nothing was sent. */
  nonce(): Promise<number>;
  stop(): void;
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(port));
    });
  });
}

export async function startAnvil(chainId: number, extraArgs: string[] = []): Promise<Anvil> {
  const port = await freePort();
  const child: ChildProcess = spawn("anvil", ["--port", String(port), "--chain-id", String(chainId), "--silent", ...extraArgs], {
    stdio: "ignore",
  });
  let spawnError: Error | undefined;
  child.once("error", (e) => (spawnError = e));
  const url = `http://127.0.0.1:${port}`;
  const provider = new ethers.JsonRpcProvider(url, undefined, { staticNetwork: true, pollingInterval: 100 });
  for (let i = 0; ; i++) {
    if (spawnError) throw new Error(`could not start anvil (is Foundry installed?): ${spawnError.message}`);
    try {
      await provider.send("eth_chainId", []);
      break;
    } catch {
      if (i > 100) throw new Error(`anvil on ${url} did not answer`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  return {
    url,
    provider,
    nonce: () => provider.getTransactionCount(A0),
    stop: () => {
      provider.destroy();
      child.kill();
    },
  };
}

/** Run `fn` with these process.env entries set (undefined deletes), restoring them afterwards. */
export async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}
