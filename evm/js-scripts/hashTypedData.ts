import { TypedDataEncoder, AbiCoder } from "ethers";
import { OrderTypedData, domain, orderTypes } from "./utils";

async function hashTypedData(): Promise<string> {
  let inputs = process.argv.slice(2);
  try {
    if (inputs.length == 0) {
      throw new Error("Required parameters not provided");
    }

    let orderValue: OrderTypedData = {
      orderChainToken: inputs[0],
      adChainToken: inputs[1],
      amount: inputs[2],
      bridger: inputs[3],
      orderChainId: inputs[4],
      orderPortal: inputs[5],
      orderRecipient: inputs[6],
      adChainId: inputs[7],
      adManager: inputs[8],
      adId: inputs[9],
      adCreator: inputs[10],
      adRecipient: inputs[11],
      salt: inputs[12],
    };

    let orderHash = TypedDataEncoder.hash(domain, orderTypes, orderValue);

    const result = AbiCoder.defaultAbiCoder().encode(["bytes32"], [orderHash]);
    return result;
  } catch (e) {
    console.log(e);
    throw e;
  }
}

(async () => {
  hashTypedData()
    .then((result) => {
      process.stdout.write(result);
      process.exit(0);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
})();
