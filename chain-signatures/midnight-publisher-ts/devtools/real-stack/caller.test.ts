import { createCircuitContext, createConstructorContext } from "@midnight-ntwrk/compact-runtime";
import { contractAddressToReference } from "@sig-net/midnight-contract-deploy";
import { expect, test } from "vitest";
import { Contract, ledger, pureCircuits } from "./managed/caller/contract/index.js";
import { createCallerPrivateState, witnesses } from "./witnesses.js";

test("storage-only creates a caller-owned request without a cross-contract notification", async () => {
  const callerAddress = "11".repeat(32);
  const coinPublicKey = "22".repeat(32);
  const secret = new Uint8Array(32).fill(3);
  const privateState = createCallerPrivateState(secret);
  const contract = new Contract(witnesses);
  const initial = await contract.initialState(
    createConstructorContext(privateState, coinPublicKey),
    pureCircuits.deployerCommitment(secret),
    contractAddressToReference("44".repeat(32)),
  );
  const target = new Uint8Array(20).fill(5);
  const argument = new Uint8Array(32);
  argument[31] = 6;
  const stored = await contract.impureCircuits.storeIsEvenRequest(
    createCircuitContext(
      "storeIsEvenRequest",
      callerAddress,
      coinPublicKey,
      initial.currentContractState,
      privateState,
    ),
    7n,
    1n,
    target,
    argument,
  );
  const state = ledger(stored.context.callContext.currentQueryContext.state);
  expect(stored.result).toHaveLength(32);
  expect(state.requests.size()).toBe(1n);
  expect(state.requestNonce).toBe(1n);
  expect(state.requests.member(stored.result)).toBe(true);
  expect(state.requests.lookup(stored.result)).toMatchObject({
    sender: contractAddressToReference(callerAddress),
    requestNonce: 0n,
    keyVersion: 1n,
    txParams: {
      chainId: 31337n,
      nonce: 7n,
      to: target,
      calldata: { is_some: true, value: { words: [argument] } },
    },
  });
  expect(stored.context.events).toEqual([]);
  expect(
    stored.context.callProofDataTrace.map(({ contractAddress, circuitId }) => ({
      contractAddress,
      circuitId,
    })),
  ).toEqual([{ contractAddress: callerAddress, circuitId: "storeIsEvenRequest" }]);
});
