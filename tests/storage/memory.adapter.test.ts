import { MemoryStoreAdapter } from "../../src/storage/adapters/memory.adapter";
import { runAdapterContractTests } from "./adapter-contract.suite";

runAdapterContractTests("MemoryStoreAdapter", async () => {
  return new MemoryStoreAdapter();
});
