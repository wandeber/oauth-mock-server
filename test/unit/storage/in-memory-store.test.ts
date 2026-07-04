import { describe, expect, it } from "vitest";

import { createClientAssertionReplayStore } from "../../../src/storage/in-memory-store";

describe("createClientAssertionReplayStore", () => {
  it("tracks replay by client and jti without separator collisions", () => {
    const store = createClientAssertionReplayStore();

    expect(store.consumeOnce("a", "b:c", 1_000, 0)).toBe(true);
    expect(store.consumeOnce("a:b", "c", 1_000, 0)).toBe(true);
    expect(store.consumeOnce("a", "b:c", 1_000, 0)).toBe(false);
  });
});
