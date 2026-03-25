import { describe, expect, it } from "vitest";

import { normalizeConfig } from "../../../src/config/normalize-config";
import { authenticateClient } from "../../../src/oauth/client-auth";
import { buildModernConfig } from "../../support/config-builder";
import {
  TEST_CONFIDENTIAL_CLIENT_ID,
  TEST_CONFIDENTIAL_CLIENT_SECRET,
  TEST_PUBLIC_CLIENT_ID
} from "../../support/constants";

function buildBasicAuthHeader(clientId: string, clientSecret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64")}`;
}

describe("authenticateClient", () => {
  it("accepts public clients identified only by client_id", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const result = authenticateClient(undefined, { client_id: TEST_PUBLIC_CLIENT_ID }, config);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.id).toBe(TEST_PUBLIC_CLIENT_ID);
    }
  });

  it("accepts confidential clients using client_secret_basic", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const result = authenticateClient(
      buildBasicAuthHeader(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET),
      {},
      config
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.id).toBe(TEST_CONFIDENTIAL_CLIENT_ID);
    }
  });

  it("rejects mismatched credentials between basic auth and request body", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const result = authenticateClient(
      buildBasicAuthHeader(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET),
      {
        client_id: TEST_CONFIDENTIAL_CLIENT_ID,
        client_secret: "different-secret"
      },
      config
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_client");
      expect(result.errorDescription).toMatch(/client_secret mismatch/);
    }
  });
});
