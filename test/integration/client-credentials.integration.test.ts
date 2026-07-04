import { describe, expect, it } from "vitest";

import { buildModernConfig } from "../support/config-builder";
import {
  createClientAssertion,
  exchangeClientCredentials,
  readJson
} from "../support/oauth-client";
import {
  TEST_CLIENT_ASSERTION_KEY_ID,
  TEST_MACHINE_CLIENT_ID,
  TEST_MACHINE_CLIENT_SECRET,
  TEST_PRIVATE_KEY_JWT_CLIENT_ID,
  TEST_PUBLIC_CLIENT_ID,
  TEST_RSA_PRIVATE_KEY_PEM,
  TEST_STANDARD_SCOPES
} from "../support/constants";
import { withOauthMockServer } from "../support/server-harness";

describe("client credentials flow", () => {
  it("issues machine tokens for client_secret_basic and client_secret_post", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const scenarios: Array<{ authMethod: "basic" | "post" }> = [
        { authMethod: "basic" },
        { authMethod: "post" }
      ];

      for (const scenario of scenarios) {
        const tokenResponse = await exchangeClientCredentials(baseUrl, {
          clientId: TEST_MACHINE_CLIENT_ID,
          clientSecret: TEST_MACHINE_CLIENT_SECRET,
          authMethod: scenario.authMethod,
          scope: TEST_STANDARD_SCOPES.machineRead
        });
        const tokenPayload = await readJson(tokenResponse);

        expect(tokenResponse.status).toBe(200);
        expect(tokenPayload.access_token).toBeTruthy();
        expect(tokenPayload.token_type).toBe("Bearer");
        expect(tokenPayload.scope).toBe(TEST_STANDARD_SCOPES.machineRead);
        expect(tokenPayload.id_token).toBeUndefined();
        expect(tokenPayload.refresh_token).toBeUndefined();

        const introspectionResponse = await fetch(`${baseUrl}/introspect`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            token: String(tokenPayload.access_token)
          }).toString()
        });
        const introspectionPayload = await readJson(introspectionResponse);
        expect(introspectionPayload.active).toBe(true);
        expect(introspectionPayload.client_id).toBe(TEST_MACHINE_CLIENT_ID);
        expect(introspectionPayload.sub).toBe(TEST_MACHINE_CLIENT_ID);
        expect(introspectionPayload.scope).toBe(TEST_STANDARD_SCOPES.machineRead);

        const userInfoResponse = await fetch(`${baseUrl}/userinfo`, {
          headers: {
            Authorization: `Bearer ${String(tokenPayload.access_token)}`
          }
        });
        expect(userInfoResponse.status).toBe(403);
      }
    });
  });

  it("accepts certificate-style private_key_jwt client authentication", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const assertion = createClientAssertion({
        clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
        audience: `${baseUrl}/token`,
        privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
        keyId: TEST_CLIENT_ASSERTION_KEY_ID,
        algorithm: "PS256",
        jwtId: "client-credentials-assertion"
      });

      const tokenResponse = await exchangeClientCredentials(baseUrl, {
        clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
        authMethod: "private_key_jwt",
        clientAssertion: assertion,
        scope: TEST_STANDARD_SCOPES.machineRead
      });
      const tokenPayload = await readJson(tokenResponse);

      expect(tokenResponse.status).toBe(200);
      expect(tokenPayload.access_token).toBeTruthy();
      expect(tokenPayload.id_token).toBeUndefined();
      expect(tokenPayload.refresh_token).toBeUndefined();

      const replayResponse = await exchangeClientCredentials(baseUrl, {
        clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
        authMethod: "private_key_jwt",
        clientAssertion: assertion,
        scope: TEST_STANDARD_SCOPES.machineRead
      });
      const replayPayload = await readJson(replayResponse);
      expect(replayResponse.status).toBe(401);
      expect(replayPayload.error).toBe("invalid_client");
    });
  });

  it("rejects public clients that request client_credentials", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const tokenResponse = await exchangeClientCredentials(baseUrl, {
        clientId: TEST_PUBLIC_CLIENT_ID,
        scope: TEST_STANDARD_SCOPES.machineRead
      });
      const tokenPayload = await readJson(tokenResponse);

      expect(tokenResponse.status).toBe(400);
      expect(tokenPayload.error).toBe("unauthorized_client");
    });
  });
});
