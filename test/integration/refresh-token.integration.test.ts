import { describe, expect, it } from "vitest";

import { buildModernConfig } from "../support/config-builder";
import {
  createPkcePair,
  exchangeAuthorizationCode,
  exchangeRefreshToken,
  readJson,
  authorizeCode
} from "../support/oauth-client";
import { withOauthMockServer } from "../support/server-harness";

describe("refresh token flow", () => {
  it("rotates refresh tokens and rejects reuse", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const pkce = createPkcePair();
      const { code } = await authorizeCode(baseUrl, {
        clientId: "confidential-web",
        redirectUri: "http://localhost/confidential/callback",
        scope: "openid email profile offline_access",
        codeChallenge: pkce.challenge
      });

      const initialTokenResponse = await exchangeAuthorizationCode(baseUrl, {
        clientId: "confidential-web",
        clientSecret: "confidential-secret",
        authMethod: "post",
        code,
        redirectUri: "http://localhost/confidential/callback",
        codeVerifier: pkce.verifier
      });
      const initialPayload = await readJson(initialTokenResponse);
      const originalRefreshToken = String(initialPayload.refresh_token ?? "");
      expect(originalRefreshToken).toBeTruthy();

      const rotatedResponse = await exchangeRefreshToken(baseUrl, {
        clientId: "confidential-web",
        clientSecret: "confidential-secret",
        authMethod: "post",
        refreshToken: originalRefreshToken
      });
      const rotatedPayload = await readJson(rotatedResponse);
      const rotatedRefreshToken = String(rotatedPayload.refresh_token ?? "");

      expect(rotatedResponse.status).toBe(200);
      expect(rotatedRefreshToken).toBeTruthy();
      expect(rotatedRefreshToken).not.toBe(originalRefreshToken);

      const reuseResponse = await exchangeRefreshToken(baseUrl, {
        clientId: "confidential-web",
        clientSecret: "confidential-secret",
        authMethod: "post",
        refreshToken: originalRefreshToken
      });
      const reusePayload = await readJson(reuseResponse);
      expect(reuseResponse.status).toBeGreaterThanOrEqual(400);
      expect(reusePayload.error).toBe("invalid_grant");

      const secondRotation = await exchangeRefreshToken(baseUrl, {
        clientId: "confidential-web",
        clientSecret: "confidential-secret",
        authMethod: "basic",
        refreshToken: rotatedRefreshToken
      });
      expect(secondRotation.status).toBe(200);
    });
  });
});
