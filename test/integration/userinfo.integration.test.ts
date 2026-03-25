import { describe, expect, it } from "vitest";

import { buildModernConfig } from "../support/config-builder";
import {
  createPkcePair,
  exchangeAuthorizationCode,
  readJson,
  authorizeCode
} from "../support/oauth-client";
import { withOauthMockServer } from "../support/server-harness";

describe("userinfo endpoint", () => {
  it("serves userinfo consistent with the access token and granted scopes", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const pkce = createPkcePair();
      const { code } = await authorizeCode(baseUrl, {
        clientId: "email-only-web",
        redirectUri: "http://localhost/email-only/callback",
        scope: "openid email",
        codeChallenge: pkce.challenge
      });

      const tokenResponse = await exchangeAuthorizationCode(baseUrl, {
        clientId: "email-only-web",
        code,
        redirectUri: "http://localhost/email-only/callback",
        codeVerifier: pkce.verifier
      });

      const tokenPayload = await readJson(tokenResponse);
      const accessToken = String(tokenPayload.access_token ?? "");
      expect(accessToken).toBeTruthy();

      const userInfoResponse = await fetch(`${baseUrl}/userinfo`, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });
      const userInfoPayload = await readJson(userInfoResponse);

      expect(userInfoResponse.status).toBe(200);
      expect(userInfoPayload.sub).toBe("user-admin");
      expect(userInfoPayload.email).toBe("admin@local.test");
      expect(userInfoPayload.name).toBeUndefined();
    });
  });
});
