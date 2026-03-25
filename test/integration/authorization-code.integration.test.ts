import { describe, expect, it } from "vitest";

import { buildModernConfig } from "../support/config-builder";
import {
  createPkcePair,
  readJson,
  readJwks,
  authorizeCode,
  exchangeAuthorizationCode
} from "../support/oauth-client";
import { assertJwtSignatureWithJwks, decodeJwtPayload } from "../support/jwt";
import { withOauthMockServer } from "../support/server-harness";

describe("authorization code flow", () => {
  it("issues RS256 id_tokens that verify against the published JWKS", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const pkce = createPkcePair();
      const nonce = "nonce-rs256-verify";
      const { code } = await authorizeCode(baseUrl, {
        clientId: "public-web",
        redirectUri: "http://localhost/public/callback",
        scope: "openid email profile",
        codeChallenge: pkce.challenge,
        state: "public-state",
        nonce
      });

      const tokenResponse = await exchangeAuthorizationCode(baseUrl, {
        clientId: "public-web",
        code,
        redirectUri: "http://localhost/public/callback",
        codeVerifier: pkce.verifier
      });

      const tokenPayload = await readJson(tokenResponse);
      const jwks = await readJwks(baseUrl);

      expect(tokenResponse.status).toBe(200);
      expect(tokenPayload.access_token).toBeTruthy();
      expect(tokenPayload.refresh_token).toBeFalsy();
      expect(typeof tokenPayload.id_token).toBe("string");

      assertJwtSignatureWithJwks(String(tokenPayload.id_token), jwks);
      const idTokenClaims = decodeJwtPayload(String(tokenPayload.id_token));
      expect(idTokenClaims.iss).toBe(baseUrl);
      expect(idTokenClaims.aud).toBe("public-web");
      expect(idTokenClaims.sub).toBe("user-admin");
      expect(idTokenClaims.nonce).toBe(nonce);
    });
  });

  it("supports client_secret_basic and client_secret_post for confidential clients", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const scenarios: Array<{
        name: string;
        authMethod: "basic" | "post";
      }> = [
        { name: "client_secret_basic", authMethod: "basic" },
        { name: "client_secret_post", authMethod: "post" }
      ];

      for (const scenario of scenarios) {
        const pkce = createPkcePair();
        const { code } = await authorizeCode(baseUrl, {
          clientId: "confidential-web",
          redirectUri: "http://localhost/confidential/callback",
          scope: "openid email profile offline_access",
          codeChallenge: pkce.challenge,
          state: scenario.name
        });

        const tokenResponse = await exchangeAuthorizationCode(baseUrl, {
          clientId: "confidential-web",
          clientSecret: "confidential-secret",
          authMethod: scenario.authMethod,
          code,
          redirectUri: "http://localhost/confidential/callback",
          codeVerifier: pkce.verifier
        });

        const tokenPayload = await readJson(tokenResponse);
        expect(tokenResponse.status).toBe(200);
        expect(tokenPayload.access_token).toBeTruthy();
        expect(tokenPayload.refresh_token).toBeTruthy();
        expect(typeof tokenPayload.id_token).toBe("string");

        const jwks = await readJwks(baseUrl);
        assertJwtSignatureWithJwks(String(tokenPayload.id_token), jwks);
      }
    });
  });
});
