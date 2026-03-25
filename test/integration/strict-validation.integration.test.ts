import { describe, expect, it } from "vitest";

import { buildModernConfig } from "../support/config-builder";
import { createPkcePair, exchangeAuthorizationCode, readJson, authorizeCode } from "../support/oauth-client";
import { withOauthMockServer } from "../support/server-harness";

describe("strict validation", () => {
  it("rejects invalid authorize and token inputs strictly", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const pkce = createPkcePair();
      const authorizeScenarios = [
        new URLSearchParams({
          client_id: "missing-client",
          redirect_uri: "http://localhost/public/callback",
          response_type: "code",
          scope: "openid email",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256"
        }),
        new URLSearchParams({
          client_id: "public-web",
          redirect_uri: "http://localhost/not-registered",
          response_type: "code",
          scope: "openid email",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256"
        }),
        new URLSearchParams({
          client_id: "public-web",
          redirect_uri: "http://localhost/public/callback",
          response_type: "token",
          scope: "openid email",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256"
        }),
        new URLSearchParams({
          client_id: "public-web",
          redirect_uri: "http://localhost/public/callback",
          response_type: "code",
          scope: "openid unauthorized-scope",
          code_challenge: pkce.challenge,
          code_challenge_method: "S256"
        })
      ];

      for (const query of authorizeScenarios) {
        const response = await fetch(`${baseUrl}/authorize?${query.toString()}`, {
          redirect: "manual"
        });
        const payload = await readJson(response);
        expect(response.status).toBeGreaterThanOrEqual(400);
        expect(payload.error).toBeTruthy();
      }

      const validPkce = createPkcePair();
      const { code } = await authorizeCode(baseUrl, {
        clientId: "public-web",
        redirectUri: "http://localhost/public/callback",
        scope: "openid email profile",
        codeChallenge: validPkce.challenge
      });

      const invalidGrant = await fetch(`${baseUrl}/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: "public-web",
          grant_type: "refresh_token",
          refresh_token: "not-used-yet"
        }).toString()
      });
      const invalidGrantPayload = await readJson(invalidGrant);
      expect(invalidGrant.status).toBeGreaterThanOrEqual(400);
      expect(invalidGrantPayload.error).toBeTruthy();

      const invalidAuth = await exchangeAuthorizationCode(baseUrl, {
        clientId: "confidential-web",
        clientSecret: "wrong-secret",
        authMethod: "post",
        code,
        redirectUri: "http://localhost/public/callback",
        codeVerifier: validPkce.verifier
      });
      const invalidAuthPayload = await readJson(invalidAuth);
      expect(invalidAuth.status).toBeGreaterThanOrEqual(400);
      expect(invalidAuthPayload.error).toBeTruthy();
    });
  });
});
