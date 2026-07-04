import { describe, expect, it } from "vitest";

import { buildModernConfig } from "../support/config-builder";
import { fetchJson, readJwks } from "../support/oauth-client";
import { withOauthMockServer } from "../support/server-harness";

describe("oauth mock server discovery", () => {
  it("publishes coherent discovery metadata and JWKS", async () => {
    await withOauthMockServer(buildModernConfig(), async ({ baseUrl }) => {
      const oauthMetadata = await fetchJson(`${baseUrl}/.well-known/oauth-authorization-server`);
      const oidcMetadata = await fetchJson(`${baseUrl}/.well-known/openid-configuration`);
      const jwks = await readJwks(baseUrl);

      expect(oauthMetadata.issuer).toBe(baseUrl);
      expect(oauthMetadata.authorization_endpoint).toBe(`${baseUrl}/authorize`);
      expect(oauthMetadata.token_endpoint).toBe(`${baseUrl}/token`);
      expect(oauthMetadata.userinfo_endpoint).toBe(`${baseUrl}/userinfo`);
      expect(oauthMetadata.jwks_uri).toBe(`${baseUrl}/jwks`);
      expect(oauthMetadata.response_types_supported).toEqual(expect.arrayContaining(["code"]));
      expect(oauthMetadata.grant_types_supported).toEqual(
        expect.arrayContaining(["authorization_code", "refresh_token", "client_credentials"])
      );
      expect(oauthMetadata.token_endpoint_auth_methods_supported).toEqual(
        expect.arrayContaining(["client_secret_basic", "client_secret_post", "private_key_jwt"])
      );
      expect(oauthMetadata.token_endpoint_auth_signing_alg_values_supported).toEqual(
        expect.arrayContaining(["RS256", "PS256"])
      );
      expect(oauthMetadata.id_token_signing_alg_values_supported).toEqual(
        expect.arrayContaining(["RS256"])
      );

      expect(oidcMetadata.issuer).toBe(baseUrl);
      expect(oidcMetadata.jwks_uri).toBe(`${baseUrl}/jwks`);
      expect(Array.isArray(jwks.keys)).toBe(true);
      expect((jwks.keys as Array<Record<string, unknown>>)[0].kid).toBe("dev-test-rs256");
    });
  });
});
