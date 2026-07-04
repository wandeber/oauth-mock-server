import crypto from "node:crypto";
import { describe, expect, it } from "vitest";

import { normalizeConfig } from "../../../src/config/normalize-config";
import { authenticateClient } from "../../../src/oauth/client-auth";
import { createInMemoryOauthStores } from "../../../src/storage/in-memory-store";
import { buildModernConfig } from "../../support/config-builder";
import { createClientAssertion } from "../../support/oauth-client";
import {
  TEST_CLIENT_ASSERTION_KEY_ID,
  TEST_CONFIDENTIAL_CLIENT_ID,
  TEST_CONFIDENTIAL_CLIENT_SECRET,
  TEST_PRIVATE_KEY_JWT_CLIENT_ID,
  TEST_PUBLIC_CLIENT_ID,
  TEST_RSA_CERTIFICATE_PEM,
  TEST_RSA_PRIVATE_KEY_PEM
} from "../../support/constants";

function buildBasicAuthHeader(clientId: string, clientSecret: string): string {
  const encodedCredentials = `${encodeFormComponent(clientId)}:${encodeFormComponent(clientSecret)}`;
  return `Basic ${Buffer.from(encodedCredentials, "utf8").toString("base64")}`;
}

function replaceJwtHeader(assertion: string, overrides: Record<string, unknown>): string {
  const [encodedHeader, encodedPayload, encodedSignature] = assertion.split(".");
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
  // This helper intentionally invalidates the signature. That is useful for
  // asserting validations that must run before signature verification, such as
  // rejecting unsupported algorithms without ever touching key material.
  return `${Buffer.from(JSON.stringify({ ...header, ...overrides }), "utf8").toString(
    "base64url"
  )}.${encodedPayload}.${encodedSignature}`;
}

describe("authenticateClient", () => {
  it("accepts public clients identified only by client_id", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const stores = createInMemoryOauthStores();
    const result = authenticateClient(
      undefined,
      { client_id: TEST_PUBLIC_CLIENT_ID },
      config,
      stores.clientAssertions
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.id).toBe(TEST_PUBLIC_CLIENT_ID);
    }
  });

  it("accepts confidential clients using client_secret_basic", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const stores = createInMemoryOauthStores();
    const result = authenticateClient(
      buildBasicAuthHeader(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET),
      {},
      config,
      stores.clientAssertions
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.id).toBe(TEST_CONFIDENTIAL_CLIENT_ID);
    }
  });

  it("accepts form-encoded client_secret_basic credentials", () => {
    const config = normalizeConfig(
      {
        server: {},
        identities: {
          user: {
            claims: { sub: "user" }
          }
        },
        clients: {
          "special:client": {
            type: "confidential",
            clientSecret: "sec:ret% with spaces",
            redirectUris: ["http://localhost/callback"],
            defaultIdentity: "user",
            allowedScopes: ["openid"]
          }
        }
      },
      {} as NodeJS.ProcessEnv
    );
    const stores = createInMemoryOauthStores();
    const result = authenticateClient(
      buildBasicAuthHeader("special:client", "sec:ret% with spaces"),
      {},
      config,
      stores.clientAssertions
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.id).toBe("special:client");
      expect(result.method).toBe("client_secret_basic");
    }
  });

  it("rejects requests that mix token endpoint authentication methods", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const stores = createInMemoryOauthStores();
    const result = authenticateClient(
      buildBasicAuthHeader(TEST_CONFIDENTIAL_CLIENT_ID, TEST_CONFIDENTIAL_CLIENT_SECRET),
      {
        client_id: TEST_CONFIDENTIAL_CLIENT_ID,
        client_secret: "different-secret"
      },
      config,
      stores.clientAssertions
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_client");
      expect(result.errorDescription).toMatch(/exactly one/);
    }
  });

  it("accepts confidential clients using private_key_jwt", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const stores = createInMemoryOauthStores();
    const assertion = createClientAssertion({
      clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
      audience: `${config.server.issuer}/token`,
      privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
      keyId: TEST_CLIENT_ASSERTION_KEY_ID
    });

    const result = authenticateClient(
      undefined,
      {
        client_id: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion
      },
      config,
      stores.clientAssertions
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.id).toBe(TEST_PRIVATE_KEY_JWT_CLIENT_ID);
      expect(result.method).toBe("private_key_jwt");
    }
  });

  it("accepts private_key_jwt assertions selected by certificate thumbprint", () => {
    const rawConfig = buildModernConfig() as Record<string, unknown>;
    const clients = rawConfig.clients as Record<string, Record<string, unknown>>;
    clients[TEST_PRIVATE_KEY_JWT_CLIENT_ID] = {
      ...clients[TEST_PRIVATE_KEY_JWT_CLIENT_ID],
      clientAssertionKeys: [
        {
          certificatePem: TEST_RSA_CERTIFICATE_PEM
        }
      ]
    };
    const config = normalizeConfig(rawConfig, {} as NodeJS.ProcessEnv);
    const stores = createInMemoryOauthStores();
    const certificate = new crypto.X509Certificate(TEST_RSA_CERTIFICATE_PEM);
    const assertion = createClientAssertion({
      clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
      audience: `${config.server.issuer}/token`,
      privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
      x5tS256: crypto.createHash("sha256").update(certificate.raw).digest("base64url")
    });

    const result = authenticateClient(
      undefined,
      {
        client_id: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion
      },
      config,
      stores.clientAssertions
    );

    expect(result.ok).toBe(true);
  });

  it("rejects non-RSA private_key_jwt verification keys", () => {
    const rawConfig = buildModernConfig() as Record<string, unknown>;
    const clients = rawConfig.clients as Record<string, Record<string, unknown>>;
    const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    clients[TEST_PRIVATE_KEY_JWT_CLIENT_ID] = {
      ...clients[TEST_PRIVATE_KEY_JWT_CLIENT_ID],
      clientAssertionKeys: [
        {
          publicJwk: publicKey.export({ format: "jwk" })
        }
      ]
    };

    expect(() => normalizeConfig(rawConfig, {} as NodeJS.ProcessEnv)).toThrow(/RSA public key/);
  });

  it("rejects invalid private_key_jwt assertions", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const wrongPrivateKeyPem = crypto
      .generateKeyPairSync("rsa", { modulusLength: 2048 })
      .privateKey.export({ format: "pem", type: "pkcs8" })
      .toString();
    const scenarios = [
      {
        name: "wrong audience",
        assertion: createClientAssertion({
          clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
          audience: "http://unexpected.example/token",
          privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
          keyId: TEST_CLIENT_ASSERTION_KEY_ID
        }),
        expected: /audience/
      },
      {
        name: "expired assertion",
        assertion: createClientAssertion({
          clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
          audience: `${config.server.issuer}/token`,
          privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
          keyId: TEST_CLIENT_ASSERTION_KEY_ID,
          nowSeconds: Math.floor(Date.now() / 1000) - 1_000,
          expiresInSeconds: 1
        }),
        expected: /expired/
      },
      {
        name: "mismatched subject",
        assertion: createClientAssertion({
          clientId: "another-client",
          audience: `${config.server.issuer}/token`,
          privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
          keyId: TEST_CLIENT_ASSERTION_KEY_ID
        }),
        expected: /mismatch/
      },
      {
        name: "unsupported algorithm",
        assertion: replaceJwtHeader(
          createClientAssertion({
            clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
            audience: `${config.server.issuer}/token`,
            privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
            keyId: TEST_CLIENT_ASSERTION_KEY_ID
          }),
          { alg: "HS256" }
        ),
        expected: /Unsupported/
      },
      {
        name: "non-string algorithm",
        assertion: replaceJwtHeader(
          createClientAssertion({
            clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
            audience: `${config.server.issuer}/token`,
            privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
            keyId: TEST_CLIENT_ASSERTION_KEY_ID
          }),
          { alg: ["PS256"] }
        ),
        expected: /alg must be a string/
      },
      {
        name: "non-string key id",
        assertion: replaceJwtHeader(
          createClientAssertion({
            clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
            audience: `${config.server.issuer}/token`,
            privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
            keyId: TEST_CLIENT_ASSERTION_KEY_ID
          }),
          { kid: [TEST_CLIENT_ASSERTION_KEY_ID] }
        ),
        expected: /kid must be a string/
      },
      {
        name: "wrong signing key",
        assertion: createClientAssertion({
          clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
          audience: `${config.server.issuer}/token`,
          privateKeyPem: wrongPrivateKeyPem,
          keyId: TEST_CLIENT_ASSERTION_KEY_ID
        }),
        expected: /signature/
      },
      {
        name: "non-string subject",
        assertion: createClientAssertion({
          clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
          audience: `${config.server.issuer}/token`,
          privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
          keyId: TEST_CLIENT_ASSERTION_KEY_ID,
          payloadOverrides: {
            sub: [TEST_PRIVATE_KEY_JWT_CLIENT_ID]
          }
        }),
        expected: /sub must be a string/
      },
      {
        name: "missing jti",
        assertion: createClientAssertion({
          clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
          audience: `${config.server.issuer}/token`,
          privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
          keyId: TEST_CLIENT_ASSERTION_KEY_ID,
          includeJwtId: false
        }),
        expected: /jti/
      },
      {
        name: "non-string jti",
        assertion: createClientAssertion({
          clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
          audience: `${config.server.issuer}/token`,
          privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
          keyId: TEST_CLIENT_ASSERTION_KEY_ID,
          payloadOverrides: {
            jti: 123
          }
        }),
        expected: /jti must be a string/
      }
    ];

    for (const scenario of scenarios) {
      const stores = createInMemoryOauthStores();
      const result = authenticateClient(
        undefined,
        {
          client_id: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: scenario.assertion
        },
        config,
        stores.clientAssertions
      );

      expect(result.ok, scenario.name).toBe(false);
      if (!result.ok) {
        expect(result.error).toBe("invalid_client");
        expect(result.errorDescription).toMatch(scenario.expected);
      }
    }

    const replayStores = createInMemoryOauthStores();
    const replayedAssertion = createClientAssertion({
      clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
      audience: `${config.server.issuer}/token`,
      privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
      keyId: TEST_CLIENT_ASSERTION_KEY_ID,
      jwtId: "same-jti"
    });
    const replayForm = {
      client_id: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: replayedAssertion
    };

    expect(authenticateClient(undefined, replayForm, config, replayStores.clientAssertions).ok).toBe(true);
    const replayResult = authenticateClient(undefined, replayForm, config, replayStores.clientAssertions);
    expect(replayResult.ok).toBe(false);
    if (!replayResult.ok) {
      expect(replayResult.errorDescription).toMatch(/already been used/);
    }

    const skewReplayStores = createInMemoryOauthStores();
    const assertionInsideExpirationSkew = createClientAssertion({
      clientId: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
      audience: `${config.server.issuer}/token`,
      privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM,
      keyId: TEST_CLIENT_ASSERTION_KEY_ID,
      jwtId: "same-skew-jti",
      nowSeconds: Math.floor(Date.now() / 1000) - 10,
      expiresInSeconds: 1
    });
    const skewReplayForm = {
      client_id: TEST_PRIVATE_KEY_JWT_CLIENT_ID,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertionInsideExpirationSkew
    };

    expect(authenticateClient(undefined, skewReplayForm, config, skewReplayStores.clientAssertions).ok).toBe(true);
    const skewReplayResult = authenticateClient(
      undefined,
      skewReplayForm,
      config,
      skewReplayStores.clientAssertions
    );
    expect(skewReplayResult.ok).toBe(false);
    if (!skewReplayResult.ok) {
      expect(skewReplayResult.errorDescription).toMatch(/already been used/);
    }
  });
});

function encodeFormComponent(value: string): string {
  return encodeURIComponent(value).replace(/%20/g, "+");
}
