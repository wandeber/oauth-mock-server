import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { GenericContainer, type StartedTestContainer } from "testcontainers";

import {
  createPkcePair,
  fetchJson,
  exchangeAuthorizationCode,
  exchangeClientCredentials,
  authorizeCode,
  readJson,
  readJwks
} from "../support/oauth-client";
import { assertJwtSignatureWithJwks, decodeJwtPayload } from "../support/jwt";
import {
  PROJECT_DIR,
  TEST_DOCKER_CLIENT_ID,
  TEST_DOCKER_MACHINE_CLIENT_ID,
  TEST_DOCKER_MACHINE_CLIENT_SECRET,
  TEST_DOCKER_REDIRECT_URI,
  TEST_STANDARD_SCOPES
} from "../support/constants";

describe("docker image smoke test", () => {
  let container: StartedTestContainer;
  let baseUrl: string;

  beforeAll(async () => {
    const builtContainer = await GenericContainer.fromDockerfile(PROJECT_DIR, "Dockerfile").build();
    container = await builtContainer.withExposedPorts(8787).start();

    baseUrl = `http://${container.getHost()}:${container.getMappedPort(8787)}`;
  });

  afterAll(async () => {
    if (container) {
      await container.stop();
    }
  });

  it("boots with the repo fixture and exposes a verifiable OIDC surface", async () => {
    const healthPayload = await fetchJson(`${baseUrl}/health`);
    expect(healthPayload.ok).toBe(true);
    expect(healthPayload.issuer).toBe("http://localhost:8787");

    const metadata = await fetchJson(`${baseUrl}/.well-known/openid-configuration`);
    const jwks = await readJwks(baseUrl);
    expect(metadata.issuer).toBe("http://localhost:8787");
    expect(metadata.jwks_uri).toBe("http://localhost:8787/jwks");
    expect(metadata.userinfo_endpoint).toBe("http://localhost:8787/userinfo");
    expect(Array.isArray(jwks.keys)).toBe(true);

    const pkce = createPkcePair();
    const { code } = await authorizeCode(baseUrl, {
      clientId: TEST_DOCKER_CLIENT_ID,
      redirectUri: TEST_DOCKER_REDIRECT_URI,
      scope: TEST_STANDARD_SCOPES.openidProfileEmail,
      codeChallenge: pkce.challenge
    });

    const tokenResponse = await exchangeAuthorizationCode(baseUrl, {
      clientId: TEST_DOCKER_CLIENT_ID,
      code,
      redirectUri: TEST_DOCKER_REDIRECT_URI,
      codeVerifier: pkce.verifier
    });
    const tokenPayload = await readJson(tokenResponse);
    expect(tokenResponse.status).toBe(200);
    expect(typeof tokenPayload.id_token).toBe("string");
    assertJwtSignatureWithJwks(String(tokenPayload.id_token), jwks);

    const idTokenClaims = decodeJwtPayload(String(tokenPayload.id_token));
    expect(idTokenClaims.sub).toBe("docker-user");

    const machineTokenResponse = await exchangeClientCredentials(baseUrl, {
      clientId: TEST_DOCKER_MACHINE_CLIENT_ID,
      clientSecret: TEST_DOCKER_MACHINE_CLIENT_SECRET,
      authMethod: "basic",
      scope: TEST_STANDARD_SCOPES.machineRead
    });
    const machineTokenPayload = await readJson(machineTokenResponse);
    expect(machineTokenResponse.status).toBe(200);
    expect(machineTokenPayload.access_token).toBeTruthy();
    expect(machineTokenPayload.scope).toBe(TEST_STANDARD_SCOPES.machineRead);
    expect(machineTokenPayload.id_token).toBeUndefined();
    expect(machineTokenPayload.refresh_token).toBeUndefined();
  });
});
