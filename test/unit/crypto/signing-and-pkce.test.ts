import { describe, expect, it } from "vitest";

import { createPkceCodeChallenge, doesPkceVerifierMatch } from "../../../src/crypto/pkce";
import { buildJwksDocument, createSignedJwt, normalizeSigningConfig } from "../../../src/crypto/signing";
import { assertJwtSignatureWithJwks, decodeJwtHeader } from "../../support/jwt";
import { TEST_RSA_KEY_ID, TEST_RSA_PRIVATE_KEY_PEM } from "../../support/constants";

describe("crypto helpers", () => {
  it("creates RS256 JWTs that verify against the published JWKS", () => {
    const signing = normalizeSigningConfig({
      algorithm: "RS256",
      keyId: TEST_RSA_KEY_ID,
      privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM
    });

    const token = createSignedJwt(
      {
        iss: "http://localhost:8787",
        sub: "user-admin",
        aud: "public-web",
        iat: 1_700_000_000,
        exp: 1_700_003_600
      },
      signing
    );
    const jwks = buildJwksDocument(signing);

    assertJwtSignatureWithJwks(token, jwks);
    expect(decodeJwtHeader(token).kid).toBe(TEST_RSA_KEY_ID);
  });

  it("binds PKCE verifiers to their derived challenges", () => {
    const verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    const challenge = createPkceCodeChallenge(verifier);

    expect(doesPkceVerifierMatch(verifier, challenge)).toBe(true);
    expect(doesPkceVerifierMatch(`${verifier}x`, challenge)).toBe(false);
  });
});
