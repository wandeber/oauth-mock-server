import type { NormalizedClientConfig, NormalizedIdentityConfig, NormalizedMockServerConfig } from "../config/types";
import {
  ALL_STANDARD_SCOPE_CLAIMS,
  STANDARD_ADDRESS_CLAIMS,
  STANDARD_EMAIL_CLAIMS,
  STANDARD_PHONE_CLAIMS,
  STANDARD_PROFILE_CLAIMS
} from "./claim-sets";
import type { JsonObject } from "../config/types";

export function buildScopedUserClaims(identityClaims: JsonObject, grantedScopes: string[]): JsonObject {
  // OIDC userinfo/id_token claims depend on granted scopes. We keep the standard
  // scope-to-claim mapping, but we also pass through custom identity claims when
  // the caller has openid so the mock remains useful for debugging app-specific data.
  const grantedScopeSet = new Set(grantedScopes);
  const claims: JsonObject = {
    sub: identityClaims.sub
  };

  if (grantedScopeSet.has("profile")) {
    copyClaims(claims, identityClaims, STANDARD_PROFILE_CLAIMS);
  }

  if (grantedScopeSet.has("email")) {
    copyClaims(claims, identityClaims, STANDARD_EMAIL_CLAIMS);
  }

  if (grantedScopeSet.has("phone")) {
    copyClaims(claims, identityClaims, STANDARD_PHONE_CLAIMS);
  }

  if (grantedScopeSet.has("address")) {
    copyClaims(claims, identityClaims, STANDARD_ADDRESS_CLAIMS);
  }

  if (grantedScopeSet.has("openid")) {
    for (const [key, value] of Object.entries(identityClaims)) {
      if (value === undefined || ALL_STANDARD_SCOPE_CLAIMS.has(key)) {
        continue;
      }

      claims[key] = value;
    }
  }

  return claims;
}

export function buildIdTokenClaims(
  config: NormalizedMockServerConfig,
  client: NormalizedClientConfig,
  identity: NormalizedIdentityConfig,
  context: {
    grantedScopes: string[];
    authTime: number;
    issuedAt: number;
    expiresAt: number;
    nonce?: string;
  }
): JsonObject {
  const userClaims = buildScopedUserClaims(identity.claims, context.grantedScopes);
  const claims: JsonObject = {
    iss: config.server.issuer,
    sub: userClaims.sub ?? identity.claims.sub ?? identity.name,
    aud: client.id,
    iat: context.issuedAt,
    exp: context.expiresAt,
    auth_time: context.authTime,
    ...userClaims
  };

  if (context.nonce) {
    claims.nonce = context.nonce;
  }

  return claims;
}

function copyClaims(target: JsonObject, source: JsonObject, allowedKeys: Set<string>): void {
  for (const key of allowedKeys) {
    if (source[key] !== undefined) {
      target[key] = source[key];
    }
  }
}
