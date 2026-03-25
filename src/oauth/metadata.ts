import type { NormalizedMockServerConfig } from "../config/types";
import {
  SUPPORTED_CODE_CHALLENGE_METHODS,
  SUPPORTED_GRANT_TYPES,
  SUPPORTED_RESPONSE_MODES,
  SUPPORTED_RESPONSE_TYPES,
  SUPPORTED_SUBJECT_TYPES,
  SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS
} from "./constants";
import type { JsonObject } from "../config/types";

export function buildAuthorizationServerMetadata(config: NormalizedMockServerConfig): JsonObject {
  const scopes = new Set<string>();
  const claims = new Set<string>(["sub"]);
  const tokenEndpointAuthMethods = new Set<string>();

  for (const client of Object.values(config.clients)) {
    for (const scope of client.allowedScopes) {
      scopes.add(scope);
    }

    if (client.type === "public") {
      tokenEndpointAuthMethods.add("none");
    } else {
      tokenEndpointAuthMethods.add("client_secret_basic");
      tokenEndpointAuthMethods.add("client_secret_post");
    }
  }

  for (const identity of Object.values(config.identities)) {
    for (const claimName of Object.keys(identity.claims)) {
      claims.add(claimName);
    }
  }

  return {
    issuer: config.server.issuer,
    authorization_endpoint: buildIssuerUrl(config.server.issuer, "/authorize"),
    token_endpoint: buildIssuerUrl(config.server.issuer, "/token"),
    userinfo_endpoint: buildIssuerUrl(config.server.issuer, "/userinfo"),
    introspection_endpoint: buildIssuerUrl(config.server.issuer, "/introspect"),
    end_session_endpoint: buildIssuerUrl(config.server.issuer, "/logout"),
    jwks_uri: buildIssuerUrl(config.server.issuer, "/jwks"),
    response_types_supported: [...SUPPORTED_RESPONSE_TYPES],
    response_modes_supported: [...SUPPORTED_RESPONSE_MODES],
    grant_types_supported: [...SUPPORTED_GRANT_TYPES],
    subject_types_supported: [...SUPPORTED_SUBJECT_TYPES],
    scopes_supported: Array.from(scopes).sort(),
    claims_supported: Array.from(claims).sort(),
    code_challenge_methods_supported: [...SUPPORTED_CODE_CHALLENGE_METHODS],
    token_endpoint_auth_methods_supported: Array.from(
      new Set([...SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS, ...tokenEndpointAuthMethods])
    ).sort(),
    id_token_signing_alg_values_supported: [config.server.signing.algorithm]
  };
}

export function buildIssuerUrl(issuer: string, pathname: string): string {
  return new URL(pathname, ensureTrailingSlash(issuer)).toString();
}

export function ensureTrailingSlash(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}
