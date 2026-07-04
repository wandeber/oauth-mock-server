import type { JsonWebKey } from "node:crypto";

export type JsonObject = Record<string, unknown>;
export type ClientType = "public" | "confidential";
export type OAuthGrantType = "authorization_code" | "refresh_token" | "client_credentials";
export type TokenEndpointAuthMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post"
  | "private_key_jwt";
export type PkceCodeChallengeMethod = "S256";
export type SigningAlgorithm = "RS256";
export type ClientAssertionSigningAlgorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "PS256"
  | "PS384"
  | "PS512";

export interface NormalizedServerSigningConfig {
  algorithm: SigningAlgorithm;
  keyId: string;
  privateKeyPem: string;
  publicKeyPem: string;
  publicJwk: JsonWebKey;
}

export interface NormalizedServerSettings {
  port: number;
  issuer: string;
  authorizationCodeTtlSeconds: number;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  signing: NormalizedServerSigningConfig;
}

export interface NormalizedIdentityConfig {
  name: string;
  claims: JsonObject;
}

export interface NormalizedClientAssertionKey {
  keyId?: string;
  publicKeyPem: string;
  publicJwk: JsonWebKey;
  x5t?: string;
  x5tS256?: string;
}

export interface NormalizedClientConfig {
  id: string;
  type: ClientType;
  redirectUris: string[];
  grantTypes: OAuthGrantType[];
  tokenEndpointAuthMethods: TokenEndpointAuthMethod[];
  defaultIdentity?: string;
  clientSecret?: string;
  clientAssertionKeys: NormalizedClientAssertionKey[];
  clientAssertionAudiences: string[];
  allowedScopes: string[];
  allowRefreshToken: boolean;
  authorizeResponse: JsonObject;
}

export interface NormalizedMockServerConfig {
  server: NormalizedServerSettings;
  identities: Record<string, NormalizedIdentityConfig>;
  clients: Record<string, NormalizedClientConfig>;
}
