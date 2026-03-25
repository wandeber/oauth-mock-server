import type { JsonWebKey } from "node:crypto";

export type JsonObject = Record<string, unknown>;
export type ClientType = "public" | "confidential";
export type PkceCodeChallengeMethod = "S256";
export type SigningAlgorithm = "RS256";

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

export interface NormalizedClientConfig {
  id: string;
  type: ClientType;
  redirectUris: string[];
  defaultIdentity?: string;
  clientSecret?: string;
  allowedScopes: string[];
  allowRefreshToken: boolean;
  authorizeResponse: JsonObject;
}

export interface NormalizedMockServerConfig {
  server: NormalizedServerSettings;
  identities: Record<string, NormalizedIdentityConfig>;
  clients: Record<string, NormalizedClientConfig>;
}
