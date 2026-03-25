import {
  DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
  DEFAULT_AUTH_CODE_TTL_SECONDS,
  DEFAULT_REFRESH_TOKEN_TTL_SECONDS
} from "../oauth/constants";
import { normalizeSigningConfig } from "../crypto/signing";
import { validateNormalizedConfig } from "./validate-config";
import type {
  JsonObject,
  ClientType,
  NormalizedClientConfig,
  NormalizedIdentityConfig,
  NormalizedMockServerConfig,
  NormalizedServerSettings,
  SigningAlgorithm
} from "./types";

export function normalizeConfig(
  fileConfig: JsonObject,
  env: NodeJS.ProcessEnv
): NormalizedMockServerConfig {
  const serverConfig = asObject(fileConfig.server);
  const rawIdentities = asObject(fileConfig.identities);
  const rawClients = asObject(fileConfig.clients);

  if (!("server" in fileConfig) || !("identities" in fileConfig) || !("clients" in fileConfig)) {
    throw new Error("Only the modern { server, identities, clients } configuration format is supported");
  }

  const port = toPositiveInt(serverConfig.port ?? env.PORT, 8787);
  const issuer = toOptionalString(serverConfig.issuer ?? env.MOCK_OAUTH_ISSUER) ?? `http://localhost:${port}`;

  const identities: Record<string, NormalizedIdentityConfig> = {};
  for (const [identityName, rawIdentity] of Object.entries(rawIdentities)) {
    const identityConfig = asObject(rawIdentity);
    const configuredClaims = deepMerge(
      asObject(identityConfig.idTokenClaims),
      asObject(identityConfig.claims)
    );

    identities[identityName] = {
      name: identityName,
      claims: {
        sub: configuredClaims.sub ?? identityName,
        ...configuredClaims
      }
    };
  }

  const clients: Record<string, NormalizedClientConfig> = {};
  for (const [clientId, rawClient] of Object.entries(rawClients)) {
    const clientConfig = asObject(rawClient);
    clients[clientId] = {
      id: clientId,
      type: normalizeClientType(clientConfig.type),
      redirectUris: toStringArray(clientConfig.redirectUris),
      defaultIdentity: toOptionalString(clientConfig.defaultIdentity),
      clientSecret: toOptionalString(clientConfig.clientSecret),
      allowedScopes: toStringArray(clientConfig.allowedScopes),
      allowRefreshToken: toBoolean(clientConfig.allowRefreshToken),
      authorizeResponse: asObject(clientConfig.authorizeResponse)
    };
  }

  const server: NormalizedServerSettings = {
    port,
    issuer,
    authorizationCodeTtlSeconds: toPositiveInt(
      serverConfig.authorizationCodeTtlSeconds,
      DEFAULT_AUTH_CODE_TTL_SECONDS
    ),
    accessTokenTtlSeconds: toPositiveInt(
      serverConfig.accessTokenTtlSeconds,
      DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    ),
    refreshTokenTtlSeconds: toPositiveInt(
      serverConfig.refreshTokenTtlSeconds,
      DEFAULT_REFRESH_TOKEN_TTL_SECONDS
    ),
    signing: normalizeSigningConfig(asObject(serverConfig.signing))
  };

  const config: NormalizedMockServerConfig = {
    server,
    identities,
    clients
  };

  validateNormalizedConfig(config);
  return config;
}

function normalizeClientType(rawValue: unknown): ClientType {
  return String(rawValue).toLowerCase() === "confidential" ? "confidential" : "public";
}

function toBoolean(value: unknown): boolean {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    return value.toLowerCase() === "true" || value === "1";
  }
  return false;
}

function toPositiveInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value), 10);
  if (Number.isFinite(parsed) && parsed > 0) {
    return parsed;
  }
  return fallback;
}

function toOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value);
  return stringValue.length > 0 ? stringValue : undefined;
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((entry) => String(entry));
}

function deepMerge<T extends object>(target: T, source: unknown): T {
  const output: JsonObject = { ...(target as JsonObject) };
  if (!isPlainObject(source)) {
    return output as T;
  }

  for (const [key, value] of Object.entries(source)) {
    const existing = output[key];
    if (isPlainObject(existing) && isPlainObject(value)) {
      output[key] = deepMerge(existing, value);
      continue;
    }
    output[key] = value;
  }

  return output as T;
}

function asObject(value: unknown): JsonObject {
  return isPlainObject(value) ? value : {};
}

function isPlainObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
