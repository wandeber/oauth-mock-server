import type { NormalizedClientConfig, NormalizedIdentityConfig, NormalizedMockServerConfig } from "../config/types";
import { createSignedJwt } from "../crypto/signing";
import { issueOpaqueToken } from "../crypto/tokens";
import type {
  AccessTokenStore,
  AuthorizationCodeStore,
  InMemoryOauthStores,
  RefreshTokenStore
} from "../storage/in-memory-store";
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  RefreshTokenRecord,
  TokenIssuanceResult
} from "../storage/types";
import { doesPkceVerifierMatch, PKCE_CODE_VERIFIER_PATTERN } from "../crypto/pkce";
import { buildIdTokenClaims } from "./claims";
import { invalidGrant, invalidRequest, serverError, unauthorizedClient, type OAuthResult } from "./errors";
import { validateClientCredentialsScopes, validateRefreshRequestScopes } from "./scopes";
import { resolveClientIdentity } from "./identities";

export function cleanupExpiredOauthStores(
  stores: InMemoryOauthStores,
  now: number = Date.now()
): void {
  stores.authorizationCodes.cleanupExpired(now);
  stores.accessTokens.cleanupExpired(now);
  stores.refreshTokens.cleanupExpired(now);
  stores.clientAssertions.cleanupExpired(now);
}

export function handleAuthorizationCodeGrant(
  form: Record<string, string>,
  config: NormalizedMockServerConfig,
  client: NormalizedClientConfig,
  stores: InMemoryOauthStores
): OAuthResult<TokenIssuanceResult> {
  if (!client.grantTypes.includes("authorization_code")) {
    return unauthorizedClient(`Client "${client.id}" is not allowed to use authorization_code`);
  }

  const code = toOptionalString(form.code);
  if (!code) {
    return invalidRequest("code is required");
  }

  const redirectURI = toOptionalString(form.redirect_uri);
  if (!redirectURI) {
    return invalidRequest("redirect_uri is required");
  }
  if (!client.redirectUris.includes(redirectURI)) {
    return invalidGrant("redirect_uri is not registered for this client");
  }

  const codeVerifier = toOptionalString(form.code_verifier);
  if (!codeVerifier) {
    return invalidRequest("code_verifier is required");
  }
  if (!PKCE_CODE_VERIFIER_PATTERN.test(codeVerifier)) {
    return invalidRequest("code_verifier must use the RFC 7636 syntax and length constraints");
  }

  const authCodeRecord = stores.authorizationCodes.get(code);
  if (!authCodeRecord) {
    return invalidGrant("Unknown or already consumed authorization code");
  }

  if (authCodeRecord.expiresAt <= Date.now()) {
    stores.authorizationCodes.consume(code);
    return invalidGrant("Authorization code has expired");
  }

  if (authCodeRecord.clientId !== client.id) {
    return invalidGrant("Authorization code was not issued to this client");
  }

  if (authCodeRecord.redirectURI !== redirectURI) {
    return invalidGrant("redirect_uri mismatch");
  }

  // PKCE is the security binding for the authorization code flow. The original
  // code challenge is stored at /authorize and the exchange only succeeds when
  // the verifier hashes back to the same value.
  if (!doesPkceVerifierMatch(codeVerifier, authCodeRecord.codeChallenge)) {
    return invalidGrant("code_verifier does not match code_challenge");
  }

  const identity = config.identities[authCodeRecord.identityName];
  if (!identity) {
    return serverError("Resolved identity no longer exists");
  }

  stores.authorizationCodes.consume(code);

  const issuance = issueTokenSet(config, client, identity, {
    grantedScopes: authCodeRecord.grantedScopes,
    authTime: authCodeRecord.authTime,
    nonce: authCodeRecord.nonce
  });
  stores.accessTokens.save(issuance.accessTokenRecord);
  if (issuance.refreshTokenRecord) {
    stores.refreshTokens.save(issuance.refreshTokenRecord);
  }

  return { ok: true, value: issuance };
}

export function handleRefreshTokenGrant(
  form: Record<string, string>,
  config: NormalizedMockServerConfig,
  client: NormalizedClientConfig,
  stores: InMemoryOauthStores
): OAuthResult<TokenIssuanceResult> {
  if (!client.grantTypes.includes("refresh_token")) {
    return unauthorizedClient(`Client "${client.id}" is not allowed to use refresh_token`);
  }

  const refreshTokenValue = toOptionalString(form.refresh_token);
  if (!refreshTokenValue) {
    return invalidRequest("refresh_token is required");
  }

  const refreshTokenRecord = stores.refreshTokens.get(refreshTokenValue);
  if (!refreshTokenRecord) {
    return invalidGrant("Unknown refresh_token");
  }

  if (refreshTokenRecord.expiresAt <= Date.now()) {
    stores.refreshTokens.delete(refreshTokenValue);
    return invalidGrant("refresh_token has expired");
  }

  if (refreshTokenRecord.consumedAt) {
    return invalidGrant("refresh_token has already been used");
  }

  if (refreshTokenRecord.clientId !== client.id) {
    return invalidGrant("refresh_token was not issued to this client");
  }

  if (!client.allowRefreshToken) {
    return invalidGrant("This client is not allowed to use refresh_token grant");
  }

  const requestedScope = toOptionalString(form.scope);
  const effectiveScopesResult = validateRefreshRequestScopes(requestedScope, client, refreshTokenRecord);
  if (!effectiveScopesResult.ok) {
    return effectiveScopesResult;
  }

  const identity = config.identities[refreshTokenRecord.identityName];
  if (!identity) {
    return serverError("Resolved identity no longer exists");
  }

  // Refresh-token rotation keeps the family realistic for local debug: every use
  // consumes the current token, mints a replacement and makes reuse detectable.
  const issuance = issueTokenSet(config, client, identity, {
    grantedScopes: effectiveScopesResult.value,
    authTime: refreshTokenRecord.authTime
  });

  stores.refreshTokens.markConsumed(refreshTokenValue, {
    consumedAt: Date.now(),
    replacedBy: issuance.refreshTokenRecord?.token
  });
  stores.accessTokens.save(issuance.accessTokenRecord);
  if (issuance.refreshTokenRecord) {
    stores.refreshTokens.save(issuance.refreshTokenRecord);
  }

  return { ok: true, value: issuance };
}

export function handleClientCredentialsGrant(
  form: Record<string, string>,
  config: NormalizedMockServerConfig,
  client: NormalizedClientConfig,
  stores: InMemoryOauthStores
): OAuthResult<TokenIssuanceResult> {
  if (!client.grantTypes.includes("client_credentials")) {
    return unauthorizedClient(`Client "${client.id}" is not allowed to use client_credentials`);
  }

  if (client.type !== "confidential") {
    return unauthorizedClient("client_credentials requires a confidential client");
  }

  const requestedScope = toOptionalString(form.scope);
  const grantedScopes = validateClientCredentialsScopes(requestedScope, client);
  if (!grantedScopes.ok) {
    return grantedScopes;
  }

  const issuance = issueClientCredentialsTokenSet(config, client, {
    grantedScopes: grantedScopes.value
  });
  stores.accessTokens.save(issuance.accessTokenRecord);

  return { ok: true, value: issuance };
}

export function issueTokenSet(
  config: NormalizedMockServerConfig,
  client: NormalizedClientConfig,
  identity: NormalizedIdentityConfig,
  context: {
    grantedScopes: string[];
    authTime: number;
    nonce?: string;
  }
): TokenIssuanceResult {
  const nowMilliseconds = Date.now();
  const nowSeconds = Math.floor(nowMilliseconds / 1000);
  const accessTokenValue = issueOpaqueToken("atk");
  const accessTokenRecord: AccessTokenRecord = {
    token: accessTokenValue,
    clientId: client.id,
    subject: {
      type: "user",
      identityName: identity.name
    },
    grantedScopes: context.grantedScopes,
    authTime: context.authTime,
    issuedAt: nowMilliseconds,
    expiresAt: nowMilliseconds + config.server.accessTokenTtlSeconds * 1000
  };

  const payload: Record<string, unknown> = {
    access_token: accessTokenValue,
    token_type: "Bearer",
    expires_in: config.server.accessTokenTtlSeconds,
    scope: context.grantedScopes.join(" ")
  };

  let refreshTokenRecord: RefreshTokenRecord | undefined;
  if (client.allowRefreshToken && context.grantedScopes.includes("offline_access")) {
    const refreshTokenValue = issueOpaqueToken("rtk");
    refreshTokenRecord = {
      token: refreshTokenValue,
      clientId: client.id,
      identityName: identity.name,
      grantedScopes: context.grantedScopes,
      authTime: context.authTime,
      issuedAt: nowMilliseconds,
      expiresAt: nowMilliseconds + config.server.refreshTokenTtlSeconds * 1000
    };
    payload.refresh_token = refreshTokenValue;
  }

  if (context.grantedScopes.includes("openid")) {
    const idTokenClaims = buildIdTokenClaims(config, client, identity, {
      grantedScopes: context.grantedScopes,
      authTime: context.authTime,
      issuedAt: nowSeconds,
      expiresAt: nowSeconds + config.server.accessTokenTtlSeconds,
      nonce: context.nonce
    });
    payload.id_token = createSignedJwt(idTokenClaims, config.server.signing);
  }

  return {
    payload,
    accessTokenRecord,
    refreshTokenRecord
  };
}

export function issueClientCredentialsTokenSet(
  config: NormalizedMockServerConfig,
  client: NormalizedClientConfig,
  context: {
    grantedScopes: string[];
  }
): TokenIssuanceResult {
  const nowMilliseconds = Date.now();
  const accessTokenValue = issueOpaqueToken("atk");
  const accessTokenRecord: AccessTokenRecord = {
    token: accessTokenValue,
    clientId: client.id,
    subject: {
      type: "client",
      clientId: client.id
    },
    grantedScopes: context.grantedScopes,
    issuedAt: nowMilliseconds,
    expiresAt: nowMilliseconds + config.server.accessTokenTtlSeconds * 1000
  };

  const payload: Record<string, unknown> = {
    access_token: accessTokenValue,
    token_type: "Bearer",
    expires_in: config.server.accessTokenTtlSeconds
  };

  if (context.grantedScopes.length > 0) {
    payload.scope = context.grantedScopes.join(" ");
  }

  return {
    payload,
    accessTokenRecord
  };
}

function toOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value);
  return stringValue.length > 0 ? stringValue : undefined;
}
