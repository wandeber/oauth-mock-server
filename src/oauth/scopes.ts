import type { NormalizedClientConfig } from "../config/types";
import type { RefreshTokenRecord } from "../storage/types";
import { invalidGrant, invalidRequest, invalidScope, type OAuthResult } from "./errors";

export function parseScopeList(rawScope: string): OAuthResult<string[]> {
  const scopeList = rawScope
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (scopeList.length === 0) {
    return invalidRequest("scope must contain at least one value");
  }

  const uniqueScopes = Array.from(new Set(scopeList));
  return { ok: true, value: uniqueScopes };
}

export function validateRequestedScopes(
  rawScope: string,
  client: NormalizedClientConfig
): OAuthResult<string[]> {
  const parsedScopes = parseScopeList(rawScope);
  if (!parsedScopes.ok) {
    return parsedScopes;
  }

  for (const scope of parsedScopes.value) {
    if (!client.allowedScopes.includes(scope)) {
      return invalidScope(`Scope "${scope}" is not allowed for client "${client.id}"`);
    }
  }

  if (parsedScopes.value.includes("offline_access") && !client.allowRefreshToken) {
    return invalidScope(`Client "${client.id}" is not allowed to request offline_access`);
  }

  return { ok: true, value: parsedScopes.value };
}

export function validateRefreshRequestScopes(
  requestedScope: string | undefined,
  client: NormalizedClientConfig,
  refreshTokenRecord: RefreshTokenRecord
): OAuthResult<string[]> {
  if (!requestedScope) {
    return { ok: true, value: refreshTokenRecord.grantedScopes };
  }

  const parsedScopes = parseScopeList(requestedScope);
  if (!parsedScopes.ok) {
    return parsedScopes;
  }

  const originallyGranted = new Set(refreshTokenRecord.grantedScopes);
  for (const scope of parsedScopes.value) {
    if (!client.allowedScopes.includes(scope)) {
      return invalidScope(`Scope "${scope}" is not allowed for client "${client.id}"`);
    }

    if (!originallyGranted.has(scope)) {
      return invalidScope(`Scope "${scope}" was not granted in the original authorization`);
    }
  }

  return { ok: true, value: parsedScopes.value };
}

export function validateClientCredentialsScopes(
  requestedScope: string | undefined,
  client: NormalizedClientConfig
): OAuthResult<string[]> {
  if (!requestedScope) {
    return { ok: true, value: [] };
  }

  const parsedScopes = parseScopeList(requestedScope);
  if (!parsedScopes.ok) {
    return parsedScopes;
  }

  for (const scope of parsedScopes.value) {
    if (scope === "openid" || scope === "offline_access") {
      return invalidScope(`Scope "${scope}" is not valid for client_credentials`);
    }

    if (!client.allowedScopes.includes(scope)) {
      return invalidScope(`Scope "${scope}" is not allowed for client "${client.id}"`);
    }
  }

  return { ok: true, value: parsedScopes.value };
}
