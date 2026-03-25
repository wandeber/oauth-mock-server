import type { IncomingMessage, ServerResponse } from "node:http";
import { URL } from "node:url";

import { PKCE_CODE_CHALLENGE_PATTERN } from "../../crypto/pkce";
import { issueOpaqueToken } from "../../crypto/tokens";
import { resolveClientIdentity } from "../../oauth/identities";
import { validateRequestedScopes } from "../../oauth/scopes";
import type { AuthorizationCodeRecord } from "../../storage/types";
import type { HttpHandlerDependencies } from "../types";
import {
  cleanupKnownUnsupportedAuthorizeParameters,
  readRequiredQueryParameter,
  toOptionalString
} from "../request";
import { sendOauthError } from "../responses";

export function handleAuthorize(
  requestUrl: URL,
  res: ServerResponse<IncomingMessage>,
  { config, stores }: HttpHandlerDependencies
): void {
  stores.authorizationCodes.cleanupExpired();
  cleanupKnownUnsupportedAuthorizeParameters(requestUrl, res);
  if (res.writableEnded) {
    return;
  }

  const clientId = readRequiredQueryParameter(requestUrl, "client_id");
  if (!clientId.ok) {
    sendOauthError(res, 400, "invalid_request", clientId.errorDescription);
    return;
  }

  const client = config.clients[clientId.value];
  if (!client) {
    sendOauthError(res, 400, "unauthorized_client", "Unknown client_id");
    return;
  }

  const responseType = readRequiredQueryParameter(requestUrl, "response_type");
  if (!responseType.ok) {
    sendOauthError(res, 400, "invalid_request", responseType.errorDescription);
    return;
  }
  if (responseType.value !== "code") {
    sendOauthError(res, 400, "unsupported_response_type", "Only response_type=code is supported");
    return;
  }

  const responseMode = toOptionalString(requestUrl.searchParams.get("response_mode"));
  if (responseMode && responseMode !== "query") {
    sendOauthError(res, 400, "invalid_request", "Only response_mode=query is supported");
    return;
  }

  const redirectURI = readRequiredQueryParameter(requestUrl, "redirect_uri");
  if (!redirectURI.ok) {
    sendOauthError(res, 400, "invalid_request", redirectURI.errorDescription);
    return;
  }
  if (!client.redirectUris.includes(redirectURI.value)) {
    sendOauthError(res, 400, "invalid_request", "redirect_uri is not registered for this client");
    return;
  }

  const scope = readRequiredQueryParameter(requestUrl, "scope");
  if (!scope.ok) {
    sendOauthError(res, 400, "invalid_request", scope.errorDescription);
    return;
  }
  const grantedScopes = validateRequestedScopes(scope.value, client);
  if (!grantedScopes.ok) {
    sendOauthError(res, grantedScopes.statusCode, grantedScopes.error, grantedScopes.errorDescription);
    return;
  }

  const state = toOptionalString(requestUrl.searchParams.get("state"));
  if (requestUrl.searchParams.has("state") && !state) {
    sendOauthError(res, 400, "invalid_request", "state cannot be empty");
    return;
  }

  const nonce = toOptionalString(requestUrl.searchParams.get("nonce"));
  if (requestUrl.searchParams.has("nonce") && !nonce) {
    sendOauthError(res, 400, "invalid_request", "nonce cannot be empty");
    return;
  }
  if (nonce && !grantedScopes.value.includes("openid")) {
    sendOauthError(res, 400, "invalid_request", "nonce requires the openid scope");
    return;
  }

  const codeChallenge = readRequiredQueryParameter(requestUrl, "code_challenge");
  if (!codeChallenge.ok) {
    sendOauthError(res, 400, "invalid_request", codeChallenge.errorDescription);
    return;
  }
  if (!PKCE_CODE_CHALLENGE_PATTERN.test(codeChallenge.value)) {
    sendOauthError(
      res,
      400,
      "invalid_request",
      "code_challenge must use the RFC 7636 base64url syntax and length constraints"
    );
    return;
  }

  const codeChallengeMethod = readRequiredQueryParameter(requestUrl, "code_challenge_method");
  if (!codeChallengeMethod.ok) {
    sendOauthError(res, 400, "invalid_request", codeChallengeMethod.errorDescription);
    return;
  }
  if (codeChallengeMethod.value !== "S256") {
    sendOauthError(
      res,
      400,
      "invalid_request",
      "Only code_challenge_method=S256 is supported"
    );
    return;
  }

  const identity = resolveClientIdentity(config, client);
  const now = Date.now();
  const code = issueOpaqueToken("code");
  const authCodeRecord: AuthorizationCodeRecord = {
    code,
    clientId: client.id,
    redirectURI: redirectURI.value,
    grantedScopes: grantedScopes.value,
    codeChallenge: codeChallenge.value,
    codeChallengeMethod: "S256",
    identityName: identity.name,
    nonce,
    authTime: Math.floor(now / 1000),
    createdAt: now,
    expiresAt: now + config.server.authorizationCodeTtlSeconds * 1000
  };

  // The authorization code is the only state we carry between /authorize and
  // /token, so everything needed for the later token exchange is bound here.
  stores.authorizationCodes.save(authCodeRecord);

  const redirectURL = new URL(redirectURI.value);
  redirectURL.searchParams.set("code", code);

  if (state) {
    redirectURL.searchParams.set("state", state);
  }

  for (const [key, value] of Object.entries(client.authorizeResponse)) {
    if (value !== undefined && value !== null) {
      redirectURL.searchParams.set(key, String(value));
    }
  }

  res.writeHead(302, { Location: redirectURL.toString() });
  res.end();
}
