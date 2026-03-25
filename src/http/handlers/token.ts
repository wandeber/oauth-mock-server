import type { IncomingMessage, ServerResponse } from "node:http";

import { authenticateClient } from "../../oauth/client-auth";
import { cleanupExpiredOauthStores, handleAuthorizationCodeGrant, handleRefreshTokenGrant } from "../../oauth/token-service";
import type { HttpHandlerDependencies } from "../types";
import { parseBody, readBody } from "../body";
import { toOptionalString } from "../request";
import { sendJson, sendOauthError } from "../responses";

export async function handleToken(
  req: IncomingMessage,
  res: ServerResponse<IncomingMessage>,
  { config, stores }: HttpHandlerDependencies
): Promise<void> {
  cleanupExpiredOauthStores(stores);

  const body = await readBody(req);
  const form = parseBody(req, body);
  const grantType = toOptionalString(form.grant_type);

  if (!grantType) {
    sendOauthError(res, 400, "invalid_request", "grant_type is required");
    return;
  }

  const authenticationResult = authenticateClient(req.headers.authorization, form, config);
  if (!authenticationResult.ok) {
    sendOauthError(
      res,
      authenticationResult.statusCode,
      authenticationResult.error,
      authenticationResult.errorDescription
    );
    return;
  }

  // The HTTP layer only dispatches by grant type; the grant-specific validation
  // and state mutations live in the token service so future grants can be added
  // without bloating the request/response plumbing.
  if (grantType === "authorization_code") {
    const issuance = handleAuthorizationCodeGrant(form, config, authenticationResult.client, stores);
    if (!issuance.ok) {
      sendOauthError(res, issuance.statusCode, issuance.error, issuance.errorDescription);
      return;
    }

    sendJson(res, 200, issuance.value.payload);
    return;
  }

  if (grantType === "refresh_token") {
    const issuance = handleRefreshTokenGrant(form, config, authenticationResult.client, stores);
    if (!issuance.ok) {
      sendOauthError(res, issuance.statusCode, issuance.error, issuance.errorDescription);
      return;
    }

    sendJson(res, 200, issuance.value.payload);
    return;
  }

  sendOauthError(res, 400, "unsupported_grant_type", `Unsupported grant_type "${grantType}"`);
}
