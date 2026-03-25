import type { IncomingMessage, ServerResponse } from "node:http";

import { buildScopedUserClaims } from "../../oauth/claims";
import type { HttpHandlerDependencies } from "../types";
import { readBearerToken } from "../request";
import { sendJson, sendOauthError } from "../responses";

export function handleUserInfo(
  req: IncomingMessage,
  res: ServerResponse<IncomingMessage>,
  { config, stores }: HttpHandlerDependencies
): void {
  stores.accessTokens.cleanupExpired();

  const accessTokenValue = readBearerToken(req.headers.authorization);
  if (!accessTokenValue) {
    sendOauthError(res, 401, "invalid_token", "Bearer access token is required");
    return;
  }

  const accessTokenRecord = stores.accessTokens.get(accessTokenValue);
  if (!accessTokenRecord || accessTokenRecord.expiresAt <= Date.now()) {
    sendOauthError(res, 401, "invalid_token", "Unknown or expired access token");
    return;
  }

  if (!accessTokenRecord.grantedScopes.includes("openid")) {
    sendOauthError(
      res,
      403,
      "insufficient_scope",
      "userinfo requires an access token with openid scope"
    );
    return;
  }

  const identity = config.identities[accessTokenRecord.identityName];
  if (!identity) {
    sendOauthError(res, 500, "server_error", "Resolved identity no longer exists");
    return;
  }

  sendJson(res, 200, buildScopedUserClaims(identity.claims, accessTokenRecord.grantedScopes));
}
