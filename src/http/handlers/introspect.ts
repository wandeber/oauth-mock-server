import type { IncomingMessage, ServerResponse } from "node:http";
import type { URL } from "node:url";

import { cleanupExpiredOauthStores } from "../../oauth/token-service";
import type { HttpHandlerDependencies } from "../types";
import { parseBody, readBody } from "../body";
import { readBearerToken, toOptionalString } from "../request";
import { sendJson } from "../responses";

export async function handleIntrospect(
  req: IncomingMessage,
  requestUrl: URL,
  res: ServerResponse<IncomingMessage>,
  { config, stores }: HttpHandlerDependencies
): Promise<void> {
  cleanupExpiredOauthStores(stores);

  let formToken: string | undefined;
  if (req.method === "POST") {
    const body = await readBody(req);
    formToken = toOptionalString(parseBody(req, body).token);
  }

  const tokenValue =
    formToken ??
    toOptionalString(requestUrl.searchParams.get("token")) ??
    readBearerToken(req.headers.authorization) ??
    undefined;

  if (!tokenValue) {
    sendJson(res, 200, { active: false });
    return;
  }

  const accessTokenRecord = stores.accessTokens.get(tokenValue);
  if (accessTokenRecord && accessTokenRecord.expiresAt > Date.now()) {
    const subject =
      accessTokenRecord.subject.type === "user"
        ? config.identities[accessTokenRecord.subject.identityName]?.claims.sub ??
          accessTokenRecord.subject.identityName
        : accessTokenRecord.subject.clientId;
    sendJson(res, 200, {
      active: true,
      token_type: "Bearer",
      client_id: accessTokenRecord.clientId,
      sub: subject,
      scope: accessTokenRecord.grantedScopes.join(" "),
      exp: Math.floor(accessTokenRecord.expiresAt / 1000)
    });
    return;
  }

  const refreshTokenRecord = stores.refreshTokens.get(tokenValue);
  if (refreshTokenRecord && !refreshTokenRecord.consumedAt && refreshTokenRecord.expiresAt > Date.now()) {
    const identity = config.identities[refreshTokenRecord.identityName];
    sendJson(res, 200, {
      active: true,
      token_type: "Refresh",
      client_id: refreshTokenRecord.clientId,
      sub: identity?.claims.sub ?? refreshTokenRecord.identityName,
      scope: refreshTokenRecord.grantedScopes.join(" "),
      exp: Math.floor(refreshTokenRecord.expiresAt / 1000)
    });
    return;
  }

  sendJson(res, 200, { active: false });
}
