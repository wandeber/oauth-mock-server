import type { IncomingMessage, ServerResponse } from "node:http";
import type { URL } from "node:url";

import { parseBody, readBody } from "../body";
import { toOptionalString } from "../request";
import { sendJson } from "../responses";

export async function handleLogout(
  req: IncomingMessage,
  requestUrl: URL,
  res: ServerResponse<IncomingMessage>
): Promise<void> {
  let postLogoutRedirectURI = toOptionalString(requestUrl.searchParams.get("post_logout_redirect_uri"));
  if (!postLogoutRedirectURI && req.method === "POST") {
    const body = await readBody(req);
    postLogoutRedirectURI = toOptionalString(parseBody(req, body).post_logout_redirect_uri);
  }

  if (postLogoutRedirectURI) {
    res.writeHead(302, { Location: postLogoutRedirectURI });
    res.end();
    return;
  }

  sendJson(res, 200, { ok: true, message: "logged out" });
}
