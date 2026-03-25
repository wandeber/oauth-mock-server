import type { IncomingMessage, ServerResponse } from "node:http";
import { URL } from "node:url";

import { handleAuthorize } from "./handlers/authorize";
import { handleIntrospect } from "./handlers/introspect";
import { handleLogout } from "./handlers/logout";
import { handleHealth, handleJwks, handleOAuthMetadata } from "./handlers/metadata";
import { handleToken } from "./handlers/token";
import { handleUserInfo } from "./handlers/userinfo";
import { getErrorMessage } from "./request";
import { sendJson, sendOauthError } from "./responses";
import type { HttpHandlerDependencies } from "./types";

export function createRouter(dependencies: HttpHandlerDependencies) {
  return async (req: IncomingMessage, res: ServerResponse<IncomingMessage>): Promise<void> => {
    const requestUrl = new URL(
      req.url ?? "/",
      `http://${req.headers.host ?? `localhost:${dependencies.config.server.port}`}`
    );
    const pathname = requestUrl.pathname;

    try {
      if (req.method === "GET" && pathname === "/health") {
        handleHealth(res, dependencies);
        return;
      }

      if (req.method === "GET" && pathname === "/.well-known/oauth-authorization-server") {
        handleOAuthMetadata(res, dependencies);
        return;
      }

      if (req.method === "GET" && pathname === "/.well-known/openid-configuration") {
        handleOAuthMetadata(res, dependencies);
        return;
      }

      if (req.method === "GET" && (pathname === "/jwks" || pathname === "/jwks.json")) {
        handleJwks(res, dependencies);
        return;
      }

      if (req.method === "GET" && pathname === "/authorize") {
        handleAuthorize(requestUrl, res, dependencies);
        return;
      }

      if (req.method === "POST" && pathname === "/token") {
        await handleToken(req, res, dependencies);
        return;
      }

      if (req.method === "GET" && pathname === "/userinfo") {
        handleUserInfo(req, res, dependencies);
        return;
      }

      if ((req.method === "GET" || req.method === "POST") && pathname === "/introspect") {
        await handleIntrospect(req, requestUrl, res, dependencies);
        return;
      }

      if ((req.method === "GET" || req.method === "POST") && pathname === "/logout") {
        await handleLogout(req, requestUrl, res);
        return;
      }

      sendJson(res, 404, { error: "not_found" });
    } catch (error) {
      // Centralising the last-resort error translation keeps the handlers focused
      // on protocol behaviour while still producing consistent OAuth-style errors.
      sendOauthError(res, 500, "server_error", getErrorMessage(error));
    }
  };
}
