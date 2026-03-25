import type { IncomingMessage, ServerResponse } from "node:http";

import { buildJwksDocument } from "../../crypto/signing";
import { SERVICE_NAME } from "../../oauth/constants";
import { buildAuthorizationServerMetadata } from "../../oauth/metadata";
import type { HttpHandlerDependencies } from "../types";
import { sendJson } from "../responses";

export function handleHealth(
  res: ServerResponse<IncomingMessage>,
  { config }: HttpHandlerDependencies
): void {
  sendJson(res, 200, {
    ok: true,
    service: SERVICE_NAME,
    issuer: config.server.issuer,
    clients: Object.keys(config.clients)
  });
}

export function handleOAuthMetadata(
  res: ServerResponse<IncomingMessage>,
  { config }: HttpHandlerDependencies
): void {
  sendJson(res, 200, buildAuthorizationServerMetadata(config));
}

export function handleJwks(
  res: ServerResponse<IncomingMessage>,
  { config }: HttpHandlerDependencies
): void {
  sendJson(res, 200, buildJwksDocument(config.server.signing));
}
