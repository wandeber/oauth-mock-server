import type { IncomingMessage, ServerResponse } from "node:http";

export function sendOauthError(
  res: ServerResponse<IncomingMessage>,
  statusCode: number,
  error: string,
  errorDescription: string
): void {
  sendJson(res, statusCode, {
    error,
    error_description: errorDescription
  });
}

export function sendJson(
  res: ServerResponse<IncomingMessage>,
  statusCode: number,
  payload: unknown
): void {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}
