import type { IncomingMessage, ServerResponse } from "node:http";
import type { URL } from "node:url";

import { TOLERATED_AUTHORIZE_PARAMS } from "../oauth/constants";
import { sendOauthError } from "./responses";

export function cleanupKnownUnsupportedAuthorizeParameters(
  requestUrl: URL,
  res: ServerResponse<IncomingMessage>
): void {
  for (const key of requestUrl.searchParams.keys()) {
    if (
      !TOLERATED_AUTHORIZE_PARAMS.has(key) &&
      (key === "request" || key === "request_uri" || key === "claims")
    ) {
      sendOauthError(res, 400, "request_not_supported", `Parameter "${key}" is not supported`);
      return;
    }
  }
}

export function readRequiredQueryParameter(
  requestUrl: URL,
  name: string
): { ok: true; value: string } | { ok: false; errorDescription: string } {
  const value = toOptionalString(requestUrl.searchParams.get(name));
  if (!value) {
    return {
      ok: false,
      errorDescription: `${name} is required`
    };
  }

  return { ok: true, value };
}

export function readBearerToken(
  authorizationHeader: string | string[] | undefined
): string | null {
  if (!authorizationHeader || Array.isArray(authorizationHeader)) {
    return null;
  }

  if (!authorizationHeader.startsWith("Bearer ")) {
    return null;
  }

  const token = authorizationHeader.slice("Bearer ".length).trim();
  return token || null;
}

export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

export function toOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value);
  return stringValue.length > 0 ? stringValue : undefined;
}
