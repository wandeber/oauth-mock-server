import type { NormalizedClientConfig, NormalizedMockServerConfig } from "../config/types";
import { invalidClient, type ClientAuthenticationResult } from "./errors";

export function parseBasicClientAuth(
  authorizationHeader: string | string[] | undefined
): { clientId: string; clientSecret: string } | null {
  if (!authorizationHeader || Array.isArray(authorizationHeader)) {
    return null;
  }

  if (!authorizationHeader.startsWith("Basic ")) {
    return null;
  }

  try {
    const rawCredentials = Buffer.from(authorizationHeader.slice("Basic ".length), "base64").toString(
      "utf8"
    );
    const separatorIndex = rawCredentials.indexOf(":");
    if (separatorIndex < 0) {
      return null;
    }

    return {
      clientId: rawCredentials.slice(0, separatorIndex),
      clientSecret: rawCredentials.slice(separatorIndex + 1)
    };
  } catch {
    return null;
  }
}

export function authenticateClient(
  authorizationHeader: string | string[] | undefined,
  form: Record<string, string>,
  config: NormalizedMockServerConfig
): ClientAuthenticationResult {
  // Token endpoint authentication rules depend on the declared client type.
  // Public clients identify themselves with client_id only, while confidential
  // clients must authenticate using either client_secret_basic or client_secret_post.
  const basicAuth = parseBasicClientAuth(authorizationHeader);
  const basicClientId = basicAuth?.clientId;
  const basicClientSecret = basicAuth?.clientSecret;
  const bodyClientId = toOptionalString(form.client_id);
  const bodyClientSecret = toOptionalString(form.client_secret);

  if (basicClientId && bodyClientId && basicClientId !== bodyClientId) {
    return invalidClient("client_id mismatch between Authorization header and request body");
  }

  if (basicClientSecret && bodyClientSecret && basicClientSecret !== bodyClientSecret) {
    return invalidClient("client_secret mismatch between Authorization header and request body");
  }

  const clientId = basicClientId ?? bodyClientId;
  if (!clientId) {
    return invalidClient("client_id is required");
  }

  const client = config.clients[clientId];
  if (!client) {
    return invalidClient("Unknown client_id");
  }

  if (client.type === "public") {
    return { ok: true, client };
  }

  const clientSecret = basicClientSecret ?? bodyClientSecret;
  if (!clientSecret) {
    return invalidClient("client_secret is required for confidential clients");
  }

  if (client.clientSecret !== clientSecret) {
    return invalidClient("Invalid client credentials");
  }

  return { ok: true, client };
}

function toOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value);
  return stringValue.length > 0 ? stringValue : undefined;
}
