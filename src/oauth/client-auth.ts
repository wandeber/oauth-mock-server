import type { NormalizedClientConfig, NormalizedMockServerConfig } from "../config/types";
import type { ClientAssertionReplayStore } from "../storage/in-memory-store";
import {
  readClientIdFromClientAssertion,
  validatePrivateKeyJwt
} from "./client-assertion";
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
      clientId: decodeFormUrlEncodedBasicPart(rawCredentials.slice(0, separatorIndex)),
      clientSecret: decodeFormUrlEncodedBasicPart(rawCredentials.slice(separatorIndex + 1))
    };
  } catch {
    return null;
  }
}

export function authenticateClient(
  authorizationHeader: string | string[] | undefined,
  form: Record<string, string>,
  config: NormalizedMockServerConfig,
  clientAssertionReplayStore: ClientAssertionReplayStore
): ClientAuthenticationResult {
  // Token endpoint authentication is intentionally resolved before grant handling:
  // every grant can rely on a single, authenticated client and the auth method
  // chosen here. This matters for private_key_jwt, where the client_id can be
  // learned from a signed assertion instead of a plain form field.
  const basicAuth = parseBasicClientAuth(authorizationHeader);
  const basicClientId = basicAuth?.clientId;
  const basicClientSecret = basicAuth?.clientSecret;
  const bodyClientId = toOptionalString(form.client_id);
  const bodyClientSecret = toOptionalString(form.client_secret);
  const clientAssertion = toOptionalString(form.client_assertion);
  const clientAssertionType = toOptionalString(form.client_assertion_type);
  const usesClientAssertion = Boolean(clientAssertion || clientAssertionType);

  const authMethodCount = [
    Boolean(basicAuth),
    Boolean(bodyClientSecret),
    usesClientAssertion
  ].filter(Boolean).length;
  if (authMethodCount > 1) {
    return invalidClient("Use exactly one client authentication method per request");
  }

  if (basicClientId && bodyClientId && basicClientId !== bodyClientId) {
    return invalidClient("client_id mismatch between Authorization header and request body");
  }

  const assertionClientId = clientAssertion ? readClientIdFromClientAssertion(clientAssertion) : undefined;
  const clientId = basicClientId ?? bodyClientId ?? assertionClientId;
  if (!clientId) {
    return invalidClient("client_id is required");
  }

  if (assertionClientId && bodyClientId && assertionClientId !== bodyClientId) {
    return invalidClient("client_id mismatch between client_assertion and request body");
  }

  const client = config.clients[clientId];
  if (!client) {
    return invalidClient("Unknown client_id");
  }

  if (usesClientAssertion) {
    if (!client.tokenEndpointAuthMethods.includes("private_key_jwt")) {
      return invalidClient("Client is not allowed to use private_key_jwt");
    }

    const assertionResult = validatePrivateKeyJwt({
      assertion: clientAssertion,
      assertionType: clientAssertionType,
      client,
      config,
      replayStore: clientAssertionReplayStore
    });
    if (!assertionResult.ok) {
      return assertionResult;
    }

    return { ok: true, client, method: "private_key_jwt" };
  }

  if (basicAuth) {
    if (!client.tokenEndpointAuthMethods.includes("client_secret_basic")) {
      return invalidClient("Client is not allowed to use client_secret_basic");
    }

    return authenticateClientSecret(client, basicClientSecret, "client_secret_basic");
  }

  if (bodyClientSecret) {
    if (!client.tokenEndpointAuthMethods.includes("client_secret_post")) {
      return invalidClient("Client is not allowed to use client_secret_post");
    }

    return authenticateClientSecret(client, bodyClientSecret, "client_secret_post");
  }

  if (client.tokenEndpointAuthMethods.includes("none")) {
    return { ok: true, client, method: "none" };
  }

  return invalidClient("client authentication is required for this client");
}

function authenticateClientSecret(
  client: NormalizedClientConfig,
  clientSecret: string | undefined,
  method: "client_secret_basic" | "client_secret_post"
): ClientAuthenticationResult {
  if (!clientSecret) {
    return invalidClient("client_secret is required for confidential clients");
  }
  if (client.clientSecret !== clientSecret) {
    return invalidClient("Invalid client credentials");
  }

  return { ok: true, client, method };
}

function decodeFormUrlEncodedBasicPart(value: string): string {
  // OAuth 2.0 client_secret_basic encodes the client_id and client_secret with
  // the application/x-www-form-urlencoded algorithm before joining them with
  // ":". Decoding here lets secrets safely contain characters like ":" or "%".
  return decodeURIComponent(value.replace(/\+/g, " "));
}

function toOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value);
  return stringValue.length > 0 ? stringValue : undefined;
}
