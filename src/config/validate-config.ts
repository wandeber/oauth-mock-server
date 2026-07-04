import { URL } from "node:url";

import type { NormalizedMockServerConfig } from "./types";

export function validateNormalizedConfig(config: NormalizedMockServerConfig): void {
  const clients = Object.values(config.clients);
  const needsUserIdentities = clients.some((client) => client.grantTypes.includes("authorization_code"));

  if (needsUserIdentities && Object.keys(config.identities).length === 0) {
    throw new Error("At least one identity must be configured");
  }

  if (clients.length === 0) {
    throw new Error("At least one client must be configured");
  }

  const identityNames = new Set(Object.keys(config.identities));
  for (const client of clients) {
    if (client.grantTypes.includes("authorization_code") && client.redirectUris.length === 0) {
      throw new Error(`Client "${client.id}" must define at least one redirectUri`);
    }

    if (client.allowedScopes.length === 0) {
      throw new Error(`Client "${client.id}" must define at least one allowedScope`);
    }

    if (client.grantTypes.length === 0) {
      throw new Error(`Client "${client.id}" must define at least one grantType`);
    }

    if (client.type === "confidential" && !client.clientSecret) {
      const usesOnlyPrivateKeyJwt =
        client.tokenEndpointAuthMethods.length === 1 &&
        client.tokenEndpointAuthMethods.includes("private_key_jwt");
      if (!usesOnlyPrivateKeyJwt) {
        throw new Error(`Confidential client "${client.id}" must define clientSecret`);
      }
    }

    if (client.type === "public" && client.clientSecret) {
      throw new Error(`Public client "${client.id}" cannot define clientSecret`);
    }

    if (client.defaultIdentity && !identityNames.has(client.defaultIdentity)) {
      throw new Error(
        `Client "${client.id}" references unknown defaultIdentity "${client.defaultIdentity}"`
      );
    }

    if (client.grantTypes.includes("refresh_token") && !client.grantTypes.includes("authorization_code")) {
      throw new Error(
        `Client "${client.id}" cannot enable refresh_token without authorization_code`
      );
    }

    if (client.allowRefreshToken && !client.allowedScopes.includes("offline_access")) {
      throw new Error(
        `Client "${client.id}" allows refresh tokens but does not advertise offline_access in allowedScopes`
      );
    }

    if (client.grantTypes.includes("client_credentials") && client.type !== "confidential") {
      throw new Error(`Client "${client.id}" must be confidential to use client_credentials`);
    }

    if (client.type === "public" && client.tokenEndpointAuthMethods.some((method) => method !== "none")) {
      throw new Error(`Public client "${client.id}" can only use tokenEndpointAuthMethods=["none"]`);
    }

    if (client.type === "confidential" && client.tokenEndpointAuthMethods.includes("none")) {
      throw new Error(`Confidential client "${client.id}" cannot use tokenEndpointAuthMethods=["none"]`);
    }

    if (
      client.tokenEndpointAuthMethods.some(
        (method) => method === "client_secret_basic" || method === "client_secret_post"
      ) &&
      !client.clientSecret
    ) {
      throw new Error(`Client "${client.id}" uses client secret authentication but has no clientSecret`);
    }

    if (
      client.tokenEndpointAuthMethods.includes("private_key_jwt") &&
      client.clientAssertionKeys.length === 0
    ) {
      throw new Error(`Client "${client.id}" uses private_key_jwt but has no clientAssertionKeys`);
    }

    if (client.tokenEndpointAuthMethods.length === 0) {
      throw new Error(`Client "${client.id}" must define at least one tokenEndpointAuthMethod`);
    }

    if (client.redirectUris.length > 0) {
      validateRedirectUris(client.id, client.redirectUris);
    }
  }
}

export function validateRedirectUris(clientId: string, redirectUris: string[]): void {
  const seen = new Set<string>();
  for (const redirectURI of redirectUris) {
    if (seen.has(redirectURI)) {
      throw new Error(`Client "${clientId}" has duplicated redirectUri "${redirectURI}"`);
    }

    seen.add(redirectURI);

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(redirectURI);
    } catch {
      throw new Error(`Client "${clientId}" has invalid redirectUri "${redirectURI}"`);
    }

    if (!parsedUrl.protocol || !parsedUrl.hostname) {
      throw new Error(`Client "${clientId}" has invalid redirectUri "${redirectURI}"`);
    }

    if (parsedUrl.hash) {
      throw new Error(`Client "${clientId}" redirectUri "${redirectURI}" must not contain fragments`);
    }
  }
}
