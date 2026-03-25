import { URL } from "node:url";

import type { NormalizedMockServerConfig } from "./types";

export function validateNormalizedConfig(config: NormalizedMockServerConfig): void {
  if (Object.keys(config.identities).length === 0) {
    throw new Error("At least one identity must be configured");
  }

  if (Object.keys(config.clients).length === 0) {
    throw new Error("At least one client must be configured");
  }

  const identityNames = new Set(Object.keys(config.identities));
  for (const client of Object.values(config.clients)) {
    if (client.redirectUris.length === 0) {
      throw new Error(`Client "${client.id}" must define at least one redirectUri`);
    }

    if (client.allowedScopes.length === 0) {
      throw new Error(`Client "${client.id}" must define at least one allowedScope`);
    }

    if (client.type === "confidential" && !client.clientSecret) {
      throw new Error(`Confidential client "${client.id}" must define clientSecret`);
    }

    if (client.type === "public" && client.clientSecret) {
      throw new Error(`Public client "${client.id}" cannot define clientSecret`);
    }

    if (client.defaultIdentity && !identityNames.has(client.defaultIdentity)) {
      throw new Error(
        `Client "${client.id}" references unknown defaultIdentity "${client.defaultIdentity}"`
      );
    }

    if (client.allowRefreshToken && !client.allowedScopes.includes("offline_access")) {
      throw new Error(
        `Client "${client.id}" allows refresh tokens but does not advertise offline_access in allowedScopes`
      );
    }

    validateRedirectUris(client.id, client.redirectUris);
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
