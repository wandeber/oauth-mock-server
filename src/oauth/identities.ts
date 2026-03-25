import type { NormalizedClientConfig, NormalizedIdentityConfig, NormalizedMockServerConfig } from "../config/types";

export function resolveClientIdentity(
  config: NormalizedMockServerConfig,
  client: NormalizedClientConfig
): NormalizedIdentityConfig {
  // Each client maps to exactly one active identity in this phase. If a client
  // does not choose one explicitly, we use the first globally declared identity
  // so the result stays deterministic and simple to debug.
  const identityName = client.defaultIdentity ?? Object.keys(config.identities)[0];
  const identity = identityName ? config.identities[identityName] : undefined;
  if (!identity) {
    throw new Error(`Cannot resolve an identity for client "${client.id}"`);
  }

  return identity;
}
