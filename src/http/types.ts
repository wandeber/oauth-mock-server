import type { NormalizedMockServerConfig } from "../config/types";
import type { InMemoryOauthStores } from "../storage/in-memory-store";

export interface HttpHandlerDependencies {
  config: NormalizedMockServerConfig;
  stores: InMemoryOauthStores;
}
