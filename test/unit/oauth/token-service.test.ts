import { describe, expect, it } from "vitest";

import { normalizeConfig } from "../../../src/config/normalize-config";
import { createInMemoryOauthStores } from "../../../src/storage/in-memory-store";
import { handleRefreshTokenGrant, issueTokenSet } from "../../../src/oauth/token-service";
import { buildModernConfig } from "../../support/config-builder";
import { TEST_CONFIDENTIAL_CLIENT_ID } from "../../support/constants";

describe("token-service refresh rotation", () => {
  it("rotates refresh tokens and marks the original one as consumed", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const client = config.clients[TEST_CONFIDENTIAL_CLIENT_ID];
    const identity = config.identities[client.defaultIdentity ?? "support"];
    const stores = createInMemoryOauthStores();

    const initialTokenSet = issueTokenSet(config, client, identity, {
      grantedScopes: ["openid", "email", "profile", "offline_access"],
      authTime: 1_700_000_000
    });

    expect(initialTokenSet.refreshTokenRecord).toBeDefined();
    stores.refreshTokens.save(initialTokenSet.refreshTokenRecord!);

    const result = handleRefreshTokenGrant(
      { refresh_token: initialTokenSet.refreshTokenRecord!.token },
      config,
      client,
      stores
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    const rotatedRefreshToken = result.value.refreshTokenRecord;
    expect(rotatedRefreshToken).toBeDefined();
    expect(rotatedRefreshToken?.token).not.toBe(initialTokenSet.refreshTokenRecord?.token);

    const consumedRecord = stores.refreshTokens.get(initialTokenSet.refreshTokenRecord!.token);
    expect(consumedRecord?.consumedAt).toBeDefined();
    expect(consumedRecord?.replacedBy).toBe(rotatedRefreshToken?.token);
  });
});
