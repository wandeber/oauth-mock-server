import { describe, expect, it } from "vitest";

import { normalizeConfig } from "../../../src/config/normalize-config";
import { buildScopedUserClaims } from "../../../src/oauth/claims";
import { validateRequestedScopes } from "../../../src/oauth/scopes";
import { buildModernConfig } from "../../support/config-builder";
import { TEST_CONFIDENTIAL_CLIENT_ID, TEST_PUBLIC_CLIENT_ID } from "../../support/constants";

describe("scope validation and claim projection", () => {
  it("deduplicates repeated scopes and keeps the granted order stable", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const client = config.clients[TEST_PUBLIC_CLIENT_ID];

    const result = validateRequestedScopes("openid email email profile", client);

    expect(result).toEqual({
      ok: true,
      value: ["openid", "email", "profile"]
    });
  });

  it("rejects offline_access for clients that cannot refresh", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const client = config.clients[TEST_PUBLIC_CLIENT_ID];

    const result = validateRequestedScopes("openid offline_access", client);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_scope");
      expect(result.errorDescription).toMatch(/offline_access/);
    }
  });

  it("includes only scoped standard claims plus custom claims behind openid", () => {
    const config = normalizeConfig(buildModernConfig(), {} as NodeJS.ProcessEnv);
    const identity = config.identities[config.clients[TEST_CONFIDENTIAL_CLIENT_ID].defaultIdentity ?? "support"];

    const claims = buildScopedUserClaims(identity.claims, ["openid", "email"]);

    expect(claims.sub).toBe("user-support");
    expect(claims.email).toBe("support@local.test");
    expect(claims.name).toBeUndefined();
    expect(claims.roles).toEqual(["SUPPORT"]);
  });
});
