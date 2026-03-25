import { describe, expect, it } from "vitest";

import { normalizeConfig } from "../../../src/config/normalize-config";
import { buildModernConfig } from "../../support/config-builder";

describe("normalizeConfig", () => {
  it("uses environment defaults when the config omits server port and issuer", () => {
    const config = normalizeConfig(buildModernConfig(), {
      PORT: "9911"
    } as NodeJS.ProcessEnv);

    expect(config.server.port).toBe(9911);
    expect(config.server.issuer).toBe("http://localhost:9911");
    expect(config.identities.admin.claims.sub).toBe("user-admin");
    expect(config.clients["public-web"].defaultIdentity).toBe("admin");
  });

  it("rejects refresh-token clients that do not advertise offline_access", () => {
    const rawConfig = buildModernConfig() as Record<string, unknown>;
    const clients = rawConfig.clients as Record<string, Record<string, unknown>>;
    clients["confidential-web"] = {
      ...clients["confidential-web"],
      allowedScopes: ["openid", "profile"],
      allowRefreshToken: true
    };

    expect(() => normalizeConfig(rawConfig, {} as NodeJS.ProcessEnv)).toThrow(
      /offline_access/
    );
  });
});
