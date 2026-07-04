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

  it("keeps legacy allowRefreshToken aligned with explicit grantTypes", () => {
    const rawConfig = buildModernConfig() as Record<string, unknown>;
    const clients = rawConfig.clients as Record<string, Record<string, unknown>>;
    clients["confidential-web"] = {
      ...clients["confidential-web"],
      grantTypes: ["authorization_code"],
      allowRefreshToken: true
    };

    const config = normalizeConfig(rawConfig, {} as NodeJS.ProcessEnv);

    expect(config.clients["confidential-web"].grantTypes).toEqual([
      "authorization_code",
      "refresh_token"
    ]);
  });

  it("rejects explicit empty grant type allowlists", () => {
    const rawConfig = buildModernConfig() as Record<string, unknown>;
    const clients = rawConfig.clients as Record<string, Record<string, unknown>>;
    clients["confidential-web"] = {
      ...clients["confidential-web"],
      allowRefreshToken: false,
      grantTypes: []
    };

    expect(() => normalizeConfig(rawConfig, {} as NodeJS.ProcessEnv)).toThrow(
      /at least one grantType/
    );
  });

  it("rejects explicit empty token endpoint auth method allowlists", () => {
    const rawConfig = buildModernConfig() as Record<string, unknown>;
    const clients = rawConfig.clients as Record<string, Record<string, unknown>>;
    clients["confidential-web"] = {
      ...clients["confidential-web"],
      tokenEndpointAuthMethods: []
    };

    expect(() => normalizeConfig(rawConfig, {} as NodeJS.ProcessEnv)).toThrow(
      /at least one tokenEndpointAuthMethod/
    );
  });

  it("allows service-only client credentials configs without identities or redirect URIs", () => {
    const config = normalizeConfig(
      {
        server: {},
        identities: {},
        clients: {
          "machine-only": {
            type: "confidential",
            clientSecret: "machine-secret",
            grantTypes: ["client_credentials"],
            allowedScopes: ["api.read"]
          }
        }
      },
      {} as NodeJS.ProcessEnv
    );

    expect(config.clients["machine-only"].redirectUris).toEqual([]);
    expect(config.clients["machine-only"].grantTypes).toEqual(["client_credentials"]);
  });
});
