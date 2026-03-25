import {
  TEST_CONFIDENTIAL_CLIENT_ID,
  TEST_CONFIDENTIAL_CLIENT_SECRET,
  TEST_CONFIDENTIAL_REDIRECT_URI,
  TEST_EMAIL_ONLY_CLIENT_ID,
  TEST_EMAIL_ONLY_REDIRECT_URI,
  TEST_PUBLIC_CLIENT_ID,
  TEST_PUBLIC_REDIRECT_URI,
  TEST_RSA_KEY_ID,
  TEST_RSA_PRIVATE_KEY_PEM
} from "./constants";

type JsonObject = Record<string, unknown>;

export type ModernConfigOptions = {
  publicDefaultIdentity?: string;
};

export function buildModernConfig(options: ModernConfigOptions = {}): JsonObject {
  return {
    server: {
      includeIdToken: true,
      authorizationCodeTtlSeconds: 300,
      signing: {
        algorithm: "RS256",
        keyId: TEST_RSA_KEY_ID,
        privateKeyPem: TEST_RSA_PRIVATE_KEY_PEM
      }
    },
    identities: {
      admin: {
        idTokenClaims: {
          sub: "user-admin",
          email: "admin@local.test",
          name: "Admin User",
          given_name: "Admin",
          family_name: "User",
          roles: ["ADMIN"]
        }
      },
      support: {
        idTokenClaims: {
          sub: "user-support",
          email: "support@local.test",
          name: "Support User",
          given_name: "Support",
          family_name: "User",
          roles: ["SUPPORT"]
        }
      }
    },
    clients: {
      [TEST_PUBLIC_CLIENT_ID]: {
        type: "public",
        redirectUris: [TEST_PUBLIC_REDIRECT_URI],
        defaultIdentity: options.publicDefaultIdentity ?? "admin",
        allowedScopes: ["openid", "email", "profile"]
      },
      [TEST_EMAIL_ONLY_CLIENT_ID]: {
        type: "public",
        redirectUris: [TEST_EMAIL_ONLY_REDIRECT_URI],
        defaultIdentity: "admin",
        allowedScopes: ["openid", "email"]
      },
      [TEST_CONFIDENTIAL_CLIENT_ID]: {
        type: "confidential",
        clientSecret: TEST_CONFIDENTIAL_CLIENT_SECRET,
        redirectUris: [TEST_CONFIDENTIAL_REDIRECT_URI],
        defaultIdentity: "support",
        allowedScopes: ["openid", "email", "profile", "offline_access"],
        allowRefreshToken: true
      }
    }
  };
}
