import type { AccessTokenRecord, AuthorizationCodeRecord, RefreshTokenRecord } from "./types";

export interface AuthorizationCodeStore {
  save(record: AuthorizationCodeRecord): void;
  get(code: string): AuthorizationCodeRecord | undefined;
  consume(code: string): AuthorizationCodeRecord | undefined;
  cleanupExpired(now?: number): void;
}

export interface AccessTokenStore {
  save(record: AccessTokenRecord): void;
  get(token: string): AccessTokenRecord | undefined;
  delete(token: string): void;
  cleanupExpired(now?: number): void;
}

export interface RefreshTokenStore {
  save(record: RefreshTokenRecord): void;
  get(token: string): RefreshTokenRecord | undefined;
  markConsumed(
    token: string,
    metadata?: { consumedAt?: number; replacedBy?: string }
  ): RefreshTokenRecord | undefined;
  delete(token: string): void;
  cleanupExpired(now?: number): void;
}

export interface ClientAssertionReplayStore {
  consumeOnce(clientId: string, jwtId: string, expiresAt: number, now?: number): boolean;
  cleanupExpired(now?: number): void;
}

export interface InMemoryOauthStores {
  authorizationCodes: AuthorizationCodeStore;
  accessTokens: AccessTokenStore;
  refreshTokens: RefreshTokenStore;
  clientAssertions: ClientAssertionReplayStore;
}

export function createAuthorizationCodeStore(): AuthorizationCodeStore {
  const records = new Map<string, AuthorizationCodeRecord>();

  return {
    save(record) {
      records.set(record.code, record);
    },
    get(code) {
      return records.get(code);
    },
    consume(code) {
      const record = records.get(code);
      if (!record) {
        return undefined;
      }

      records.delete(code);
      return record;
    },
    cleanupExpired(now = Date.now()) {
      for (const [code, record] of records.entries()) {
        if (record.expiresAt <= now) {
          records.delete(code);
        }
      }
    }
  };
}

export function createAccessTokenStore(): AccessTokenStore {
  const records = new Map<string, AccessTokenRecord>();

  return {
    save(record) {
      records.set(record.token, record);
    },
    get(token) {
      return records.get(token);
    },
    delete(token) {
      records.delete(token);
    },
    cleanupExpired(now = Date.now()) {
      for (const [token, record] of records.entries()) {
        if (record.expiresAt <= now) {
          records.delete(token);
        }
      }
    }
  };
}

export function createRefreshTokenStore(): RefreshTokenStore {
  const records = new Map<string, RefreshTokenRecord>();

  return {
    save(record) {
      records.set(record.token, record);
    },
    get(token) {
      return records.get(token);
    },
    markConsumed(token, metadata = {}) {
      const record = records.get(token);
      if (!record) {
        return undefined;
      }

      record.consumedAt = metadata.consumedAt ?? Date.now();
      if (metadata.replacedBy) {
        record.replacedBy = metadata.replacedBy;
      }
      return record;
    },
    delete(token) {
      records.delete(token);
    },
    cleanupExpired(now = Date.now()) {
      for (const [token, record] of records.entries()) {
        if (record.expiresAt <= now) {
          records.delete(token);
        }
      }
    }
  };
}

export function createClientAssertionReplayStore(): ClientAssertionReplayStore {
  const assertionExpirationsByClient = new Map<string, Map<string, number>>();

  return {
    consumeOnce(clientId, jwtId, expiresAt, now = Date.now()) {
      this.cleanupExpired(now);

      let clientAssertionExpirations = assertionExpirationsByClient.get(clientId);
      if (!clientAssertionExpirations) {
        clientAssertionExpirations = new Map<string, number>();
        assertionExpirationsByClient.set(clientId, clientAssertionExpirations);
      }

      if (clientAssertionExpirations.has(jwtId)) {
        return false;
      }

      clientAssertionExpirations.set(jwtId, expiresAt);
      return true;
    },
    cleanupExpired(now = Date.now()) {
      for (const [clientId, clientAssertionExpirations] of assertionExpirationsByClient.entries()) {
        for (const [jwtId, expiresAt] of clientAssertionExpirations.entries()) {
          if (expiresAt <= now) {
            clientAssertionExpirations.delete(jwtId);
          }
        }

        if (clientAssertionExpirations.size === 0) {
          assertionExpirationsByClient.delete(clientId);
        }
      }
    }
  };
}

export function createInMemoryOauthStores(): InMemoryOauthStores {
  return {
    authorizationCodes: createAuthorizationCodeStore(),
    accessTokens: createAccessTokenStore(),
    refreshTokens: createRefreshTokenStore(),
    clientAssertions: createClientAssertionReplayStore()
  };
}
