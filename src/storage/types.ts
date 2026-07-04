import type { JsonObject, PkceCodeChallengeMethod } from "../config/types";

export interface AuthorizationCodeRecord {
  code: string;
  clientId: string;
  redirectURI: string;
  grantedScopes: string[];
  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;
  identityName: string;
  nonce?: string;
  authTime: number;
  createdAt: number;
  expiresAt: number;
}

export interface AccessTokenRecord {
  token: string;
  clientId: string;
  subject:
    | {
        type: "user";
        identityName: string;
      }
    | {
        type: "client";
        clientId: string;
      };
  grantedScopes: string[];
  authTime?: number;
  issuedAt: number;
  expiresAt: number;
}

export interface RefreshTokenRecord {
  token: string;
  clientId: string;
  identityName: string;
  grantedScopes: string[];
  authTime: number;
  issuedAt: number;
  expiresAt: number;
  consumedAt?: number;
  replacedBy?: string;
}

export interface TokenIssuanceResult {
  payload: JsonObject;
  accessTokenRecord: AccessTokenRecord;
  refreshTokenRecord?: RefreshTokenRecord;
}
