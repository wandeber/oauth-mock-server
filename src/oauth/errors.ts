import type { NormalizedClientConfig, TokenEndpointAuthMethod } from "../config/types";

export interface OAuthErrorResult {
  ok: false;
  statusCode: number;
  error: string;
  errorDescription: string;
}

export interface OAuthSuccessResult<T> {
  ok: true;
  value: T;
}

export type OAuthResult<T> = OAuthSuccessResult<T> | OAuthErrorResult;

export interface AuthenticationResult {
  ok: true;
  client: NormalizedClientConfig;
  method: TokenEndpointAuthMethod;
}

export interface AuthenticationError {
  ok: false;
  statusCode: 401;
  error: "invalid_client";
  errorDescription: string;
}

export type ClientAuthenticationResult = AuthenticationResult | AuthenticationError;

export function oauthError(
  statusCode: number,
  error: string,
  errorDescription: string
): OAuthErrorResult {
  return {
    ok: false,
    statusCode,
    error,
    errorDescription
  };
}

export function invalidRequest(errorDescription: string): OAuthErrorResult {
  return oauthError(400, "invalid_request", errorDescription);
}

export function invalidGrant(errorDescription: string): OAuthErrorResult {
  return oauthError(400, "invalid_grant", errorDescription);
}

export function invalidScope(errorDescription: string): OAuthErrorResult {
  return oauthError(400, "invalid_scope", errorDescription);
}

export function unauthorizedClient(errorDescription: string): OAuthErrorResult {
  return oauthError(400, "unauthorized_client", errorDescription);
}

export function invalidClient(errorDescription: string): AuthenticationError {
  return {
    ok: false,
    statusCode: 401,
    error: "invalid_client",
    errorDescription
  };
}

export function serverError(errorDescription: string): OAuthErrorResult {
  return oauthError(500, "server_error", errorDescription);
}
