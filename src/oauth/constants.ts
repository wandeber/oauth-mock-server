export const SERVICE_NAME = "oauth-mock-server";
export const MAX_REQUEST_BODY_LENGTH = 1_000_000;
export const DEFAULT_AUTH_CODE_TTL_SECONDS = 300;
export const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 3600;
export const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;

export const TOLERATED_AUTHORIZE_PARAMS = new Set([
  "client_id",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "prompt",
  "login_hint",
  "ui_locales",
  "acr_values",
  "display",
  "max_age",
  "response_mode"
]);

export const SUPPORTED_RESPONSE_TYPES = ["code"] as const;
export const SUPPORTED_RESPONSE_MODES = ["query"] as const;
export const SUPPORTED_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
export const SUPPORTED_SUBJECT_TYPES = ["public"] as const;
export const SUPPORTED_CODE_CHALLENGE_METHODS = ["S256"] as const;
export const SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS = [
  "none",
  "client_secret_basic",
  "client_secret_post"
] as const;
