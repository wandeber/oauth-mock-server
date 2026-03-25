import crypto from "node:crypto";

export const PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;
export const PKCE_CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;

export function createPkceCodeChallenge(codeVerifier: string): string {
  return toBase64Url(crypto.createHash("sha256").update(codeVerifier).digest());
}

export function doesPkceVerifierMatch(codeVerifier: string, codeChallenge: string): boolean {
  return createPkceCodeChallenge(codeVerifier) === codeChallenge;
}

function toBase64Url(value: Buffer): string {
  return value
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
