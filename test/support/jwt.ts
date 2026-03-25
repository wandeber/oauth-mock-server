import crypto from "node:crypto";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length < 2) {
    throw new Error(`Invalid JWT: ${token}`);
  }

  const payload = Buffer.from(parts[1], "base64url").toString("utf8");
  return JSON.parse(payload) as Record<string, unknown>;
}

export function decodeJwtHeader(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length < 2) {
    throw new Error(`Invalid JWT: ${token}`);
  }

  const header = Buffer.from(parts[0], "base64url").toString("utf8");
  return JSON.parse(header) as Record<string, unknown>;
}

export function assertJwtSignatureWithJwks(token: string, jwks: Record<string, unknown>): void {
  const [headerPart, payloadPart, signaturePart] = token.split(".");
  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error(`Invalid JWT: ${token}`);
  }

  const header = decodeJwtHeader(token);
  if (header.alg !== "RS256") {
    throw new Error(`Expected RS256 JWT, got ${String(header.alg)}`);
  }

  const keyId = String(header.kid ?? "");
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  const jwk = keys.find((entry) => isPlainObject(entry) && entry.kid === keyId);
  if (!jwk || !isPlainObject(jwk)) {
    throw new Error(`JWKS does not contain kid "${keyId}"`);
  }

  // The smoke/integration assertions intentionally verify the same thing a real client would:
  // reconstruct the public key from JWKS and validate the detached RS256 signature.
  const publicKey = crypto.createPublicKey({ key: jwk as object, format: "jwk" });
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(`${headerPart}.${payloadPart}`);
  verifier.end();

  const signature = Buffer.from(signaturePart, "base64url");
  if (!verifier.verify(publicKey, signature)) {
    throw new Error("JWT signature does not verify against the provided JWKS");
  }
}
