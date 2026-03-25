import crypto, { createPrivateKey, createPublicKey, type JsonWebKey } from "node:crypto";

import { DEV_SIGNING_KEY_ID, DEV_SIGNING_PRIVATE_KEY_PEM } from "../dev-signing-key";
import type {
  JsonObject,
  NormalizedServerSigningConfig,
  SigningAlgorithm
} from "../config/types";

function toBase64Url(value: Buffer): string {
  return value
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function toBase64UrlJson(value: unknown): string {
  return toBase64Url(Buffer.from(JSON.stringify(value), "utf8"));
}

export function normalizeSigningConfig(rawSigningConfig: JsonObject): NormalizedServerSigningConfig {
  const algorithmRaw = toOptionalString(rawSigningConfig.algorithm) ?? "RS256";
  if (algorithmRaw !== "RS256") {
    throw new Error(`Unsupported signing algorithm "${algorithmRaw}". Only RS256 is supported`);
  }

  const configuredPrivateKeyPem = toOptionalString(rawSigningConfig.privateKeyPem);
  const configuredPublicKeyPem = toOptionalString(rawSigningConfig.publicKeyPem);
  const privateKeyPem = configuredPrivateKeyPem ?? DEV_SIGNING_PRIVATE_KEY_PEM;
  const privateKey = createPrivateKey(privateKeyPem);
  const publicKey = configuredPublicKeyPem
    ? createPublicKey(configuredPublicKeyPem)
    : createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const publicJwk = publicKey.export({ format: "jwk" }) as JsonWebKey;

  if (publicJwk.kty !== "RSA" || !publicJwk.n || !publicJwk.e) {
    throw new Error("The configured signing key must be an RSA key pair");
  }

  const keyId =
    toOptionalString(rawSigningConfig.keyId) ??
    (configuredPrivateKeyPem || configuredPublicKeyPem ? computeJwkThumbprint(publicJwk) : DEV_SIGNING_KEY_ID);

  return {
    algorithm: "RS256",
    keyId,
    privateKeyPem,
    publicKeyPem,
    publicJwk
  };
}

export function createSignedJwt(payload: JsonObject, signing: NormalizedServerSigningConfig): string {
  const header = {
    alg: signing.algorithm,
    typ: "JWT",
    kid: signing.keyId
  };
  const encodedHeader = toBase64UrlJson(header);
  const encodedPayload = toBase64UrlJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), signing.privateKeyPem);
  return `${signingInput}.${toBase64Url(signature)}`;
}

export function computeJwkThumbprint(jwk: JsonWebKey): string {
  const thumbprintPayload = JSON.stringify({
    e: jwk.e,
    kty: jwk.kty,
    n: jwk.n
  });

  return toBase64Url(crypto.createHash("sha256").update(thumbprintPayload).digest());
}

export function buildJwksDocument(signing: NormalizedServerSigningConfig): JsonObject {
  return {
    keys: [
      {
        ...signing.publicJwk,
        kid: signing.keyId,
        use: "sig",
        alg: signing.algorithm
      }
    ]
  };
}

function toOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value);
  return stringValue.length > 0 ? stringValue : undefined;
}

export type { SigningAlgorithm };
