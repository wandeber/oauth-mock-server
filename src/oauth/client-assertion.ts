import crypto, { X509Certificate, createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";

import type {
  ClientAssertionSigningAlgorithm,
  JsonObject,
  NormalizedClientAssertionKey,
  NormalizedClientConfig,
  NormalizedMockServerConfig
} from "../config/types";
import type { ClientAssertionReplayStore } from "../storage/in-memory-store";
import { CLIENT_ASSERTION_TYPE_JWT_BEARER, SUPPORTED_CLIENT_ASSERTION_ALGORITHMS } from "./constants";
import { invalidClient, type AuthenticationError } from "./errors";
import { buildIssuerUrl } from "./metadata";

const CLIENT_ASSERTION_CLOCK_SKEW_SECONDS = 300;

type ClientAssertionValidationResult = { ok: true } | AuthenticationError;

interface DecodedJwt {
  header: JsonObject;
  payload: JsonObject;
  signingInput: string;
  signature: Buffer;
}

export function normalizeClientAssertionKeys(
  rawKeys: unknown,
  rawJwks: unknown
): NormalizedClientAssertionKey[] {
  const normalizedKeys: NormalizedClientAssertionKey[] = [];

  for (const rawKey of toObjectArray(rawKeys)) {
    normalizedKeys.push(normalizeClientAssertionKey(rawKey));
  }

  const jwks = asObject(rawJwks);
  const jwkKeys = Array.isArray(jwks.keys) ? jwks.keys : [];
  for (const jwk of jwkKeys) {
    normalizedKeys.push(normalizeClientAssertionKey({ publicJwk: jwk }));
  }

  return normalizedKeys;
}

export function readClientIdFromClientAssertion(assertion: string): string | undefined {
  const decoded = decodeCompactJwt(assertion);
  if (!decoded.ok) {
    return undefined;
  }

  const issuer = toOptionalJwtString(decoded.value.payload.iss);
  const subject = toOptionalJwtString(decoded.value.payload.sub);
  return issuer ?? subject;
}

export function validatePrivateKeyJwt(input: {
  assertion: string | undefined;
  assertionType: string | undefined;
  client: NormalizedClientConfig;
  config: NormalizedMockServerConfig;
  replayStore: ClientAssertionReplayStore;
  now?: number;
}): ClientAssertionValidationResult {
  if (input.assertionType !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
    return invalidClient("client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
  }

  if (!input.assertion) {
    return invalidClient("client_assertion is required");
  }

  const decoded = decodeCompactJwt(input.assertion);
  if (!decoded.ok) {
    return invalidClient(decoded.errorDescription);
  }

  const headerStringValidation = validateJwtStringFields(
    decoded.value.header,
    ["alg", "kid", "x5t", "x5t#S256"],
    "client_assertion header"
  );
  if (headerStringValidation) {
    return invalidClient(headerStringValidation);
  }

  const algorithm = toOptionalJwtString(decoded.value.header.alg);
  if (!isSupportedClientAssertionAlgorithm(algorithm)) {
    return invalidClient("Unsupported client_assertion signing algorithm");
  }

  const candidates = selectCandidateKeys(decoded.value.header, input.client.clientAssertionKeys);
  if (candidates.length === 0) {
    return invalidClient("No registered client assertion key matches the JWT header");
  }

  // Replay tracking is deliberately performed after signature verification. The
  // unsigned payload is not trusted until a registered key proves it, otherwise an
  // attacker could burn a future jti by sending an invalid assertion first.
  for (const key of candidates) {
    if (verifyClientAssertionSignature(decoded.value, algorithm, key.publicKeyPem)) {
      return validateClientAssertionClaims({
        payload: decoded.value.payload,
        client: input.client,
        config: input.config,
        replayStore: input.replayStore,
        now: input.now ?? Date.now()
      });
    }
  }

  return invalidClient("client_assertion signature could not be verified");
}

function normalizeClientAssertionKey(rawKey: JsonObject): NormalizedClientAssertionKey {
  const keyId = toOptionalString(rawKey.keyId ?? rawKey.kid);
  const certificatePem = toOptionalString(rawKey.certificatePem);
  const publicKeyPem = toOptionalString(rawKey.publicKeyPem);
  const publicJwk = asObject(rawKey.publicJwk ?? rawKey.jwk);

  if (certificatePem) {
    const certificate = new X509Certificate(certificatePem);
    assertRsaPublicKey(certificate.publicKey, "clientAssertionKeys certificatePem");
    const jwk = certificate.publicKey.export({ format: "jwk" }) as JsonWebKey;
    return {
      keyId,
      publicKeyPem: certificate.publicKey.export({ format: "pem", type: "spki" }).toString(),
      publicJwk: jwk,
      x5t: toBase64Url(crypto.createHash("sha1").update(certificate.raw).digest()),
      x5tS256: toBase64Url(crypto.createHash("sha256").update(certificate.raw).digest())
    };
  }

  if (publicKeyPem) {
    const publicKey = createPublicKey(publicKeyPem);
    assertRsaPublicKey(publicKey, "clientAssertionKeys publicKeyPem");
    return {
      keyId,
      publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
      publicJwk: publicKey.export({ format: "jwk" }) as JsonWebKey
    };
  }

  if (Object.keys(publicJwk).length > 0) {
    const publicKey = createPublicKey({ key: publicJwk, format: "jwk" });
    assertRsaPublicKey(publicKey, "clientAssertionKeys publicJwk");
    return {
      keyId: keyId ?? toOptionalString(publicJwk.kid),
      publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
      publicJwk: publicKey.export({ format: "jwk" }) as JsonWebKey,
      x5t: toOptionalString(publicJwk.x5t),
      x5tS256: toOptionalString(publicJwk["x5t#S256"])
    };
  }

  throw new Error("clientAssertionKeys entries must include publicKeyPem, certificatePem, or publicJwk");
}

function decodeCompactJwt(
  token: string
): { ok: true; value: DecodedJwt } | { ok: false; errorDescription: string } {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    return { ok: false, errorDescription: "client_assertion must be a compact JWT" };
  }

  try {
    return {
      ok: true,
      value: {
        header: decodeBase64UrlJson(parts[0]),
        payload: decodeBase64UrlJson(parts[1]),
        signingInput: `${parts[0]}.${parts[1]}`,
        signature: Buffer.from(parts[2], "base64url")
      }
    };
  } catch {
    return { ok: false, errorDescription: "client_assertion contains invalid base64url JSON" };
  }
}

function validateClientAssertionClaims(input: {
  payload: JsonObject;
  client: NormalizedClientConfig;
  config: NormalizedMockServerConfig;
  replayStore: ClientAssertionReplayStore;
  now: number;
}): ClientAssertionValidationResult {
  const payloadStringValidation = validateJwtStringFields(
    input.payload,
    ["iss", "sub", "jti"],
    "client_assertion payload"
  );
  if (payloadStringValidation) {
    return invalidClient(payloadStringValidation);
  }

  const issuer = toOptionalJwtString(input.payload.iss);
  const subject = toOptionalJwtString(input.payload.sub);
  if (issuer !== input.client.id || subject !== input.client.id) {
    return invalidClient("client_assertion iss and sub must both match client_id");
  }

  if (!isAcceptedAudience(input.payload.aud, input.client, input.config)) {
    return invalidClient("client_assertion audience is not accepted");
  }

  const nowSeconds = Math.floor(input.now / 1000);
  const expiresAt = toNumericDate(input.payload.exp);
  if (expiresAt === undefined) {
    return invalidClient("client_assertion exp is required");
  }

  if (expiresAt <= nowSeconds - CLIENT_ASSERTION_CLOCK_SKEW_SECONDS) {
    return invalidClient("client_assertion has expired");
  }

  const notBefore = toNumericDate(input.payload.nbf);
  if (notBefore !== undefined && notBefore > nowSeconds + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS) {
    return invalidClient("client_assertion is not valid yet");
  }

  const issuedAt = toNumericDate(input.payload.iat);
  if (issuedAt !== undefined && issuedAt > nowSeconds + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS) {
    return invalidClient("client_assertion iat is in the future");
  }

  const jwtId = toOptionalJwtString(input.payload.jti);
  if (!jwtId) {
    return invalidClient("client_assertion jti is required");
  }

  // The assertion remains acceptable until `exp + clock skew`, so the replay
  // marker must live for the same interval. Otherwise a used jti could be
  // accepted again after raw exp but before the skew-tolerant expiration check
  // rejects the assertion.
  const replayExpiresAt = (expiresAt + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS) * 1000;
  if (!input.replayStore.consumeOnce(input.client.id, jwtId, replayExpiresAt, input.now)) {
    return invalidClient("client_assertion has already been used");
  }

  return { ok: true };
}

function isAcceptedAudience(
  rawAudience: unknown,
  client: NormalizedClientConfig,
  config: NormalizedMockServerConfig
): boolean {
  const acceptedAudiences = new Set([
    config.server.issuer,
    buildIssuerUrl(config.server.issuer, "/token"),
    ...client.clientAssertionAudiences
  ]);
  const audiences = Array.isArray(rawAudience) ? rawAudience : [rawAudience];
  return audiences.some((entry) => typeof entry === "string" && acceptedAudiences.has(entry));
}

function selectCandidateKeys(
  header: JsonObject,
  keys: NormalizedClientAssertionKey[]
): NormalizedClientAssertionKey[] {
  const keyId = toOptionalJwtString(header.kid);
  const sha1Thumbprint = toOptionalJwtString(header.x5t);
  const sha256Thumbprint = toOptionalJwtString(header["x5t#S256"]);

  if (!keyId && !sha1Thumbprint && !sha256Thumbprint) {
    return keys;
  }

  return keys.filter((key) => {
    return (
      (keyId && key.keyId === keyId) ||
      (sha1Thumbprint && key.x5t === sha1Thumbprint) ||
      (sha256Thumbprint && key.x5tS256 === sha256Thumbprint)
    );
  });
}

function verifyClientAssertionSignature(
  decoded: DecodedJwt,
  algorithm: ClientAssertionSigningAlgorithm,
  publicKeyPem: string
): boolean {
  const hashAlgorithm = getHashAlgorithm(algorithm);
  const publicKey =
    algorithm.startsWith("PS")
      ? {
          key: publicKeyPem,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        }
      : publicKeyPem;

  return crypto.verify(
    hashAlgorithm,
    Buffer.from(decoded.signingInput, "utf8"),
    publicKey,
    decoded.signature
  );
}

function getHashAlgorithm(algorithm: ClientAssertionSigningAlgorithm): string {
  if (algorithm.endsWith("384")) {
    return "sha384";
  }

  if (algorithm.endsWith("512")) {
    return "sha512";
  }

  return "sha256";
}

function isSupportedClientAssertionAlgorithm(
  value: string | undefined
): value is ClientAssertionSigningAlgorithm {
  return SUPPORTED_CLIENT_ASSERTION_ALGORITHMS.includes(value as ClientAssertionSigningAlgorithm);
}

function assertRsaPublicKey(publicKey: KeyObject, label: string): void {
  // The server advertises and validates only RS*/PS* assertion algorithms. Node's
  // generic crypto.verify can also verify ECDSA signatures for EC keys, so fail
  // during config normalization before a non-RSA key can be used with an RSA alg.
  if (publicKey.asymmetricKeyType !== "rsa" && publicKey.asymmetricKeyType !== "rsa-pss") {
    throw new Error(`${label} must be an RSA public key`);
  }
}

function validateJwtStringFields(
  object: JsonObject,
  fieldNames: string[],
  label: string
): string | undefined {
  for (const fieldName of fieldNames) {
    if (object[fieldName] !== undefined && typeof object[fieldName] !== "string") {
      return `${label} ${fieldName} must be a string`;
    }
  }
  return undefined;
}

function decodeBase64UrlJson(value: string): JsonObject {
  const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  return asObject(parsed);
}

function toObjectArray(value: unknown): JsonObject[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map(asObject);
}

function toNumericDate(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return undefined;
  }

  return Math.floor(value);
}

function toBase64Url(value: Buffer): string {
  return value
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function toOptionalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value);
  return stringValue.length > 0 ? stringValue : undefined;
}

function toOptionalJwtString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function asObject(value: unknown): JsonObject {
  return isPlainObject(value) ? value : {};
}

function isPlainObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
