import crypto from "node:crypto";

export type PkcePair = {
  verifier: string;
  challenge: string;
};

export function createPkcePair(seed = crypto.randomBytes(32).toString("hex")): PkcePair {
  // PKCE S256 always hashes the ASCII verifier and then serializes the digest with base64url.
  // Keeping the helper here avoids repeating that subtle encoding detail in every spec.
  const verifier = seed;
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export function buildBasicAuthHeader(clientId: string, clientSecret: string): string {
  // OAuth client_secret_basic form-encodes both values before base64. Keeping
  // test traffic spec-shaped catches regressions for secrets containing ":" or
  // other reserved characters.
  const encodedCredentials = `${encodeFormComponent(clientId)}:${encodeFormComponent(clientSecret)}`;
  return `Basic ${Buffer.from(encodedCredentials, "utf8").toString("base64")}`;
}

export function createClientAssertion(input: {
  clientId: string;
  audience: string;
  privateKeyPem: string;
  keyId?: string;
  x5tS256?: string;
  algorithm?: "RS256" | "PS256";
  jwtId?: string;
  includeJwtId?: boolean;
  payloadOverrides?: Record<string, unknown>;
  nowSeconds?: number;
  expiresInSeconds?: number;
}): string {
  const algorithm = input.algorithm ?? "PS256";
  const nowSeconds = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const header: Record<string, unknown> = {
    alg: algorithm,
    typ: "JWT",
    ...(input.keyId ? { kid: input.keyId } : {}),
    ...(input.x5tS256 ? { "x5t#S256": input.x5tS256 } : {})
  };
  const payload = {
    aud: input.audience,
    exp: nowSeconds + (input.expiresInSeconds ?? 300),
    iat: nowSeconds,
    iss: input.clientId,
    nbf: nowSeconds,
    sub: input.clientId,
    ...(input.includeJwtId === false ? {} : { jti: input.jwtId ?? crypto.randomUUID() }),
    ...(input.payloadOverrides ?? {})
  };
  const signingInput = `${toBase64UrlJson(header)}.${toBase64UrlJson(payload)}`;
  const key =
    algorithm === "PS256"
      ? {
          key: input.privateKeyPem,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        }
      : input.privateKeyPem;
  const signature = crypto.sign("sha256", Buffer.from(signingInput, "utf8"), key);
  return `${signingInput}.${signature.toString("base64url")}`;
}

export async function readJson(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text) {
    return {};
  }

  return JSON.parse(text) as Record<string, unknown>;
}

export async function fetchJson(
  input: Parameters<typeof fetch>[0],
  init?: RequestInit
): Promise<Record<string, unknown>> {
  const response = await fetch(input, init);
  return await readJson(response);
}

export async function readJwks(baseUrl: string): Promise<Record<string, unknown>> {
  return await fetchJson(`${baseUrl}/jwks`);
}

export async function authorizeCode(baseUrl: string, input: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  state?: string;
  nonce?: string;
  responseType?: string;
  codeChallengeMethod?: string;
}): Promise<{ code: string; location: string }> {
  const query = new URLSearchParams({
    client_id: input.clientId,
    redirect_uri: input.redirectUri,
    response_type: input.responseType ?? "code",
    scope: input.scope,
    code_challenge: input.codeChallenge,
    code_challenge_method: input.codeChallengeMethod ?? "S256",
    ...(input.state ? { state: input.state } : {}),
    ...(input.nonce ? { nonce: input.nonce } : {})
  });

  const response = await fetch(`${baseUrl}/authorize?${query.toString()}`, {
    redirect: "manual"
  });

  const location = response.headers.get("location");
  if (response.status !== 302 || !location) {
    throw new Error(`Expected authorize redirect, got ${response.status}`);
  }

  const redirect = new URL(location);
  const code = redirect.searchParams.get("code");
  if (!code) {
    throw new Error(`Authorize redirect did not contain an authorization code: ${location}`);
  }

  if (input.state) {
    if (redirect.searchParams.get("state") !== input.state) {
      throw new Error("Authorize redirect lost the state parameter");
    }
  }

  return { code, location };
}

export async function exchangeAuthorizationCode(baseUrl: string, input: {
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
  clientSecret?: string;
  authMethod?: "basic" | "post";
}): Promise<Response> {
  const body = new URLSearchParams({
    client_id: input.clientId,
    code: input.code,
    redirect_uri: input.redirectUri,
    grant_type: "authorization_code",
    code_verifier: input.codeVerifier
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded"
  };

  if (input.authMethod === "basic" && input.clientSecret) {
    headers.Authorization = buildBasicAuthHeader(input.clientId, input.clientSecret);
  } else if (input.clientSecret) {
    body.set("client_secret", input.clientSecret);
  }

  return await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers,
    body: body.toString()
  });
}

export async function exchangeRefreshToken(baseUrl: string, input: {
  clientId: string;
  refreshToken: string;
  clientSecret?: string;
  authMethod?: "basic" | "post";
}): Promise<Response> {
  const body = new URLSearchParams({
    client_id: input.clientId,
    grant_type: "refresh_token",
    refresh_token: input.refreshToken
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded"
  };

  if (input.authMethod === "basic" && input.clientSecret) {
    headers.Authorization = buildBasicAuthHeader(input.clientId, input.clientSecret);
  } else if (input.clientSecret) {
    body.set("client_secret", input.clientSecret);
  }

  return await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers,
    body: body.toString()
  });
}

export async function exchangeClientCredentials(baseUrl: string, input: {
  clientId: string;
  scope?: string;
  clientSecret?: string;
  authMethod?: "basic" | "post" | "private_key_jwt";
  clientAssertion?: string;
}): Promise<Response> {
  const body = new URLSearchParams({
    client_id: input.clientId,
    grant_type: "client_credentials",
    ...(input.scope ? { scope: input.scope } : {})
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded"
  };

  if (input.authMethod === "basic" && input.clientSecret) {
    headers.Authorization = buildBasicAuthHeader(input.clientId, input.clientSecret);
  } else if (input.authMethod === "private_key_jwt" && input.clientAssertion) {
    body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    body.set("client_assertion", input.clientAssertion);
  } else if (input.clientSecret) {
    body.set("client_secret", input.clientSecret);
  }

  return await fetch(`${baseUrl}/token`, {
    method: "POST",
    headers,
    body: body.toString()
  });
}

function toBase64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function encodeFormComponent(value: string): string {
  return encodeURIComponent(value).replace(/%20/g, "+");
}
