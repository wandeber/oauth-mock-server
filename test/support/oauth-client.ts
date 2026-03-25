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
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64")}`;
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
