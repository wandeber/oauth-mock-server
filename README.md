# OAuth Mock Server (Local)

Local OAuth2/OIDC development server for sample applications.

This project lets several apps talk to the same local provider without changing application code.

## Concepts

`id_token` is the OIDC JWT that represents the user's authentication.

`JWKS` is the set of public keys clients use to verify the signature of those JWTs.

## What It Supports

- `authorization_code + PKCE (S256)` as the primary flow.
- `refresh_token` grant with strict in-memory rotation.
- `client_credentials` grant for machine-to-machine clients.
- `id_token` signed with `RS256`.
- OIDC and OAuth discovery at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`.
- Public `JWKS` for signature validation.
- `GET /userinfo` to retrieve claims for the authenticated user.
- Multiple `clients` in parallel.
- A global `identities` catalog reusable across apps.
- Strict validation of `redirect_uri` and supported parameters.
- `client_secret_basic`, `client_secret_post`, and `private_key_jwt` token endpoint authentication.
- Tolerance for extra optional OIDC parameters when they do not change behavior or introduce ambiguity.

## What It Does Not Support

- `implicit`.
- `password`.
- `device_code`.
- OIDC hybrid flows.
- `mock` parameters in the URL.

## Endpoints

- `GET /authorize`
- `POST /token`
- `GET /userinfo`
- `GET /jwks`
- `GET /jwks.json` (alias)
- `GET /health`
- `GET|POST /introspect`
- `POST /logout`
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/openid-configuration`

## Quick Start

```sh
cd oauth-mock-server
cp mock-config.example.json mock-config.json
npm install
npm run dev
```

`npm run dev` uses `tsx watch` to restart automatically when TypeScript files change.

For non-watch execution:

```sh
npm run build
npm start
```

You can also run it with Docker:

```sh
cd oauth-mock-server
docker compose up -d
```

It is published at `http://localhost:8787` and connected to the `oauth-mock-shared` Docker network
so other `docker-compose` stacks can consume it through the `oauth-mock` hostname.

For apps running in another `docker-compose`:

- Connect the consumer service to the external `oauth-mock-shared` network.
- Use `http://oauth-mock:8787/...` for backend calls from a container.
- Use `http://localhost:8787/...` for OAuth browser redirects.

By default it loads `mock-config.json` from this folder. To use another file:

```sh
MOCK_OAUTH_CONFIG_FILE=./another-path.json npm run dev
```

## Configuration

The recommended format is split into:

- `server`: global process and signing configuration.
- `identities`: a reusable global catalog of mock profiles.
- `clients`: the registry of applications that will use the server.

Identity resolution rules:

1. If a `client` has `defaultIdentity`, that one is used.
2. If it does not, the first identity declared in `identities` is used.
3. If there are no identities, the server fails at startup.

Validation rules:

- `redirect_uri` must exactly match one of the client's registered URIs.
- `redirectUris` are required only for clients that enable the `authorization_code` grant.
- `scope` can only request values allowed for that client.
- `offline_access` is required to issue refresh tokens, and the client must enable the `refresh_token` grant
  directly or through the legacy `allowRefreshToken: true` flag.
- `client_secret` only applies to `confidential` clients.
- `client_credentials` clients must be `confidential`.
- `client_credentials` never issues `id_token` or `refresh_token`.
- `private_key_jwt` requires a signed `client_assertion` with `iss` and `sub` equal to the `client_id`,
  an accepted `aud`, a valid `exp`, and a unique `jti` for replay protection.
- Supported parameters are validated strictly; known optional extra OIDC parameters are tolerated when they do not affect the result.

## Recommended Example

```json
{
  "server": {
    "port": 8787,
    "issuer": "http://localhost:8787",
    "authorizationCodeTtlSeconds": 300
  },
  "identities": {
    "admin": {
      "idTokenClaims": {
        "sub": "admin-user",
        "email": "admin@example.test",
        "name": "Admin User",
        "employeeId": "EMP-001",
        "roles": ["ADMIN"]
      }
    },
    "support": {
      "idTokenClaims": {
        "sub": "support-user",
        "email": "support@example.test",
        "name": "Support User",
        "roles": ["SUPPORT"]
      }
    }
  },
  "clients": {
    "sample-web-app": {
      "type": "public",
      "redirectUris": ["http://localhost:3000/callback"],
      "defaultIdentity": "admin",
      "allowedScopes": ["openid", "profile", "email", "offline_access"],
      "allowRefreshToken": true
    },
    "sample-admin-app": {
      "type": "confidential",
      "clientSecret": "local-admin-secret",
      "redirectUris": ["http://localhost:4200/callback"],
      "defaultIdentity": "support",
      "allowedScopes": ["openid", "profile", "email", "roles", "offline_access"],
      "allowRefreshToken": true
    },
    "sample-machine-client": {
      "type": "confidential",
      "clientSecret": "local-machine-secret",
      "grantTypes": ["client_credentials"],
      "tokenEndpointAuthMethods": ["client_secret_basic", "client_secret_post"],
      "allowedScopes": ["api.read", "api.write"]
    },
    "sample-certificate-client": {
      "type": "confidential",
      "grantTypes": ["client_credentials"],
      "tokenEndpointAuthMethods": ["private_key_jwt"],
      "clientAssertionKeys": [
        {
          "keyId": "local-cert-key",
          "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
        }
      ],
      "allowedScopes": ["api.read"]
    }
  }
}
```

For certificate-style client authentication, configure `tokenEndpointAuthMethods` with
`private_key_jwt` and register the client's verification material in `clientAssertionKeys`.
Each key can use one of these shapes:

```json
{ "keyId": "key-1", "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" }
{ "keyId": "key-1", "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----" }
{ "keyId": "key-1", "publicJwk": { "kty": "RSA", "n": "...", "e": "AQAB" } }
```

The token request must send:

```text
grant_type=client_credentials
client_id=sample-certificate-client
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<signed JWT>
scope=api.read
```

The assertion must be signed with one of the registered keys. The mock accepts
`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, and `PS512` to cover PingOne-style
`PRIVATE_KEY_JWT` and Microsoft Entra certificate assertions. By default, `aud`
can be the issuer or the local token endpoint; add `clientAssertionAudiences`
when a Docker hostname or another local URL should also be accepted. The `jti`
claim is required and can only be used once until the assertion expires.

If you do not define `server.signing`, the server uses the fixed development key included in the repository.
If you want your own key, you can add this optional block inside `server`:

```json
{
  "signing": {
    "algorithm": "RS256",
    "keyId": "my-local-rsa",
    "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }
}
```

## Standards Support

| Capability | Status | Notes |
| --- | --- | --- |
| `authorization_code` | Supported | Primary mock flow |
| PKCE `S256` | Supported | Required for authorization code |
| `refresh_token` grant | Supported | With strict in-memory rotation |
| `client_credentials` grant | Supported | Confidential machine-to-machine clients |
| `id_token` signed with `RS256` | Supported | Verifiable through JWKS |
| `JWKS` | Supported | Public keys for signature validation |
| `userinfo` | Supported | Returns claims consistent with the access token |
| `state` | Supported | Propagated on redirect |
| `nonce` | Supported | Included in `id_token` |
| Multiple `clients` | Supported | Several apps in parallel |
| Global `identities` | Supported | Reusable across clients |
| Exact `redirect_uri` | Supported | Strict matching |
| `client_secret_basic` | Supported | For `confidential` clients |
| `client_secret_post` | Supported | For `confidential` clients |
| `private_key_jwt` | Supported | For `confidential` clients with registered public keys or certificates |
| `/.well-known/oauth-authorization-server` | Supported | OAuth discovery |
| `/.well-known/openid-configuration` | Supported | OIDC discovery |
| Extra optional OIDC parameters | Partial | Tolerated when they do not affect behavior |
| `implicit` | Not supported | Out of scope |
| `password` | Not supported | Out of scope |
| `device_code` | Not supported | Out of scope |
| `mock` URL parameters | Not supported | Selection is config-driven |

## Tests

The repo includes an integration suite with `Vitest` + `Testcontainers` that spins up the mock server in a real container and validates the main OAuth/OIDC flow.

```sh
npm test
```

Docker must be available on the host.
