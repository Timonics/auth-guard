# @timonics/auth-guard

[![npm version](https://img.shields.io/npm/v/@timonics/auth-guard)](https://www.npmjs.com/package/@timonics/auth-guard)

Resource-server authentication for timonics microservices. Verifies RS256 JWT
access tokens issued by the workspace auth service (cerberus) against its
public JWKS — the standard OAuth2 resource-server pattern — and provides
global guards for authentication and scope authorization.

## Install

```bash
npm i @timonics/auth-guard jose
```

Published to the public npm registry as
[`@timonics/auth-guard`](https://www.npmjs.com/package/@timonics/auth-guard).
`@nestjs/common`, `@nestjs/core` and `reflect-metadata` are peer
dependencies (any Nest 10 or 11 app already has them).

## Setup

Import once in the consuming app's root module:

```ts
import { AuthGuardModule } from '@timonics/auth-guard';

@Module({
  imports: [
    AuthGuardModule.forRoot({
      jwksUrl: process.env.CERBERUS_JWKS_URL, // throw loudly if unset
      // issuer: 'cerberus',                   // default
      // audience: 'cerberus-clients',         // default
      // jwksCacheTtlMs: 30_000,               // default
      // jwksRequestTimeoutMs: 5_000,          // default
      // applyGlobal: true,                    // default
    }),
  ],
})
export class AppModule {}
```

With `applyGlobal: true` (the default) both guards and the exception filter
are registered globally — the app needs zero additional auth wiring:

- **JwtAuthGuard** — verifies the `Authorization: Bearer` token on every
  route and attaches a `Principal` to `req.user`.
- **ScopesGuard** — enforces `@Scopes()` metadata (runs after auth).
- **GlobalAuthExceptionFilter** — renders auth errors as JSON.

`jwksUrl` is validated at bootstrap: it must be an `https://` URL, except
`http://localhost:*` / `http://127.0.0.1:*` for local dev. Invalid config
throws during module init — there are no silent defaults.

Set `applyGlobal: false` to register the pieces yourself via `APP_GUARD` /
`APP_FILTER` (all classes are exported).

## Usage

```ts
import {
  CurrentPrincipal,
  Principal,
  Public,
  Scopes,
} from '@timonics/auth-guard';

@Controller('content')
export class ContentController {
  // No token required:
  @Get('health')
  @Public()
  health() { ... }

  // Any of the listed scopes is sufficient:
  @Get()
  @Scopes('content:read')
  list(@CurrentPrincipal() principal: Principal) {
    // principal.subjectId / orgId / role / scopes / tokenType / expiresAt
  }

  @Post()
  @Scopes('content:write', 'content:admin') // ANY-match
  create() { ... }
}
```

The principal is derived from the cerberus token claims:

| Field       | Source                              |
| ----------- | ----------------------------------- |
| `subjectId` | `sub` (user or app UUID)            |
| `orgId`     | `org` (cerberus organization UUID)  |
| `role`      | `role` (`OWNER`/`ADMIN`/`MEMBER`/null) |
| `scopes`    | `scope`, split on whitespace        |
| `tokenType` | `'app'` when `typ === 'app'`, else `'user'` |
| `expiresAt` | `exp` as a `Date`                   |

## Error responses

All auth failures share one deliberately uninformative body shape (the
underlying cause is logged server-side only):

```json
// 401 — missing, malformed, expired, wrong iss/aud, bad signature,
//       or JWKS unreachable
{ "code": "authorization.token.invalid", "message": "..." }

// 403 — authenticated but missing the required scope
{ "code": "authorization.scope.missing", "message": "..." }

// 500 — anything unexpected
{ "code": "internal.error", "message": "Internal server error" }
```

The filter is a catch-all: if your app registers its own exception filters
for other error classes, make sure they are dispatched first (import your
error-handling module before `AuthGuardModule`).

## Extending: principal providers

`JwtAuthGuard` depends only on the `PrincipalProvider` interface (bound to
the `PrincipalProvider` DI token). V1 ships `JwksPrincipalProvider`, which
verifies the Bearer JWT locally against the JWKS. A future gateway mode
(`HeaderTrustPrincipalProvider`, reading the principal from trusted
gateway headers) can be selected via `forRoot` config without touching the
guards or any consumer code.

## Development

```bash
npm install
npm run test     # jest + ts-jest, colocated src/*.spec.ts (jose mocked)
npm run build    # tsc → dist/ (js + .d.ts)
npm run lint     # eslint flat config, typescript-eslint type-checked
npm run format   # prettier
```
