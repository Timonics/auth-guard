import type { Request } from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';
import { Principal, PrincipalProvider, principalFromClaims } from './principal';

export type JwksPrincipalProviderOptions = {
  jwksUrl: string;
  issuer: string;
  audience: string;
  jwksCacheTtlMs: number;
  jwksRequestTimeoutMs: number;
};

/**
 * Verifies the request's `Authorization: Bearer` JWT locally against
 * the cerberus JWKS (`GET /.well-known/jwks.json`, public).
 *
 * The JWKS key set is fetched and cached by `jose`; cache cooldown and
 * fetch timeout come from the module options. Signature algorithm is
 * pinned implicitly by the JWKS keys (cerberus signs RS256).
 *
 * Verification failures (expired, wrong issuer/audience, bad
 * signature, unreachable JWKS) surface as plain errors here; the
 * `JwtAuthGuard` wraps them into a deliberately uninformative 401
 * `authorization.token.invalid` and logs the underlying cause
 * server-side.
 */
export class JwksPrincipalProvider implements PrincipalProvider {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  public constructor(private readonly options: JwksPrincipalProviderOptions) {
    this.jwks = createRemoteJWKSet(new URL(options.jwksUrl), {
      cooldownDuration: options.jwksCacheTtlMs,
      timeoutDuration: options.jwksRequestTimeoutMs,
    });
  }

  public async resolvePrincipal(request: Request): Promise<Principal> {
    const token = extractBearerToken(request);
    if (!token) {
      throw new AuthGuardError(
        AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
        401,
        'Authorization: Bearer <token> header is required',
      );
    }
    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.options.issuer,
      audience: this.options.audience,
    });
    return principalFromClaims(payload);
  }
}

export function extractBearerToken(request: Request): string | null {
  const header = request.headers['authorization'];
  if (typeof header !== 'string') {
    return null;
  }
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return null;
  }
  return match[1].trim();
}
