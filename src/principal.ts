import { JWTPayload } from 'jose';
import { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';

export type PrincipalRole = 'OWNER' | 'ADMIN' | 'MEMBER' | null;

export type Principal = {
  subjectId: string;
  orgId: string;
  role: PrincipalRole;
  scopes: string[];
  tokenType: 'user' | 'app';
  expiresAt: Date;
};

/**
 * Resolves the authenticated principal for a request.
 *
 * V1 ships exactly one implementation: `JwksPrincipalProvider`, which
 * verifies the request's Bearer JWT locally against cerberus's JWKS.
 *
 * A future `HeaderTrustPrincipalProvider` (for the API-gateway mode,
 * where the gateway has already verified the token and forwards the
 * principal as trusted headers) only needs to implement this interface
 * and be bound to the `PrincipalProvider` DI token in
 * `AuthGuardModule.forRoot` — the guards and all consumer business
 * code stay untouched.
 */
export interface PrincipalProvider {
  resolvePrincipal(request: import('express').Request): Promise<Principal>;
}

export const PrincipalProvider = Symbol('PrincipalProvider');

const KNOWN_ROLES = new Set(['OWNER', 'ADMIN', 'MEMBER']);

/**
 * Map verified cerberus JWT claims to a `Principal`.
 *
 *   * `sub`  → subjectId (user UUID or app UUID)
 *   * `org`  → orgId (cerberus organization UUID — the tenant id)
 *   * `role` → role, `null` when absent or not a known role
 *   * `scope` → scopes, split on whitespace (OAuth2 standard)
 *   * `typ`  → tokenType: `'app'` only when explicitly `'app'`
 *   * `exp`  → expiresAt
 *
 * Throws `AuthGuardError` (401 `authorization.token.invalid`) when the
 * claims cannot produce a usable principal — verification has already
 * succeeded at this point, so this only fires on structurally broken
 * tokens.
 */
export function principalFromClaims(claims: JWTPayload): Principal {
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
    throw new AuthGuardError(
      AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
      401,
      'token is missing a sub claim',
    );
  }
  if (typeof claims.exp !== 'number') {
    throw new AuthGuardError(
      AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
      401,
      'token is missing an exp claim',
    );
  }
  const role =
    typeof claims.role === 'string' && KNOWN_ROLES.has(claims.role)
      ? (claims.role as 'OWNER' | 'ADMIN' | 'MEMBER')
      : null;
  const scopes =
    typeof claims.scope === 'string'
      ? claims.scope.split(/\s+/).filter((scope) => scope.length > 0)
      : [];
  return {
    subjectId: claims.sub,
    orgId: typeof claims.org === 'string' ? claims.org : '',
    role,
    scopes,
    tokenType: claims.typ === 'app' ? 'app' : 'user',
    expiresAt: new Date(claims.exp * 1000),
  };
}
