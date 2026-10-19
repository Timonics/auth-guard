import type { Request } from 'express';
import type { JWTPayload } from 'jose';
import { AUTH_GUARD_ERROR_CODES } from './auth-guard-error';
import { extractBearerToken } from './jwks-principal-provider';
import { principalFromClaims } from './principal';

describe('principalFromClaims', () => {
  it('maps a full app-token claims object to a Principal', () => {
    const claims: JWTPayload = {
      sub: '22222222-3333-4444-5555-666666666666',
      org: 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
      role: 'OWNER',
      scope: 'content:read content:write org:admin',
      typ: 'app',
      exp: 1_735_689_600,
      iss: 'cerberus',
      aud: 'cerberus-clients',
    };

    expect(principalFromClaims(claims)).toEqual({
      subjectId: '22222222-3333-4444-5555-666666666666',
      orgId: 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
      role: 'OWNER',
      scopes: ['content:read', 'content:write', 'org:admin'],
      tokenType: 'app',
      expiresAt: new Date(1_735_689_600_000),
    });
  });

  it('treats absent typ as a user token and null/missing role as null', () => {
    const claims: JWTPayload = {
      sub: 'user-uuid',
      org: 'org-uuid',
      role: null,
      scope: 'profile:read',
      exp: 1_735_689_600,
    };

    const principal = principalFromClaims(claims);
    expect(principal.tokenType).toBe('user');
    expect(principal.role).toBeNull();
    expect(principal.scopes).toEqual(['profile:read']);
  });

  it('ignores unknown role strings and a missing org claim', () => {
    const claims: JWTPayload = {
      sub: 'user-uuid',
      role: 'SUPERUSER',
      exp: 1_735_689_600,
    };

    const principal = principalFromClaims(claims);
    expect(principal.role).toBeNull();
    expect(principal.orgId).toBe('');
    expect(principal.scopes).toEqual([]);
  });

  it('throws 401 when sub is missing', () => {
    expect(() => principalFromClaims({ exp: 1_735_689_600 })).toThrow(
      expect.objectContaining({
        name: 'AuthGuardError',
        code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
        status: 401,
      }),
    );
  });

  it('throws 401 when exp is missing', () => {
    expect(() => principalFromClaims({ sub: 'user-uuid' })).toThrow(
      expect.objectContaining({
        code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
        status: 401,
      }),
    );
  });
});

describe('extractBearerToken', () => {
  const requestWith = (authorization?: string): Request =>
    ({ headers: authorization ? { authorization } : {} }) as unknown as Request;

  it('extracts the token from a Bearer header', () => {
    expect(extractBearerToken(requestWith('Bearer abc.def.ghi'))).toBe(
      'abc.def.ghi',
    );
  });

  it('is case-insensitive on the scheme', () => {
    expect(extractBearerToken(requestWith('bearer abc'))).toBe('abc');
  });

  it('rejects non-Bearer schemes', () => {
    expect(extractBearerToken(requestWith('Basic abc'))).toBeNull();
  });

  it('rejects missing headers', () => {
    expect(extractBearerToken(requestWith())).toBeNull();
  });
});
