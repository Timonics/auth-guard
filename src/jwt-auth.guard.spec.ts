import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';
import { Public } from './decorators';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwksPrincipalProvider } from './jwks-principal-provider';

jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn().mockReturnValue({}),
  jwtVerify: jest.fn(),
}));

const mockJwtVerify = jwtVerify as jest.MockedFunction<typeof jwtVerify>;
const mockCreateRemoteJWKSet = createRemoteJWKSet as jest.MockedFunction<
  typeof createRemoteJWKSet
>;

const TOKEN = 'header.payload.signature';

const CLAIMS = {
  sub: '11111111-2222-3333-4444-555555555555',
  org: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  role: 'ADMIN',
  scope: 'content:read content:write',
  exp: 1_735_689_600,
};

const VERIFY_RESULT = {
  payload: CLAIMS,
  protectedHeader: { alg: 'RS256', kid: 'test-key' },
  key: new Uint8Array(),
};

const PROVIDER_OPTIONS = {
  jwksUrl: 'https://cerberus.example.com/.well-known/jwks.json',
  issuer: 'cerberus',
  audience: 'cerberus-clients',
  jwksCacheTtlMs: 30_000,
  jwksRequestTimeoutMs: 5_000,
};

class TestController {
  @Public()
  public open(): void {
    /* noop */
  }

  public restricted(): void {
    /* noop */
  }
}

const controller = new TestController();

function handler(name: 'open' | 'restricted'): object {
  return Reflect.get(controller, name);
}

function buildContext(
  headers: Record<string, string>,
  handler: unknown,
): { context: ExecutionContext; request: Request } {
  const request = { headers } as unknown as Request;
  const context = {
    getHandler: () => handler,
    getClass: () => TestController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { context, request };
}

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;

  beforeEach(() => {
    jest.clearAllMocks();
    guard = new JwtAuthGuard(
      new Reflector(),
      new JwksPrincipalProvider(PROVIDER_OPTIONS),
    );
  });

  it('hands JWKS cache/timeout options to jose', () => {
    expect(mockCreateRemoteJWKSet).toHaveBeenCalledWith(
      new URL(PROVIDER_OPTIONS.jwksUrl),
      {
        cooldownDuration: PROVIDER_OPTIONS.jwksCacheTtlMs,
        timeoutDuration: PROVIDER_OPTIONS.jwksRequestTimeoutMs,
      },
    );
  });

  it('attaches the principal to the request on a valid token', async () => {
    mockJwtVerify.mockResolvedValue(VERIFY_RESULT);
    const { context, request } = buildContext(
      { authorization: `Bearer ${TOKEN}` },
      handler('restricted'),
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);

    expect(mockJwtVerify).toHaveBeenCalledWith(
      TOKEN,
      {},
      { issuer: 'cerberus', audience: 'cerberus-clients' },
    );
    const principal = (request as Request & { user: unknown }).user as {
      subjectId: string;
      orgId: string;
      role: string;
      scopes: string[];
      tokenType: string;
      expiresAt: Date;
    };
    expect(principal.subjectId).toBe(CLAIMS.sub);
    expect(principal.orgId).toBe(CLAIMS.org);
    expect(principal.role).toBe('ADMIN');
    expect(principal.scopes).toEqual(['content:read', 'content:write']);
    expect(principal.tokenType).toBe('user');
    expect(principal.expiresAt).toEqual(new Date(CLAIMS.exp * 1000));
  });

  it('rejects expired tokens with 401 authorization.token.invalid', async () => {
    mockJwtVerify.mockRejectedValue(new Error('JWT expired at 1735689600'));
    const { context } = buildContext(
      { authorization: `Bearer ${TOKEN}` },
      handler('restricted'),
    );

    await expect(guard.canActivate(context)).rejects.toMatchObject({
      name: 'AuthGuardError',
      code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
      status: 401,
    });
  });

  it('rejects wrong-audience tokens with 401 authorization.token.invalid', async () => {
    mockJwtVerify.mockRejectedValue(new Error('audience mismatch'));
    const { context } = buildContext(
      { authorization: `Bearer ${TOKEN}` },
      handler('restricted'),
    );

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      AuthGuardError,
    );
    await expect(guard.canActivate(context)).rejects.toMatchObject({
      code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
      status: 401,
    });
  });

  it('rejects malformed authorization headers without calling jose', async () => {
    const { context } = buildContext(
      { authorization: 'Token abc.def.ghi' },
      handler('restricted'),
    );

    await expect(guard.canActivate(context)).rejects.toMatchObject({
      code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
      status: 401,
    });
    expect(mockJwtVerify).not.toHaveBeenCalled();
  });

  it('rejects missing authorization headers without calling jose', async () => {
    const { context } = buildContext({}, handler('restricted'));

    await expect(guard.canActivate(context)).rejects.toMatchObject({
      code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
      status: 401,
    });
    expect(mockJwtVerify).not.toHaveBeenCalled();
  });

  it('allows @Public() routes without any token', async () => {
    const { context } = buildContext({}, handler('open'));

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(mockJwtVerify).not.toHaveBeenCalled();
  });
});
