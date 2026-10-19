import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { AUTH_GUARD_ERROR_CODES } from './auth-guard-error';
import { Scopes } from './decorators';
import { Principal } from './principal';
import { ScopesGuard } from './scopes.guard';

class TestController {
  @Scopes('content:write')
  public write(): void {
    /* noop */
  }

  public open(): void {
    /* noop */
  }
}

const guard = new ScopesGuard(new Reflector());

function buildContext(
  principal: Principal | undefined,
  handler: unknown,
): ExecutionContext {
  const request = { user: principal } as unknown as Request;
  return {
    getHandler: () => handler,
    getClass: () => TestController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

function principalWith(scopes: string[]): Principal {
  return {
    subjectId: '11111111-2222-3333-4444-555555555555',
    orgId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    role: 'MEMBER',
    scopes,
    tokenType: 'user',
    expiresAt: new Date(1_735_689_600_000),
  };
}

describe('ScopesGuard', () => {
  const controller = new TestController();

  function handler(name: 'open' | 'write'): object {
    return Reflect.get(controller, name);
  }

  it('passes routes without @Scopes() metadata', () => {
    expect(guard.canActivate(buildContext(undefined, handler('open')))).toBe(
      true,
    );
  });

  it('fails with 403 authorization.scope.missing when scopes do not overlap', () => {
    const context = buildContext(
      principalWith(['content:read']),
      handler('write'),
    );

    expect(() => guard.canActivate(context)).toThrow(
      expect.objectContaining({
        name: 'AuthGuardError',
        code: AUTH_GUARD_ERROR_CODES.SCOPE_MISSING,
        status: 403,
      }),
    );
  });

  it('passes when the principal has ANY of the required scopes', () => {
    const context = buildContext(
      principalWith(['content:read', 'content:write']),
      handler('write'),
    );

    expect(guard.canActivate(context)).toBe(true);
  });

  it('fails when no principal is attached (guard ordering broken)', () => {
    const context = buildContext(undefined, handler('write'));

    expect(() => guard.canActivate(context)).toThrow(
      expect.objectContaining({
        code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
        status: 401,
      }),
    );
  });
});
