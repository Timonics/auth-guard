import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';
import { SCOPES_KEY } from './decorators';
import { Principal } from './principal';

/**
 * Global authorization guard — runs AFTER JwtAuthGuard (registration
 * order in `AuthGuardModule.forRoot`), so `req.user` is populated.
 *
 * Reads the `@Scopes()` metadata: the principal needs ANY of the
 * listed scopes. No metadata → pass. Missing principal (should not
 * happen with the global guards) → 401. Insufficient scope → 403
 * `authorization.scope.missing`.
 */
@Injectable()
export class ScopesGuard implements CanActivate {
  public constructor(private readonly reflector: Reflector) {}

  public canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>(SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const principal = (request as Request & { user?: Principal }).user;
    if (!principal) {
      throw new AuthGuardError(
        AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
        401,
        'No authenticated principal — JwtAuthGuard must run first',
      );
    }
    const hasScope = required.some((scope) => principal.scopes.includes(scope));
    if (!hasScope) {
      throw new AuthGuardError(
        AUTH_GUARD_ERROR_CODES.SCOPE_MISSING,
        403,
        `Missing required scope(s): ${required.join(', ')}`,
      );
    }
    return true;
  }
}
