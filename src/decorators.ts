import {
  createParamDecorator,
  ExecutionContext,
  SetMetadata,
} from '@nestjs/common';
import type { Request } from 'express';
import { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';
import { Principal } from './principal';

/**
 * Mark a route (or a whole controller) as public — bypasses
 * JwtAuthGuard. `req.user` is left undefined; endpoints that still
 * want a principal when one is presented should read it via
 * `@CurrentPrincipal()` guarded by their own logic.
 */
export const PUBLIC_KEY = 'timonics:public-route';
export const Public = (): MethodDecorator & ClassDecorator =>
  SetMetadata(PUBLIC_KEY, true);

/**
 * Require that the caller's token carries ANY of the listed scopes.
 * Used together with the global `ScopesGuard` (which runs after
 * `JwtAuthGuard`).
 */
export const SCOPES_KEY = 'timonics:required-scopes';
export const Scopes = (...scopes: string[]): MethodDecorator =>
  SetMetadata(SCOPES_KEY, scopes);

/**
 * Extract the authenticated principal from the request.
 *
 * `JwtAuthGuard` populates `req.user` after verifying the Bearer
 * token; this decorator just plucks it out. If no principal is
 * attached (e.g. the route is `@Public()` or the guard didn't run),
 * it throws 401 `authorization.token.invalid`.
 */
export const CurrentPrincipal = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Principal => {
    const req = ctx.switchToHttp().getRequest<Request>();
    const principal = (req as Request & { user?: Principal }).user;
    if (!principal) {
      throw new AuthGuardError(
        AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
        401,
        'No authenticated principal on request',
      );
    }
    return principal;
  },
);
