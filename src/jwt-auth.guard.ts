import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';
import { PUBLIC_KEY } from './decorators';
import { Principal, PrincipalProvider } from './principal';

/**
 * Global authentication guard. Resolves the request's principal via
 * the configured `PrincipalProvider` and attaches it to `req.user`.
 *
 * Behavior:
 *
 *   1. Route marked `@Public()` → skip, `req.user` stays undefined.
 *   2. Provider throws (missing/malformed Bearer header, verification
 *      failure of any kind — expired, wrong issuer/audience, unknown
 *      kid, JWKS unreachable) → 401 `authorization.token.invalid`.
 *      The underlying error is logged server-side only; the response
 *      stays deliberately uninformative.
 *   3. Success → `req.user = principal`, pass to ScopesGuard.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private static readonly logger = new Logger(JwtAuthGuard.name);

  public constructor(
    private readonly reflector: Reflector,
    @Inject(PrincipalProvider)
    private readonly principalProvider: PrincipalProvider,
  ) {}

  public async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    let principal: Principal;
    try {
      principal = await this.principalProvider.resolvePrincipal(request);
    } catch (err) {
      if (err instanceof AuthGuardError) {
        throw err;
      }
      // Log the underlying jose/JWKS error server-side, but never leak
      // it to the caller ("JWT expired", "issuer mismatch", ... are
      // useful signals for someone probing the token surface).
      JwtAuthGuard.logger.warn(`principal resolution failed: ${String(err)}`);
      throw new AuthGuardError(
        AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
        401,
        'JWT verification failed',
      );
    }

    (request as Request & { user: Principal }).user = principal;
    return true;
  }
}
