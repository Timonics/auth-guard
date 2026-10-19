import { DynamicModule, Module, Provider } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { GlobalAuthExceptionFilter } from './auth-exception.filter';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwksPrincipalProvider } from './jwks-principal-provider';
import { PrincipalProvider } from './principal';
import { ScopesGuard } from './scopes.guard';

export const AUTH_GUARD_OPTIONS = Symbol('AUTH_GUARD_OPTIONS');

export type AuthGuardModuleOptions = {
  /**
   * cerberus JWKS endpoint, e.g.
   * `https://cerberus.example.com/.well-known/jwks.json`.
   * Must be https:// — http:// is only accepted for
   * localhost / 127.0.0.1 (local dev). Validated at bootstrap.
   */
  jwksUrl: string;
  /** Expected `iss` claim. Defaults to `'cerberus'`. */
  issuer?: string;
  /** Expected `aud` claim. Defaults to `'cerberus-clients'`. */
  audience?: string;
  /** JWKS cache cooldown handed to jose. Defaults to 30s. */
  jwksCacheTtlMs?: number;
  /** JWKS fetch timeout handed to jose. Defaults to 5s. */
  jwksRequestTimeoutMs?: number;
  /**
   * When true (default), registers `JwtAuthGuard`, `ScopesGuard` and
   * `GlobalAuthExceptionFilter` globally via `APP_GUARD` / `APP_FILTER`
   * multi-providers. Set false to wire the guards/filter yourself.
   */
  applyGlobal?: boolean;
};

export type ResolvedAuthGuardOptions = Required<AuthGuardModuleOptions>;

const OPTION_DEFAULTS = {
  issuer: 'cerberus',
  audience: 'cerberus-clients',
  jwksCacheTtlMs: 30_000,
  jwksRequestTimeoutMs: 5_000,
  applyGlobal: true,
} as const;

/**
 * Validate `jwksUrl` — must parse as a URL and use https://, except
 * http://localhost:* and http://127.0.0.1:* which are accepted for
 * local dev. Throws loudly at bootstrap; there are no silent
 * fallbacks.
 */
export function validateJwksUrl(jwksUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(jwksUrl);
  } catch {
    throw new Error(`auth-guard: jwksUrl is not a valid URL: ${jwksUrl}`);
  }
  if (parsed.protocol === 'https:') {
    return;
  }
  const isLocalHttp =
    parsed.protocol === 'http:' &&
    (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1');
  if (isLocalHttp) {
    return;
  }
  throw new Error(
    'auth-guard: jwksUrl must use https:// ' +
      '(http:// is only allowed for localhost/127.0.0.1): ' +
      jwksUrl,
  );
}

export function resolveAuthGuardOptions(
  options: AuthGuardModuleOptions,
): ResolvedAuthGuardOptions {
  if (!options || typeof options.jwksUrl !== 'string') {
    throw new Error('auth-guard: `jwksUrl` is required');
  }
  validateJwksUrl(options.jwksUrl);
  return {
    jwksUrl: options.jwksUrl,
    issuer: options.issuer ?? OPTION_DEFAULTS.issuer,
    audience: options.audience ?? OPTION_DEFAULTS.audience,
    jwksCacheTtlMs: options.jwksCacheTtlMs ?? OPTION_DEFAULTS.jwksCacheTtlMs,
    jwksRequestTimeoutMs:
      options.jwksRequestTimeoutMs ?? OPTION_DEFAULTS.jwksRequestTimeoutMs,
    applyGlobal: options.applyGlobal ?? OPTION_DEFAULTS.applyGlobal,
  };
}

@Module({})
export class AuthGuardModule {
  public static forRoot(options: AuthGuardModuleOptions): DynamicModule {
    const resolved = resolveAuthGuardOptions(options);

    const providers: Provider[] = [
      { provide: AUTH_GUARD_OPTIONS, useValue: resolved },
      {
        provide: PrincipalProvider,
        useFactory: (opts: ResolvedAuthGuardOptions) =>
          new JwksPrincipalProvider(opts),
        inject: [AUTH_GUARD_OPTIONS],
      },
      JwtAuthGuard,
      ScopesGuard,
    ];
    const exports_: NonNullable<DynamicModule['exports']> = [
      AUTH_GUARD_OPTIONS,
      PrincipalProvider,
      JwtAuthGuard,
      ScopesGuard,
    ];

    if (resolved.applyGlobal) {
      providers.push(
        GlobalAuthExceptionFilter,
        { provide: APP_GUARD, useExisting: JwtAuthGuard },
        { provide: APP_GUARD, useExisting: ScopesGuard },
        { provide: APP_FILTER, useExisting: GlobalAuthExceptionFilter },
      );
      exports_.push(GlobalAuthExceptionFilter);
    }

    return {
      module: AuthGuardModule,
      providers,
      exports: exports_,
    };
  }
}
