export { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';
export type { AuthGuardErrorCode } from './auth-guard-error';
export { GlobalAuthExceptionFilter } from './auth-exception.filter';
export {
  AuthGuardModule,
  AUTH_GUARD_OPTIONS,
  resolveAuthGuardOptions,
  validateJwksUrl,
} from './auth-guard.module';
export type {
  AuthGuardModuleOptions,
  ResolvedAuthGuardOptions,
} from './auth-guard.module';
export {
  CurrentPrincipal,
  Public,
  Scopes,
  PUBLIC_KEY,
  SCOPES_KEY,
} from './decorators';
export { JwtAuthGuard } from './jwt-auth.guard';
export { ScopesGuard } from './scopes.guard';
export {
  JwksPrincipalProvider,
  extractBearerToken,
} from './jwks-principal-provider';
export type { JwksPrincipalProviderOptions } from './jwks-principal-provider';
export { PrincipalProvider, principalFromClaims } from './principal';
export type { Principal, PrincipalRole } from './principal';
