export const AUTH_GUARD_ERROR_CODES = {
  TOKEN_INVALID: 'authorization.token.invalid',
  SCOPE_MISSING: 'authorization.scope.missing',
  INTERNAL_ERROR: 'internal.error',
} as const;

export type AuthGuardErrorCode =
  (typeof AUTH_GUARD_ERROR_CODES)[keyof typeof AUTH_GUARD_ERROR_CODES];

/**
 * Error thrown by the auth-guard guards. Carries the machine-readable
 * `code` rendered in the response body and the HTTP `status` it maps
 * to. `GlobalAuthExceptionFilter` turns these into
 * `{ code, message }` responses.
 */
export class AuthGuardError extends Error {
  public constructor(
    public readonly code: string,
    public readonly status: number,
    message?: string,
  ) {
    super(message ?? code);
    this.name = 'AuthGuardError';
    Object.setPrototypeOf(this, AuthGuardError.prototype);
  }
}
