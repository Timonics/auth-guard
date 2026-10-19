import {
  AuthGuardModule,
  resolveAuthGuardOptions,
  validateJwksUrl,
} from './auth-guard.module';

describe('validateJwksUrl', () => {
  it('accepts https URLs', () => {
    expect(() =>
      validateJwksUrl('https://cerberus.example.com/.well-known/jwks.json'),
    ).not.toThrow();
  });

  it('accepts http localhost URLs for local dev', () => {
    expect(() =>
      validateJwksUrl('http://localhost:3000/.well-known/jwks.json'),
    ).not.toThrow();
    expect(() =>
      validateJwksUrl('http://127.0.0.1:8080/.well-known/jwks.json'),
    ).not.toThrow();
  });

  it('throws on non-URL strings', () => {
    expect(() => validateJwksUrl('not-a-url')).toThrow(
      /jwksUrl is not a valid URL/,
    );
  });

  it('throws on remote http URLs', () => {
    expect(() =>
      validateJwksUrl('http://cerberus.example.com/.well-known/jwks.json'),
    ).toThrow(/must use https/);
  });
});

describe('resolveAuthGuardOptions', () => {
  it('applies cerberus defaults', () => {
    expect(
      resolveAuthGuardOptions({
        jwksUrl: 'https://cerberus.example.com/.well-known/jwks.json',
      }),
    ).toEqual({
      jwksUrl: 'https://cerberus.example.com/.well-known/jwks.json',
      issuer: 'cerberus',
      audience: 'cerberus-clients',
      jwksCacheTtlMs: 30_000,
      jwksRequestTimeoutMs: 5_000,
      applyGlobal: true,
    });
  });

  it('keeps explicit overrides', () => {
    const resolved = resolveAuthGuardOptions({
      jwksUrl: 'http://localhost:3000/.well-known/jwks.json',
      issuer: 'cerberus-test',
      audience: 'test-clients',
      jwksCacheTtlMs: 1_000,
      jwksRequestTimeoutMs: 500,
      applyGlobal: false,
    });
    expect(resolved.issuer).toBe('cerberus-test');
    expect(resolved.applyGlobal).toBe(false);
  });

  it('throws loudly when jwksUrl is missing', () => {
    expect(() => resolveAuthGuardOptions({} as { jwksUrl: string })).toThrow(
      /jwksUrl.*required/,
    );
  });
});

describe('AuthGuardModule.forRoot', () => {
  it('throws at bootstrap on an invalid jwksUrl', () => {
    expect(() =>
      AuthGuardModule.forRoot({ jwksUrl: 'http://evil.example.com/jwks' }),
    ).toThrow(/must use https/);
  });

  it('produces a dynamic module with guards and filter providers', () => {
    const dynamicModule = AuthGuardModule.forRoot({
      jwksUrl: 'https://cerberus.example.com/.well-known/jwks.json',
    });
    expect(dynamicModule.module).toBe(AuthGuardModule);
    const provides = dynamicModule.providers?.map((p) =>
      typeof p === 'object' && p !== null && 'provide' in p
        ? String((p as { provide: unknown }).provide)
        : String(p),
    );
    expect(provides).toEqual(
      expect.arrayContaining(['Symbol(PrincipalProvider)']),
    );
  });
});
