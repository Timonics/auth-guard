import { Controller, Get, INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { jwtVerify } from 'jose';
import request from 'supertest';
import { AuthGuardModule } from './auth-guard.module';
import { AUTH_GUARD_ERROR_CODES } from './auth-guard-error';
import { CurrentPrincipal, Public, Scopes } from './decorators';
import { Principal } from './principal';

jest.mock('jose', () => ({
  createRemoteJWKSet: jest.fn().mockReturnValue({}),
  jwtVerify: jest.fn(),
}));

const mockJwtVerify = jwtVerify as jest.MockedFunction<typeof jwtVerify>;

const SUBJECT_ID = '11111111-2222-3333-4444-555555555555';
const ORG_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const EXP = 1_735_689_600;

function claimsWith(scope: string): Record<string, unknown> {
  return { sub: SUBJECT_ID, org: ORG_ID, role: 'MEMBER', scope, exp: EXP };
}

function verifyResult(scope: string) {
  return {
    payload: claimsWith(scope),
    protectedHeader: { alg: 'RS256', kid: 'test-key' },
    key: new Uint8Array(),
  };
}

@Controller()
class TestController {
  @Get('health')
  @Public()
  public health(): { ok: boolean } {
    return { ok: true };
  }

  @Get('content')
  @Scopes('content:write')
  public content(): { ok: boolean } {
    return { ok: true };
  }

  @Get('me')
  public me(@CurrentPrincipal() principal: Principal): Principal {
    return principal;
  }

  @Get('boom')
  public boom(): never {
    throw new Error('unexpected failure');
  }
}

describe('AuthGuardModule (integration)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        AuthGuardModule.forRoot({
          jwksUrl: 'https://cerberus.example.com/.well-known/jwks.json',
        }),
      ],
      controllers: [TestController],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockJwtVerify.mockReset();
  });

  it('serves @Public() endpoints without a token', async () => {
    await request(app.getHttpServer())
      .get('/health')
      .expect(200)
      .expect({ ok: true });
    expect(mockJwtVerify).not.toHaveBeenCalled();
  });

  it('returns 401 authorization.token.invalid without a token', async () => {
    await request(app.getHttpServer()).get('/me').expect(401).expect({
      code: AUTH_GUARD_ERROR_CODES.TOKEN_INVALID,
      message: 'Authorization: Bearer <token> header is required',
    });
  });

  it('returns the principal shape from @CurrentPrincipal() on success', async () => {
    mockJwtVerify.mockResolvedValue(verifyResult('content:read'));

    await request(app.getHttpServer())
      .get('/me')
      .set('Authorization', 'Bearer good.token.here')
      .expect(200)
      .expect((res) => {
        expect(res.body).toEqual({
          subjectId: SUBJECT_ID,
          orgId: ORG_ID,
          role: 'MEMBER',
          scopes: ['content:read'],
          tokenType: 'user',
          expiresAt: new Date(EXP * 1000).toISOString(),
        });
      });
  });

  it('returns 403 authorization.scope.missing when scopes do not overlap', async () => {
    mockJwtVerify.mockResolvedValue(verifyResult('content:read'));

    await request(app.getHttpServer())
      .get('/content')
      .set('Authorization', 'Bearer good.token.here')
      .expect(403)
      .expect((res) => {
        const body = res.body as { code: string; message: string };
        expect(body.code).toBe(AUTH_GUARD_ERROR_CODES.SCOPE_MISSING);
        expect(body.message).toContain('content:write');
      });
  });

  it('allows access when the principal carries the required scope', async () => {
    mockJwtVerify.mockResolvedValue(verifyResult('content:read content:write'));

    await request(app.getHttpServer())
      .get('/content')
      .set('Authorization', 'Bearer good.token.here')
      .expect(200)
      .expect({ ok: true });
  });

  it('maps unexpected errors to 500 internal.error', async () => {
    mockJwtVerify.mockResolvedValue(verifyResult('content:read'));

    await request(app.getHttpServer())
      .get('/boom')
      .set('Authorization', 'Bearer good.token.here')
      .expect(500)
      .expect({
        code: AUTH_GUARD_ERROR_CODES.INTERNAL_ERROR,
        message: 'Internal server error',
      });
  });
});
