import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AUTH_GUARD_ERROR_CODES, AuthGuardError } from './auth-guard-error';

/**
 * Renders `AuthGuardError` as `{ code, message }` with the error's
 * status. Anything else (this is a catch-all filter) is logged with
 * its stack and rendered as 500 `{ "code": "internal.error" }` —
 * same shape as cerberus's DomainErrorFilter.
 *
 * NOTE: being catch-all, this filter claims every exception that no
 * more-specific filter claimed first. If the consuming app has its
 * own exception filters for other error classes, register them via
 * `APP_FILTER` and make sure they win the dispatch order (import the
 * app's error-handling module before `AuthGuardModule`).
 */
@Catch()
export class GlobalAuthExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalAuthExceptionFilter.name);

  public catch(exception: unknown, host: ArgumentsHost): void {
    if (host.getType<string>() !== 'http') {
      throw exception;
    }
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    if (exception instanceof AuthGuardError) {
      this.logger.debug(
        `[${exception.status}] ${request.method} ${request.url} -> ${exception.code}: ${exception.message}`,
      );
      response.status(exception.status).json({
        code: exception.code,
        message: exception.message,
      });
      return;
    }

    this.logger.error(
      `Unhandled error at ${request.method} ${request.url}: ${String(exception)}`,
      exception instanceof Error ? exception.stack : undefined,
    );
    response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      code: AUTH_GUARD_ERROR_CODES.INTERNAL_ERROR,
      message: 'Internal server error',
    });
  }
}
