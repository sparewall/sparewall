import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';

import { REQUEST_HEADER } from '../api/api-client';
import { Session } from './session';

/**
 * Adds the custom header to every API call, and sends the user to sign
 * in again when the node no longer takes the session.
 */
export const requestHeader: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith('/call/')) return next(req);
  const session = inject(Session);
  const login = req.url.endsWith('.Auth.Login');
  return next(req.clone({ setHeaders: { [REQUEST_HEADER]: '1' } })).pipe(
    catchError((e: unknown) => {
      if (!login && e instanceof HttpErrorResponse && e.status === 401) session.ended();
      return throwError(() => e);
    }),
  );
};
