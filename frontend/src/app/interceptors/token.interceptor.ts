import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

/**
 * Enhanced Token Interceptor (Phase 7 - A07:2025)
 * 
 * Features:
 * - Automatically injects JWT Bearer token into outgoing HTTP requests.
 * - Catches HTTP 401 Unauthorized errors caused by expired Access Tokens (15 min).
 * - Automatically calls /api/auth/refresh to rotate and obtain a fresh Access Token.
 * - Seamlessly replays the original failed request with the new Access Token.
 * - Falls back to logout if the refresh token is missing or expired.
 */
export const tokenInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const token = authService.getToken();

  // Endpoints that do not require an existing access token
  const isPublicAuthEndpoint = req.url.includes('/api/auth/login') || req.url.includes('/api/auth/refresh');

  let authReq = req;
  if (token && !isPublicAuthEndpoint) {
    authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      // Catch 401 Unauthorized errors on protected requests
      if (error.status === 401 && !isPublicAuthEndpoint) {
        const refreshToken = authService.getRefreshToken();

        if (refreshToken) {
          // Attempt automatic token refresh
          return authService.refreshToken().pipe(
            switchMap((response: any) => {
              const newAccessToken = response?.accessToken || authService.getToken();

              // Replay the original request with the fresh Access Token
              const retriedReq = req.clone({
                setHeaders: {
                  Authorization: `Bearer ${newAccessToken}`
                }
              });
              return next(retriedReq);
            }),
            catchError((refreshError) => {
              // Refresh token is expired or revoked -> force logout
              authService.logout();
              return throwError(() => refreshError);
            })
          );
        } else {
          // No refresh token available -> logout
          authService.logout();
        }
      }

      return throwError(() => error);
    })
  );
};
