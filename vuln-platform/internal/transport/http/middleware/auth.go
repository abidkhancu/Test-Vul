// Package middleware implements HTTP cross-cutting concerns: JWT
// authentication, RBAC authorization, request logging, panic
// recovery, and rate limiting.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/usecase/auth"
)

type contextKey string

const claimsContextKey contextKey = "auth_claims"

// Authenticate validates the Bearer JWT on every request it wraps and
// stores the parsed claims in the request context. Handlers retrieve
// them via ClaimsFromContext. Requests without a valid token receive
// 401 and never reach the handler.
func Authenticate(authSvc *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
				return
			}
			tokenString := strings.TrimPrefix(header, "Bearer ")

			claims, err := authSvc.VerifyAccessToken(tokenString)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext retrieves the authenticated user's claims. Only
// valid to call on requests that passed through Authenticate — panics
// with a clear message otherwise, since that indicates a route was
// mounted without the auth middleware, which is a wiring bug that
// should fail loudly in development rather than silently proceed
// unauthenticated.
func ClaimsFromContext(ctx context.Context) *auth.Claims {
	claims, ok := ctx.Value(claimsContextKey).(*auth.Claims)
	if !ok {
		panic("middleware.ClaimsFromContext called on a request that didn't pass through Authenticate — check route wiring")
	}
	return claims
}

// RequireRole restricts a route to the given set of roles. Must be
// mounted after Authenticate. This is the sole place route-level RBAC
// decisions get made — handlers themselves should not re-implement
// role checks, so "who can approve patches" etc. stays defined once
// (on entity.Role's methods) and enforced once (here).
func RequireRole(allowed ...entity.Role) func(http.Handler) http.Handler {
	allowedSet := make(map[entity.Role]struct{}, len(allowed))
	for _, r := range allowed {
		allowedSet[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if _, ok := allowedSet[claims.Role]; !ok {
				writeError(w, http.StatusForbidden, "your role does not have permission to perform this action")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePatchApprover is a convenience wrapper matching the spec's
// approval-gate requirement directly, using entity.Role.CanApprovePatches
// rather than an explicit role list, so it stays in sync automatically
// if that method's definition changes.
func RequirePatchApprover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if !claims.Role.CanApprovePatches() {
			writeError(w, http.StatusForbidden, "patch approval requires the patch_approver or administrator role")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
