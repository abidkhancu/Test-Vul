// Package handlers implements HTTP handler functions for each
// /api/v1/* resource group. Handlers are intentionally thin: parse
// request, call a usecase, translate the result/error to an HTTP
// response. Business logic and safety invariants live in the usecase
// layer (already enforced regardless of what a handler does), not
// here — a handler bug should be able to produce a wrong HTTP
// response, never bypass an approval check.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ubank/vuln-platform/internal/transport/http/middleware"
	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
	"github.com/ubank/vuln-platform/internal/usecase/auth"
)

type AuthHandler struct {
	svc *auth.Service
}

func NewAuthHandler(svc *auth.Service) *AuthHandler {
	return &AuthHandler{svc: svc}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresAt    string      `json:"expires_at"`
	User         userSummary `json:"user"`
}

type userSummary struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		vhttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		vhttp.WriteError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	pair, user, err := h.svc.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, auth.ErrAccountInactive):
			status = http.StatusForbidden
		}
		vhttp.WriteError(w, status, err.Error())
		return
	}

	vhttp.WriteJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		ExpiresAt:    pair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		User:         userSummary{ID: user.ID, Username: user.Username, Role: string(user.Role)},
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		vhttp.WriteError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	pair, err := h.svc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		vhttp.WriteError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	vhttp.WriteJSON(w, http.StatusOK, map[string]string{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"expires_at":    pair.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// POST /api/v1/auth/logout — requires Authenticate middleware.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if err := h.svc.Logout(r.Context(), claims.UserID); err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to log out")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/v1/auth/me — requires Authenticate middleware.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	vhttp.WriteJSON(w, http.StatusOK, userSummary{ID: claims.UserID, Username: claims.Username, Role: string(claims.Role)})
}
