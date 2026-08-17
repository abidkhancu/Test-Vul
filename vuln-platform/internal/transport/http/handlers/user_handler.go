package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
	"github.com/ubank/vuln-platform/internal/usecase/auth"

	vhttp "github.com/ubank/vuln-platform/internal/transport/httpresponse"
)

// UserHandler implements user management. Every route it exposes is
// mounted behind middleware.RequireRole(entity.RoleAdministrator) in
// the router — see entity.Role.CanManageUsers, which is the single
// definition of "who may create/modify accounts" that both the router
// and (redundantly, defensively) this handler's own checks rely on.
type UserHandler struct {
	users repository.UserRepository
}

func NewUserHandler(users repository.UserRepository) *UserHandler {
	return &UserHandler{users: users}
}

var validRoles = map[entity.Role]struct{}{
	entity.RoleAdministrator:   {},
	entity.RoleSecurityAnalyst: {},
	entity.RoleOperator:        {},
	entity.RolePatchApprover:   {},
	entity.RoleViewer:          {},
}

type createUserRequest struct {
	Username string      `json:"username"`
	Email    string      `json:"email"`
	Password string      `json:"password"`
	Role     entity.Role `json:"role"`
}

// POST /api/v1/users
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		vhttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Email == "" {
		vhttp.WriteError(w, http.StatusBadRequest, "username and email are required")
		return
	}
	if len(req.Password) < 12 {
		vhttp.WriteError(w, http.StatusBadRequest, "password must be at least 12 characters")
		return
	}
	if _, ok := validRoles[req.Role]; !ok {
		vhttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid role %q", req.Role))
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user := &entity.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         req.Role,
		IsActive:     true,
	}
	if err := h.users.Create(r.Context(), user); err != nil {
		vhttp.WriteError(w, http.StatusConflict, "failed to create user (username or email may already be in use): "+err.Error())
		return
	}

	vhttp.WriteJSON(w, http.StatusCreated, userSummary{ID: user.ID, Username: user.Username, Role: string(user.Role)})
}

// GET /api/v1/users?page=&page_size=
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	users, total, err := h.users.List(r.Context(), page, pageSize)
	if err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, map[string]interface{}{"users": users, "total": total})
}

// GET /api/v1/users/{id}
func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	user, err := h.users.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		vhttp.WriteError(w, http.StatusNotFound, "user not found")
		return
	}
	vhttp.WriteJSON(w, http.StatusOK, user)
}

type setRoleRequest struct {
	Role entity.Role `json:"role"`
}

// PATCH /api/v1/users/{id}/role
func (h *UserHandler) SetRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req setRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		vhttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, ok := validRoles[req.Role]; !ok {
		vhttp.WriteError(w, http.StatusBadRequest, fmt.Sprintf("invalid role %q", req.Role))
		return
	}

	if err := h.users.SetRole(r.Context(), id, req.Role); err != nil {
		vhttp.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type setActiveRequest struct {
	Active bool `json:"active"`
}

// PATCH /api/v1/users/{id}/active
//
// Deactivating rather than deleting a user preserves referential
// integrity with everything they touched historically (approved
// remediation tasks, patch jobs, audit log entries all reference a
// user ID) — accounts are disabled, never hard-deleted.
func (h *UserHandler) SetActive(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req setActiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		vhttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.users.SetActive(r.Context(), id, req.Active); err != nil {
		vhttp.WriteError(w, http.StatusInternalServerError, "failed to update user status")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
