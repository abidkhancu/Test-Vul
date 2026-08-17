// Package auth implements authentication: bcrypt password hashing,
// JWT access token issuance/verification, and refresh token rotation.
// RBAC authorization (what a role can do) lives on entity.Role's
// methods and is enforced by transport/http/middleware — this package
// only answers "who is this" and "prove you are who you say."
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/ubank/vuln-platform/internal/domain/entity"
	"github.com/ubank/vuln-platform/internal/domain/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountInactive    = errors.New("account is inactive")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

type Service struct {
	users         repository.UserRepository
	refreshTokens repository.RefreshTokenRepository
	signingKey    []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

func NewService(users repository.UserRepository, refreshTokens repository.RefreshTokenRepository, signingKey []byte, accessTTL, refreshTTL time.Duration) *Service {
	return &Service{
		users:         users,
		refreshTokens: refreshTokens,
		signingKey:    signingKey,
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

// Claims carried in the JWT access token. Role is embedded directly
// so middleware doesn't need a DB round-trip per request to enforce
// RBAC — at the cost of a stale role surviving until the token
// expires if an admin changes someone's role mid-session. accessTTL
// should be kept short (config default: 15m) specifically to bound
// that staleness window.
type Claims struct {
	UserID   string      `json:"uid"`
	Username string      `json:"username"`
	Role     entity.Role `json:"role"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// HashPassword bcrypt-hashes a plaintext password for storage. Uses
// bcrypt's default cost factor; bump via bcrypt.GenerateFromPassword's
// second argument if a security review calls for a higher cost.
func HashPassword(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// Login verifies credentials and issues a new access+refresh token
// pair. It deliberately returns the same generic ErrInvalidCredentials
// whether the username doesn't exist or the password is wrong, so
// responses don't leak which usernames are registered.
func (s *Service) Login(ctx context.Context, username, password string) (*TokenPair, *entity.User, error) {
	user, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		// Run bcrypt anyway against a dummy hash to keep response
		// timing similar whether or not the username exists —
		// reduces (does not eliminate) username-enumeration-by-timing.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$CwTycUXWue0Thq9StjUM0uJ8FQOTJlZ3lTfTKKqjTQKWzKV0G8vQK"), []byte(password))
		return nil, nil, ErrInvalidCredentials
	}
	if !user.IsActive {
		return nil, nil, ErrAccountInactive
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	pair, err := s.issueTokenPair(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	_ = s.users.UpdateLastLogin(ctx, user.ID)
	return pair, user, nil
}

// Refresh exchanges a valid, unrevoked refresh token for a new token
// pair, rotating the refresh token (the old one is revoked as part of
// this call) so a leaked refresh token has a single-use window rather
// than remaining valid for its full TTL after first use.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	hash := hashToken(refreshToken)
	stored, err := s.refreshTokens.GetByTokenHash(ctx, hash)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if stored.RevokedAt != nil || time.Now().After(stored.ExpiresAt) {
		return nil, ErrInvalidToken
	}

	user, err := s.users.Get(ctx, stored.UserID)
	if err != nil || !user.IsActive {
		return nil, ErrInvalidToken
	}

	if err := s.refreshTokens.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("revoke used refresh token: %w", err)
	}

	return s.issueTokenPair(ctx, user)
}

// Logout revokes all outstanding refresh tokens for a user. Access
// tokens already issued remain valid until their short TTL expires —
// this scaffold doesn't implement an access-token blocklist; add one
// (e.g. Redis-backed, keyed by JTI) if immediate access-token
// revocation on logout is a hard requirement.
func (s *Service) Logout(ctx context.Context, userID string) error {
	return s.refreshTokens.RevokeAllForUser(ctx, userID)
}

func (s *Service) issueTokenPair(ctx context.Context, user *entity.User) (*TokenPair, error) {
	now := time.Now()
	accessExp := now.Add(s.accessTTL)

	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			Subject:   user.ID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString(s.signingKey)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshRaw, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	refreshExp := now.Add(s.refreshTTL)
	if err := s.refreshTokens.Create(ctx, &entity.RefreshToken{
		UserID:    user.ID,
		TokenHash: hashToken(refreshRaw),
		ExpiresAt: refreshExp,
	}); err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	return &TokenPair{AccessToken: accessToken, RefreshToken: refreshRaw, ExpiresAt: accessExp}, nil
}

// VerifyAccessToken parses and validates a JWT access token, returning
// its claims. This is the function transport/http/middleware calls on
// every authenticated request.
func (s *Service) VerifyAccessToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return s.signingKey, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
