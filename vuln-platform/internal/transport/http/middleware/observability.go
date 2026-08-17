package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// RequestLogging logs one structured line per request: method, path,
// status, duration, and a per-request correlation ID that handlers
// can thread into audit log entries so an HTTP request and the audit
// trail it produced can be tied together.
func RequestLogging(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			requestID := uuid.New().String()
			ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r.WithContext(ctx))

			log.Info().
				Str("request_id", requestID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", sw.status).
				Dur("duration", time.Since(start)).
				Str("remote_addr", r.RemoteAddr).
				Msg("http request")
		})
	}
}

type contextKeyRequestID string

const requestIDContextKey contextKeyRequestID = "request_id"

func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDContextKey).(string)
	return id
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Recover catches panics in downstream handlers, logs them with a
// stack-adjacent message, and returns 500 rather than crashing the
// whole server process on one bad request — important given this
// serves production infrastructure tooling where availability of the
// dashboard itself matters.
func Recover(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error().Interface("panic", rec).Str("path", r.URL.Path).Msg("recovered from panic in HTTP handler")
					writeError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter is a simple in-memory fixed-window limiter keyed by
// remote address. Adequate for a single-instance deployment; replace
// with a Redis-backed limiter (the spec's Redis dependency) before
// running more than one API replica, since per-instance in-memory
// counters don't coordinate across replicas.
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{requests: make(map[string][]time.Time), limit: limit, window: window}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		now := time.Now()

		rl.mu.Lock()
		cutoff := now.Add(-rl.window)
		kept := rl.requests[key][:0]
		for _, t := range rl.requests[key] {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) >= rl.limit {
			rl.mu.Unlock()
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		rl.requests[key] = append(kept, now)
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}
