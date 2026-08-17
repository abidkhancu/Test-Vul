module github.com/ubank/vuln-platform

go 1.22

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/jung-kurt/gofpdf v1.16.2
	github.com/rs/zerolog v1.33.0
	github.com/spf13/viper v1.19.0
	github.com/xuri/excelize/v2 v2.9.0
	golang.org/x/crypto v0.26.0
)

// Not yet imported by code in this slice (Import -> Extraction ->
// Correlation), but required by later slices per the spec. Add these
// to `require` as each slice is built, then run `go mod tidy`:
//
//   github.com/go-playground/validator/v10   -- HTTP request validation
//   golang.org/x/sync                        -- worker pool primitives (errgroup etc.)
//   github.com/prometheus/client_golang      -- metrics
//   go.opentelemetry.io/otel                 -- tracing
//   github.com/spf13/cobra                   -- CLI subcommands (migrate, seed, etc.)
//   golang.org/x/crypto/bcrypt               -- password hashing

// NOTE: this sandbox has no route to proxy.golang.org (only a fixed
// domain allowlist), so `go mod tidy` / `go build` could not be fully
// completed here -- resolution got as far as pgx's and zerolog's
// direct-VCS transitive deps before hitting golang.org/x/*,
// go.opentelemetry.io, and gopkg.in hosts blocked by this sandbox's
// egress rules. The code itself was verified with `gofmt` and
// `go vet` (parses cleanly; the only errors surfaced were missing
// go.sum / network errors, not syntax errors). Run `go mod tidy` on
// a machine with normal internet access to generate a real go.sum,
// then `go build ./...`.


