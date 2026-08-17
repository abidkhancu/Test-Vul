module github.com/ubank/vuln-platform

go 1.22

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.6.0
	github.com/jung-kurt/gofpdf v1.16.2
	github.com/rs/zerolog v1.33.0
	github.com/xuri/excelize/v2 v2.9.0
	golang.org/x/crypto v0.28.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826 // indirect
	github.com/richardlehane/mscfb v1.0.4 // indirect
	github.com/richardlehane/msoleps v1.0.4 // indirect
	github.com/xuri/efp v0.0.0-20240408161823-9ad904a10d6d // indirect
	github.com/xuri/nfp v0.0.0-20240318013403-ab9948c2c4a7 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/text v0.19.0 // indirect
)

// Not yet imported by any code in this repo, but plausibly useful for
// later work: github.com/go-playground/validator/v10 (request
// validation), github.com/prometheus/client_golang (metrics),
// go.opentelemetry.io/otel (tracing), github.com/spf13/cobra (CLI
// subcommands). Add to `require` when actually imported, then
// `go mod tidy`.

// The replace block below works around this build environment having
// no route to proxy.golang.org — see README.md's "Reproducing the
// dependency-resolution workaround" section for what it does and why,
// and remove it on a machine with normal internet access, where a
// plain `go mod tidy` regenerates a real go.sum without any of this.
replace (
	golang.org/x/crypto => github.com/golang/crypto v0.17.0
	golang.org/x/image => github.com/golang/image v0.19.0
	golang.org/x/mod => github.com/golang/mod v0.20.0
	golang.org/x/net => github.com/golang/net v0.28.0
	golang.org/x/sync => github.com/golang/sync v0.8.0
	golang.org/x/sys => github.com/golang/sys v0.24.0
	golang.org/x/telemetry => github.com/golang/telemetry v0.0.0-20240521205824-bda55230c457
	golang.org/x/term => github.com/golang/term v0.23.0
	golang.org/x/text => github.com/golang/text v0.14.0
	golang.org/x/tools => github.com/golang/tools v0.24.0
	gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20180628173108-788fd7840127
	gopkg.in/yaml.v3 => github.com/go-yaml/yaml v0.0.0-20220521103104-8f96da9f5d5e
)
