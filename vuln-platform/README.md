# Enterprise Vulnerability Management Platform — Backend Core

Go/PostgreSQL foundation for a vulnerability management platform that
imports scanner reports, extracts CVEs/RHSAs, correlates duplicate
findings into remediation tasks, and (in later slices) verifies and
patches RHEL hosts over SSH under strict read-only-by-default,
approval-gated controls.

## What's built in this slice

- **Clean/Hexagonal architecture skeleton** — `internal/domain` (entities +
  repository ports), `internal/usecase` (business logic, zero DB
  imports), `internal/repository/postgres` (the only package that
  imports pgx).
- **PostgreSQL schema** (`migrations/0001_init_schema.sql`) covering
  users/roles, hosts/credentials, imports, CVEs/RHSAs + join tables,
  scanner findings, remediation tasks, patch jobs, maintenance
  windows, and an append-only audit log (UPDATE/DELETE blocked at the
  DB level via rules).
- **CSV & XLSX import engine** — column-alias-tolerant header mapping,
  missing columns don't fail the import, malformed rows are counted
  and skipped rather than aborting a 100k-row file, streamed rather
  than fully buffered.
- **CVE / RHSA / package extraction engine** — regex-based for
  `CVE-YYYY-NNNN` / `RHSA-YYYY:NNNN` (precise, auditable), heuristic
  known-package matching with NEVRA-suffix stripping for package
  names (extend `defaultKnownPackages` from your own advisory corpus).
- **Correlation engine** — collapses many raw findings into one
  `RemediationTask` per (host, RHSA) or (host, CVE-set), preferring a
  single covering advisory over N per-CVE tasks. Backed by a DB
  partial unique index so dedup is guaranteed at the storage layer,
  not just in application logic.
- **Async worker pool** — bounded goroutine pool consuming an
  `ImportJob` channel; each import triggers a post-import correlation
  pass, plus a 10-minute periodic reconciliation pass as a safety net.
- **Credential encryption** (`internal/crypto`) — AES-256-GCM, key
  rotation support via `KeyProvider`, plaintext zeroed after use,
  never logged.
- **SSH verification engine** (`internal/usecase/ssh`) — read-only by
  construction:
  - `commands.go` is the single choke point for what can ever be sent
    over an SSH session. It exposes only typed functions
    (`CheckAdvisory`, `VerifyPackage`, etc.) that return an opaque
    `ReadOnlyCommand`; there is no function anywhere in this package
    capable of building `dnf update`/`yum update`/`rpm -i` or similar.
    RHSA IDs, CVE IDs, and package names are validated against strict
    regexes before ever touching a command string.
  - `dialer.go` — connection pooling per host, jump-host tunneling,
    password/key auth, strict host-key verification (constant-time
    fingerprint comparison, refuses to connect on mismatch), retry
    with backoff, global concurrency cap.
  - `verifier.go` — runs the read-only workflow, classifies outcomes
    (Already Installed / Pending / Missing Repository / Package
    Missing / Not Applicable / Host Offline / SSH Failure) per spec,
    writes an audit log entry for **every** command run, updates
    `RemediationTask` status.
- **Patch approval + execution engine** (`internal/usecase/patch`) —
  isolated from the verification engine on purpose:
  - `guard.go` — `Guard.Authorize` is the *only* function in the
    codebase that can mint an `ApprovalToken`, and it re-reads the
    task's approval state from the database at call time rather than
    trusting in-memory/stale state. No exported constructor exists for
    `ApprovalToken` outside this function. A separate, more
    restrictive `AuthorizeFullSystemUpdate` path exists for the spec's
    one explicit exception to "never `-y`", gated behind both a
    deployment-level config flag and explicit per-request
    confirmation.
  - `commands.go` — `BuildAdvisoryPatch`/`BuildFullSystemUpdate` only
    accept an `ApprovalToken`, never a raw RHSA string.
  - `executor.go` — connects via the *same* path `Verifier` uses
    (jump hosts, host-key checks included), runs the approved command,
    **fails closed on audit-write failure** (an unaudited patch is
    treated as a failed patch, regardless of the remote exit code),
    then re-runs read-only verification post-patch rather than trusting
    the patch command's own exit code as proof of remediation.
- **Config** (zero-dependency stdlib, env-prefixed `VULN_*`) and **structured logging**
  (zerolog, JSON in non-dev environments).
- **Auth** (`internal/usecase/auth`) — bcrypt password hashing, JWT
  access tokens (short-lived, role embedded in claims), refresh token
  rotation with revocation-on-use, generic error on bad
  username/password (no user-enumeration signal), timing-equalized
  failed lookups.
- **HTTP transport** (`internal/transport/http`) — chi router, full
  middleware chain (panic recovery, structured request logging,
  in-memory rate limiting), and the `/api/v1/*` routes from the spec:
  auth, imports (upload → worker queue), findings, hosts (+ explicit
  host-key registration, administrator-only), remediation
  (list/get/verify/approve/reject), patches (execute/list/get), audit
  (administrator-only), plus `/healthz` and `/readyz` for k8s probes.
- **RBAC** (`internal/transport/http/middleware`, `entity.Role`) —
  role capability checks (`CanApprovePatches`, `CanRunVerification`,
  `CanManageUsers`, `CanWriteFindings`) live as methods on `Role` in
  one place; middleware and handlers call those methods rather than
  re-implementing role logic per endpoint. Patch approval/execution
  and audit log access are the most tightly gated routes.
- **Full pagination** — `FindingRepo.List`, `HostRepo.List`,
  `RemediationRepo.List`, and `AuditRepo.Query` all now have real
  dynamic WHERE-clause building + offset pagination (not stubs).
- **Verification scheduler** (`internal/scheduler`) — periodic sweep
  over tasks in `pending_verification`, so correlated tasks get
  checked over SSH without waiting on a manual "verify" click.
- **Maintenance window / scheduling check** — `patch.Guard.Authorize`
  now refuses to authorize execution if a task's `ScheduledFor` time
  is still in the future.
- **Initial admin bootstrap** — `cmd/server` seeds one administrator
  account on first boot from `VULN_SEED_ADMIN_USERNAME` /
  `_EMAIL` / `_PASSWORD` env vars if no users exist yet, so a fresh
  deploy is usable without direct DB access.
- **User management** (`internal/transport/http/handlers/user_handler.go`)
  — administrator-only endpoints to create users, list/get, change
  role, and activate/deactivate. Deactivation rather than deletion, so
  historical references (approvals, patch jobs, audit entries) stay
  intact.
- **Reporting engine** (`internal/usecase/reporting`) — all nine
  report types from the spec (executive_summary, technical, host,
  package, rhsa, cve, verification, patch, audit), each in PDF, and
  the tabular ones also in CSV/XLSX. One `Table` intermediate
  representation feeds both the CSV and XLSX renderers so there's no
  duplicated "how do I turn a ScannerFinding into a row" logic per
  format; PDF gets its own renderer (`gofpdf`) since it needs
  pagination/layout the other two don't. Executive summary is a
  numbers-first one-pager (PDF only); the rest are full tables.
  Reports are generated synchronously, written to disk, and recorded
  in the `reports` table for later re-download.

## What's intentionally stubbed / not yet built

| Area | Status |
|---|---|
| React/Next.js frontend | Not started |
| MFA | Schema has `mfa_enabled`/`mfa_secret_enc` columns; no TOTP flow implemented |
| Vault / KMS-backed credential encryption | `crypto.KeyProvider` is an interface specifically so a Vault-backed implementation can replace `StaticKeyProvider` without touching callers; not implemented |
| Access-token revocation on logout | `Logout` revokes refresh tokens; short-lived access tokens already issued remain valid until natural expiry (no blocklist) |
| Multi-instance rate limiting | `middleware.RateLimiter` is in-memory per-instance; fine for one API replica, needs a Redis-backed limiter before scaling out |
| Notifications (email/Slack/Teams) | Not started |
| OpenAPI spec generation | Not started — routes are defined in `router.go`; annotate with swaggo or similar if generated docs are needed |
| Report data source scale | `reporting.Generator` fetches via `repository.List` calls capped at `maxRows` (5000); fine for now, but Package/CVE/RHSA-specific reports currently render the same findings table rather than a filtered one — and everything here pages through data in Go rather than a dedicated SQL aggregate, so a 100k+ finding report needs a streaming/cursor rework before it's truly enterprise-scale |
| Async report generation | Reports render synchronously within the request; fine given the `maxRows` cap, but move to the worker-pool pattern (like imports) if reports grow large enough to risk a request timeout |

## Design notes worth knowing before you extend this

- **Two isolated packages, on purpose.** `usecase/ssh` (read-only) and
  `usecase/patch` (mutating) don't share a command-building code path.
  If you're tempted to add a "convenience" function that lets
  `usecase/patch` build a command without going through
  `Guard.Authorize`, don't — that's the one invariant this whole slice
  exists to protect.
- **`ApprovalToken` has no exported constructor.** If you need patch
  execution from a new code path (e.g. a scheduled maintenance-window
  runner), it must call `Guard.Authorize` too. There's no backdoor.
- **Audit writes are fail-closed for patches, best-effort for
  verification.** This matches the spec's audit requirement while
  keeping read-only verification passes resilient to transient DB
  hiccups. Don't invert this without understanding why the asymmetry
  is there — an audited failure is recoverable; an unaudited patch to
  a banking host is a different kind of problem.
- **Host key registration must stay a deliberate action.** Wiring
  `HostKeyRegistry.Register` behind anything automatic (first-connect
  auto-trust) defeats strict checking. When you build that HTTP
  handler, require an explicit RBAC-gated action and audit-log it.
- **`transport/httpresponse` exists to break an import cycle**, not
  as an architectural preference — `transport/http` (the router)
  imports `transport/http/handlers`, so handlers can't import
  `transport/http` back for response helpers. Keep response-writing
  utilities in `httpresponse`, not in the router package, or the
  cycle comes back.
- **In-memory state doesn't survive multiple replicas cleanly yet.**
  `deploy/helm` defaults to `autoscaling.enabled: true` with up to 6
  replicas, but three pieces of this codebase currently hold state
  per-process rather than shared: `middleware.RateLimiter` (in-memory
  counters — a client's requests get load-balanced across replicas,
  each enforcing its own limit), `ssh.Dialer`'s connection pool (each
  replica pools its own SSH connections per host — harmless but
  means no cross-replica reuse), and `worker.Pool`'s import queue
  (a job enqueued on one replica's in-memory channel is invisible to
  the others). None of these cause incorrect behavior at moderate
  scale, but the rate limiter in particular becomes meaningfully
  weaker as replica count grows. Move it to Redis (already a
  dependency per the spec) before relying on it for anything beyond
  basic abuse deterrence.

## Deployment

`deploy/k8s/` has plain Kubernetes manifests (apply in numeric order);
`deploy/helm/vuln-platform/` has the equivalent as a proper Helm chart
with `values.yaml` overrides, checksummed rollout triggers on
config/secret changes, and a pre-install/pre-upgrade migration Job
hook. Use whichever fits your existing GitOps setup — they're
independent, not layered.

```bash
# Plain manifests
kubectl apply -f deploy/k8s/00-namespace.yaml
cp deploy/k8s/02-secret.yaml.template deploy/k8s/02-secret.yaml  # fill in real values, never commit
kubectl apply -f deploy/k8s/

# Helm
cp deploy/helm/vuln-platform/values.yaml values-production.yaml   # override image.repository, secrets.*, networkPolicy.sshEgressCIDR, etc.
helm upgrade --install vuln-platform ./deploy/helm/vuln-platform \
  -f values-production.yaml --namespace vuln-platform --create-namespace
```

Before pointing either at real infrastructure: set
`networkPolicy.sshEgressCIDR` (or the equivalent block in
`deploy/k8s/06-networkpolicy.yaml`) to your actual managed-fleet
ranges — the default is a placeholder and, left as-is, doesn't
meaningfully restrict anything. Generate a real 32-byte
`credentialEncryptionKey` and JWT signing key rather than leaving the
template placeholders. Set `secrets.managedExternally: true` in Helm
once you have Vault/External Secrets/Sealed Secrets provisioning the
Secret out of band, rather than passing real secrets through
`--set`/`helm history`.

`.github/workflows/ci.yml` runs on every push/PR: `gofmt`/`go vet`,
`golangci-lint`, `staticcheck`, `go build`, tests against real
Postgres+Redis service containers, `govulncheck`, `gosec`, a Trivy
filesystem scan, and `helm lint`/`helm template` on the chart.
`.github/workflows/cd.yml` builds and pushes the image (with an image
scan and SBOM/provenance attestation before push), then deploys to
staging automatically and to production only on a version tag *and*
behind a GitHub Environment manual-approval gate — deliberately not a
straight auto-deploy-on-green-CI, given what this application is
capable of doing to production infrastructure.

## Local setup

```bash
# 1. Start Postgres + Redis
docker compose up -d postgres redis

# 2. Resolve dependencies (requires network access to your Go module
#    proxy — this couldn't be done in the sandbox that generated this
#    scaffold)
go mod tidy

# 3. Apply the schema (docker-compose mounts migrations/ for
#    first-run init; for subsequent changes use a migration tool —
#    golang-migrate or goose are both drop-in compatible with the
#    numbered .sql files here)
migrate -path migrations -database "postgres://vuln_platform:changeme_local_dev_only@localhost:5432/vuln_platform?sslmode=disable" up

# 4. Run (set a real 32-byte key and JWT secret for anything beyond
#    local dev; seed vars create the first admin account on first boot)
VULN_ENV=dev \
VULN_DATABASE_PASSWORD=changeme_local_dev_only \
VULN_DATABASE_SSL_MODE=disable \
VULN_AUTH_JWT_SIGNING_KEY=dev-only-change-me \
VULN_SEED_ADMIN_USERNAME=admin \
VULN_SEED_ADMIN_EMAIL=admin@example.com \
VULN_SEED_ADMIN_PASSWORD=changeme-12-chars-min \
go run ./cmd/server

# 5. Log in
curl -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme-12-chars-min"}'
```

## Project layout

```
cmd/server/            entrypoint, DI wiring
internal/config/       env-var-only config, zero third-party deps (see "Verification status" below for why)
internal/domain/
  entity/               core domain types (Host, ScannerFinding, RemediationTask, PatchJob, AuditLog...)
  repository/           outbound port interfaces — usecase layer depends on these, not on postgres/
internal/usecase/
  importer/             CSV + XLSX import, header normalization
  extraction/            CVE/RHSA/package regex + heuristic extraction
  correlation/           finding -> remediation task dedup engine
internal/repository/postgres/   pgx-based adapters implementing the domain/repository interfaces
internal/worker/        bounded async worker pool for import + correlation jobs
internal/scheduler/     periodic verification sweep
pkg/logger/             zerolog setup
migrations/             numbered SQL migrations
deploy/k8s/              plain Kubernetes manifests
deploy/helm/vuln-platform/  Helm chart (mirrors deploy/k8s/, templated)
.github/workflows/       CI (lint/test/scan) and CD (build/push/deploy) pipelines
```

## Verification status

Earlier drafts of this README said the code had never been compiled
due to sandbox network restrictions. That's no longer true. A working
path was found — a set of `replace` directives in `go.mod` mapping
`golang.org/x/*` and `gopkg.in/*` modules to their GitHub mirrors,
letting `go mod tidy`/`go build` resolve via direct git fetch instead
of `proxy.golang.org` — and the full stack was then verified for real:

- `go build ./...`, `go vet ./...`, `gofmt -l .` all pass clean.
- A real Postgres 16 instance ran the actual `migrations/0001_init_schema.sql`
  with zero errors — every table, constraint, index, and the
  audit-log-protecting `RULE`s.
- The compiled binary was run against that live database: config
  loading, connection pool, admin account seeding, HTTP server
  startup, and graceful shutdown on SIGTERM all confirmed working.
- Full authenticated request cycle tested live: login (bcrypt
  verification, JWT issuance), `/auth/me`, RBAC-gated routes,
  wrong-password and missing-token rejection (401s), admin-only route
  enforcement.
- **The core pipeline — CSV upload → host resolution → CVE/RHSA/package
  extraction → correlation into remediation tasks — was run end to end
  against real data and produced correct results**: a 3-row scanner
  CSV correctly resolved to 2 hosts, extracted the right CVEs/RHSAs/
  packages, and correlated into exactly 3 remediation tasks with
  accurate severity inheritance and status transitions.
- The patch approval guard was tested live against real state:
  executing a patch on an unapproved task and approving a task not in
  `pending_approval` both correctly returned 409 with clear error
  messages, never silently succeeding.

That process surfaced and fixed six real bugs that no amount of
`gofmt`/`go vet`-only checking would have caught:

1. **`internal/usecase/ssh/dialer.go`** — `&credentialToDecrypt(credential)`
   took the address of a function call's return value, which Go
   doesn't allow. Compile error, not a logic bug, but a compile error
   nonetheless — this alone proves the earlier "syntax-checked but
   never compiled" caveat was hiding a real problem.
2. **`pkg/logger/logger.go`** — `zerolog.ParseLevel("")` returns
   `(NoLevel, nil)`, not an error, so an unset `VULN_LOG_LEVEL` set the
   *global* log level to `NoLevel`, which suppresses every log line —
   Fatal included. The app would exit(1) on any startup failure with
   **zero diagnostic output**, indistinguishable from a silent crash.
   Fixed by also checking `lvl == zerolog.NoLevel`, not just `err != nil`.
3. **`internal/usecase/extraction/extractor.go`** — the package
   extractor stored the original-case matched token instead of the
   canonical lowercase form, so scanner text containing both "OpenSSL"
   (in a title) and "compat-openssl11" (in a description) produced two
   separate, non-canonical package entries instead of one real one —
   noise that would waste an `rpm -q OpenSSL` SSH verification command
   that could never match a real package name.
4. **`internal/repository/postgres/finding_repo.go`** — `Get`, `List`,
   and `UnresolvedForCorrelation` never actually joined
   `finding_cves`/`finding_rhsas`/`finding_packages`, despite comments
   saying they should. This was **the most severe bug found**: the
   correlation engine explicitly skips any finding with no extracted
   identifiers, so with this bug, correlation could never have created
   a single remediation task, ever, regardless of how much scanner
   data was imported.
5. **No host resolution existed anywhere in the import pipeline.**
   `scanner_findings.host_id` was never set from the scanner report's
   `Host/Application` column, and `UnresolvedForCorrelation`'s query
   filters on `host_id IS NOT NULL` — so combined with bug #4, the
   correlation engine had two independent, compounding reasons it
   could never have produced a remediation task. Fixed by adding
   `internal/usecase/importer/host_resolver.go`, which resolves-or-
   creates a `Host` record per distinct hostname seen during import
   (with in-memory caching so a 100k-row file with a few hundred
   distinct hosts doesn't do a DB round-trip per row).
6. **`internal/repository/postgres/remediation_repo.go`** — same class
   of bug as #4: `Get`/`List` never joined
   `remediation_task_cves`/`remediation_task_packages`. Beyond
   incomplete API responses, this meant `ssh.Verifier.verifyCVETask`
   — which reads `task.PackageNames` to know what to check over SSH
   for CVE-only tasks with no RHSA yet — would silently no-op with
   "no package name extracted... needs manual triage" even when the
   correlation engine had recorded real package names.

Bugs #4–#6 share a pattern worth internalizing if you extend this
codebase: a `SELECT` that only touches one table, with a comment
saying "join tables handled elsewhere," is a trap — nothing enforces
that the "elsewhere" actually exists. The fix in all three cases was a
batched `WHERE x = ANY($1)` query per join table, called from both
`Get` and `List`, checked in as `populateExtracted`/`populateRelations`.

What's still true from the original caveat: this was all verified
against a single local Postgres instance with a handful of rows, not
at the 100k+ finding / 10k+ host scale the spec targets, and SSH
verification/patch execution were exercised only against the guard's
authorization logic (real state transitions, real 409s) — not against
an actual SSH-reachable RHEL host, since none exists in this sandbox.
That part of the safety story (the read-only command allowlist, the
approval token flow) is verified by construction and by the guard's
live-tested state checks, but not by watching a real `dnf update`
happen.

## Reproducing the dependency-resolution workaround

If you need to build this without normal `proxy.golang.org` access —
otherwise skip this section, a normal `go build ./...` after
`go mod tidy` on a machine with regular internet access is simpler —
add this to `go.mod`:

```
replace (
	golang.org/x/sys => github.com/golang/sys v0.24.0
	golang.org/x/net => github.com/golang/net v0.28.0
	golang.org/x/text => github.com/golang/text v0.14.0
	golang.org/x/term => github.com/golang/term v0.23.0
	golang.org/x/crypto => github.com/golang/crypto v0.17.0
	golang.org/x/image => github.com/golang/image v0.19.0
	golang.org/x/tools => github.com/golang/tools v0.24.0
	golang.org/x/mod => github.com/golang/mod v0.20.0
	golang.org/x/sync => github.com/golang/sync v0.8.0
	golang.org/x/telemetry => github.com/golang/telemetry v0.0.0-20240521205824-bda55230c457
	gopkg.in/yaml.v3 => github.com/go-yaml/yaml v0.0.0-20220521103104-8f96da9f5d5e
	gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20180628173108-788fd7840127
)
```

then `GOPROXY=direct GOSUMDB=off go build ./...`. Remove the `replace`
block once you have normal proxy access — it's a workaround, not
something to ship. (This is also why `internal/config` no longer uses
viper: viper's transitive dependency chain, specifically
`gopkg.in/yaml.v3` and `gopkg.in/ini.v1`, was the single largest
source of resolution failures. Every real deployment path in this
repo — docker-compose, the k8s manifests, the Helm chart — already
configures purely via environment variables, so dropping viper for a
zero-dependency stdlib config loader cost nothing functionally and
removed a large, otherwise-unnecessary dependency chain.)
