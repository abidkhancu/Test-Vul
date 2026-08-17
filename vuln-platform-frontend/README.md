# Vulnerability Management Platform — Frontend

Next.js/TypeScript/TailwindCSS frontend for the Go backend in
`../vuln-platform`. **This build was actually compiled and smoke-tested
in the environment that generated it** — `npm run build` succeeds,
`tsc --noEmit` and `next lint` are both clean, and the standalone
production server was started and confirmed to serve a real 200
response — unlike the Go backend, which could only be verified via
`gofmt`/`go vet` due to sandbox network restrictions on the Go module
proxy. If anything here doesn't work against your actual backend, it's
far more likely an API contract mismatch than a frontend bug.

## Stack

Next.js 14 (App Router) · TypeScript · TailwindCSS · TanStack Query ·
TanStack Table · Recharts · Radix UI primitives (hand-written
shadcn-style components — see "About the component library" below) ·
next-themes for dark mode.

## What's built

- **Auth** — login, JWT access token + refresh token flow with
  automatic 401-triggered refresh (de-duplicated so several
  simultaneously-expiring requests don't each fire their own refresh
  call), route protection via the `(app)` layout group.
- **RBAC-aware UI** — `lib/rbac.ts` mirrors the backend's
  `entity.Role` capability methods exactly (`canApprovePatches`,
  `canRunVerification`, `canManageUsers`, `canWriteFindings`). Used
  only to decide what to *show*; every one of these is re-enforced
  server-side regardless of what the UI hides, same as the backend's
  own design.
- **Dashboard** — stat cards + a severity pie chart and remediation
  pipeline bar chart (Recharts), built from the same `total` counts
  the paginated list endpoints already expose.
- **Findings** — searchable, filterable table (severity, status).
- **Hosts** — searchable table with reachability status.
- **Imports** — CSV/XLSX upload with polling progress, gated to
  `security_analyst`/`administrator` per the backend's own RBAC.
- **Remediation** — list with status/severity filters; detail page
  with the full action set: run verification, approve, reject (reason
  required, confirmed via dialog), and **execute patch** — which gets
  its own explicit, non-dismissable-by-accident confirmation dialog
  quoting the exact `dnf update --advisory=...` command that will run,
  since this is the one action in the whole app capable of changing
  production infrastructure state.
- **Patch job history** — shown inline on the remediation detail page.
- **Reports** — generate (type × format matrix matching the backend's
  nine report types) and download, plus a history of previously
  generated reports.
- **Audit log** — administrator-only, filterable by username/action.
- **User management** — administrator-only: create users, change
  role, activate/deactivate.
- **Dark mode**, responsive layout (sidebar collapses on mobile
  breakpoints — see `components/sidebar.tsx`'s `hidden md:flex`).

## About the component library

The spec calls for "ShadCN UI." shadcn isn't an npm package — its CLI
(`npx shadcn add button`) fetches component source from
`ui.shadcn.com`'s registry at generation time, which isn't in this
sandbox's network allowlist. `components/ui/*` here is hand-written
using the exact same underlying approach shadcn itself uses (Radix UI
primitives + `class-variance-authority` + Tailwind, `cn()` merge
helper) — functionally and structurally equivalent, just typed out
directly rather than fetched. If you have real network access to
`ui.shadcn.com`, running the actual CLI against this project would be
a drop-in match for what's here, plus you'd get the shadcn CLI's
future component additions for free.

## Local setup

```bash
npm install
cp .env.example .env.local   # point API_PROXY_TARGET at your running Go backend
npm run dev
```

Requires the backend running (see `../vuln-platform/README.md`) —
`next.config.mjs` proxies `/api/v1/*` to it so the browser never needs
CORS configured on the Go side.

```bash
npm run build    # production build (verified working — see top of this file)
npm run start    # serve the production build
npm run typecheck
npm run lint
```

## Known gaps / things to tighten before production

- **Dashboard stats make 12 small requests in parallel** rather than
  hitting one aggregate endpoint, because the backend doesn't expose
  one yet (see `hooks/use-dashboard-stats.ts`'s doc comment, and the
  matching note in the backend README about `reporting.StatsCollector`
  doing the same thing server-side for the executive summary report).
  Fine at current scale; add a real `GET /api/v1/stats/summary`
  endpoint on the backend before this becomes a real page-load cost.
- **No E2E/component tests.** `tsc --noEmit` and `next lint` are
  clean and the production build/smoke-test passed, but nothing here
  exercises actual user flows (login → approve → patch, etc.). Given
  what the "execute patch" action does, this is the first thing worth
  adding — Playwright against a real backend + test database would
  catch RBAC-gating regressions that TypeScript can't.
- **No pagination controls in the UI yet.** The backend's `List`
  endpoints all support `page`/`page_size`, but every table here
  fetches a single page (`page_size=1` for stats, otherwise the
  backend's default) without a "load more" or page-through control.
  Fine while data volumes are moderate; needed before this scales to
  the spec's 100k+ findings target.
- **Optimistic UI updates aren't used anywhere** — every mutation
  (approve, reject, verify, execute patch, user role changes) waits
  for the server response before invalidating and refetching, which
  is the safer default given several of these are irreversible
  production actions, but means the UI can feel a beat slower than a
  fully optimistic app. Deliberate trade-off, not an oversight —
  reconsider only for the genuinely low-stakes mutations (e.g. user
  activation toggles), never for approve/execute.

## Project layout

```
src/
  app/
    layout.tsx, providers.tsx, globals.css   root layout + client providers
    page.tsx                                  redirects to /dashboard or /login
    login/                                     public login page
    (app)/                                     authenticated route group
      layout.tsx                               sidebar + topbar + route protection
      dashboard/  findings/  hosts/  imports/
      remediation/  remediation/[id]/
      reports/  audit/  users/                 admin-gated where noted above
  components/
    ui/            hand-written shadcn-style primitives (button, dialog, table, etc.)
    data-table.tsx generic TanStack Table wrapper used by every list page
    severity-badge.tsx, status-badge.tsx
    sidebar.tsx, topbar.tsx
  hooks/           use-toast, use-dashboard-stats
  lib/
    api-client.ts  the only place fetch/auth-header/401-refresh logic lives (JSON + blob downloads both go through it)
    auth-context.tsx
    rbac.ts        mirrors backend entity.Role capability methods
    utils.ts       cn() Tailwind class merge helper
  types/api.ts     hand-written types mirroring backend entity JSON shapes
```
