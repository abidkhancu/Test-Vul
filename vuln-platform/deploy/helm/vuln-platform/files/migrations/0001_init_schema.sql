-- 0001_init_schema.sql
-- Enterprise Vulnerability Management Platform - initial schema.
-- Target: PostgreSQL 15+. Uses gen_random_uuid() from pgcrypto.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm; -- for fast ILIKE / fuzzy search on findings

-- =========================================================
-- Auth / RBAC
-- =========================================================

CREATE TABLE roles (
    id          SMALLINT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE, -- administrator, security_analyst, operator, patch_approver, viewer
    description TEXT
);

INSERT INTO roles (id, name, description) VALUES
    (1, 'administrator', 'Full platform access including user/role management'),
    (2, 'security_analyst', 'Read/write on findings, correlation, reporting; no patch execution'),
    (3, 'operator', 'Can run read-only SSH verification; cannot approve or execute patches'),
    (4, 'patch_approver', 'Can approve/reject remediation tasks and authorize patch execution'),
    (5, 'viewer', 'Read-only access to dashboards and reports');

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL, -- bcrypt
    role_id         SMALLINT NOT NULL REFERENCES roles(id),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false, -- reserved for future MFA
    mfa_secret_enc  BYTEA,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE, -- store a hash, never the raw token
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id) WHERE revoked_at IS NULL;

-- =========================================================
-- Hosts & Credentials
-- =========================================================

CREATE TABLE credentials (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT NOT NULL,
    auth_type          TEXT NOT NULL CHECK (auth_type IN ('password', 'key')),
    encrypted_blob     BYTEA NOT NULL,   -- AES-256-GCM ciphertext; never plaintext
    encryption_key_id  TEXT NOT NULL,    -- supports key rotation without re-encrypting on read
    nonce              BYTEA NOT NULL,
    created_by         UUID NOT NULL REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at         TIMESTAMPTZ
);

CREATE TABLE hosts (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname              TEXT NOT NULL,
    ip_address            INET,
    environment           TEXT, -- prod, dr, stg, dev
    os_family             TEXT, -- rhel8, rhel9, etc.
    os_version             TEXT,
    status                TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (status IN ('unknown','ssh_reachable','ssh_failed','offline')),
    ssh_host              TEXT,
    ssh_port              INT NOT NULL DEFAULT 22,
    ssh_user              TEXT,
    jump_host_id          UUID REFERENCES hosts(id),
    credential_id         UUID REFERENCES credentials(id),
    host_key_fingerprint  TEXT,
    last_seen_at          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hostname, environment)
);
CREATE INDEX idx_hosts_hostname_trgm ON hosts USING gin (hostname gin_trgm_ops);
CREATE INDEX idx_hosts_environment ON hosts(environment);
CREATE INDEX idx_hosts_status ON hosts(status);

CREATE TABLE host_tags (
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    key     TEXT NOT NULL,
    value   TEXT NOT NULL,
    PRIMARY KEY (host_id, key)
);

-- =========================================================
-- Imports
-- =========================================================

CREATE TABLE imports (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename       TEXT NOT NULL,
    file_type      TEXT NOT NULL CHECK (file_type IN ('csv','xlsx')),
    status         TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','processing','completed','failed','partial')),
    total_rows     INT NOT NULL DEFAULT 0,
    processed_rows INT NOT NULL DEFAULT 0,
    failed_rows    INT NOT NULL DEFAULT 0,
    error_summary  TEXT,
    uploaded_by    UUID NOT NULL REFERENCES users(id),
    started_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_imports_status ON imports(status);
CREATE INDEX idx_imports_created ON imports(created_at DESC);

-- =========================================================
-- Packages / CVEs / RHSA advisories
-- =========================================================

CREATE TABLE packages (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT NOT NULL UNIQUE,
    installed_version  TEXT,
    fixed_version      TEXT
);

CREATE TABLE cves (
    id           TEXT PRIMARY KEY, -- e.g. CVE-2023-0286
    description  TEXT,
    severity     TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (severity IN ('critical','high','medium','low','unknown')),
    cvss_score   NUMERIC(3,1),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rhsa_advisories (
    id          TEXT PRIMARY KEY, -- e.g. RHSA-2025:7937
    synopsis    TEXT,
    severity    TEXT NOT NULL DEFAULT 'unknown'
                   CHECK (severity IN ('critical','high','medium','low','unknown')),
    issued_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rhsa_cves (
    rhsa_id TEXT NOT NULL REFERENCES rhsa_advisories(id) ON DELETE CASCADE,
    cve_id  TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    PRIMARY KEY (rhsa_id, cve_id)
);

CREATE TABLE rhsa_packages (
    rhsa_id      TEXT NOT NULL REFERENCES rhsa_advisories(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    PRIMARY KEY (rhsa_id, package_name)
);
CREATE INDEX idx_rhsa_packages_name ON rhsa_packages(package_name);

-- =========================================================
-- Scanner findings (raw, normalized)
-- =========================================================

CREATE TABLE scanner_findings (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    import_id              UUID NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
    source                 TEXT,
    source_id              TEXT,
    name                   TEXT,
    description            TEXT,
    impact                 TEXT,
    solution               TEXT,
    assessment_type        TEXT,
    comments               TEXT,
    closure_by_exception   BOOLEAN NOT NULL DEFAULT false,
    severity               TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (severity IN ('critical','high','medium','low','unknown')),
    status                 TEXT NOT NULL DEFAULT 'open'
                              CHECK (status IN ('open','pending_verification','verified','already_remediated','closed','false_positive')),
    host_id                UUID REFERENCES hosts(id),
    host_raw               TEXT, -- original "Host/Application" text, kept even if host_id resolution fails
    reported_on            TIMESTAMPTZ,
    closure_date           TIMESTAMPTZ,
    age_days               INT,
    days_for_closure       INT,
    remediation_task_id    UUID, -- FK added after remediation_tasks table is created
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_findings_host ON scanner_findings(host_id);
CREATE INDEX idx_findings_severity ON scanner_findings(severity);
CREATE INDEX idx_findings_status ON scanner_findings(status);
CREATE INDEX idx_findings_import ON scanner_findings(import_id);
CREATE INDEX idx_findings_unresolved ON scanner_findings(id) WHERE remediation_task_id IS NULL;
CREATE INDEX idx_findings_name_trgm ON scanner_findings USING gin (name gin_trgm_ops);
CREATE INDEX idx_findings_desc_trgm ON scanner_findings USING gin (description gin_trgm_ops);

CREATE TABLE finding_cves (
    finding_id UUID NOT NULL REFERENCES scanner_findings(id) ON DELETE CASCADE,
    cve_id     TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, cve_id)
);

CREATE TABLE finding_rhsas (
    finding_id UUID NOT NULL REFERENCES scanner_findings(id) ON DELETE CASCADE,
    rhsa_id    TEXT NOT NULL REFERENCES rhsa_advisories(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, rhsa_id)
);

CREATE TABLE finding_packages (
    finding_id   UUID NOT NULL REFERENCES scanner_findings(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    PRIMARY KEY (finding_id, package_name)
);

-- =========================================================
-- Remediation tasks (correlation engine output) & Patch jobs
-- =========================================================

CREATE TABLE remediation_tasks (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id               UUID NOT NULL REFERENCES hosts(id),
    rhsa_id               TEXT REFERENCES rhsa_advisories(id),
    severity              TEXT NOT NULL DEFAULT 'unknown'
                             CHECK (severity IN ('critical','high','medium','low','unknown')),
    status                TEXT NOT NULL DEFAULT 'pending_verification'
                             CHECK (status IN (
                               'pending_verification','verifying','verified_vulnerable',
                               'already_remediated','not_applicable','ssh_failed',
                               'pending_approval','approved','patch_scheduled','patching',
                               'patch_verifying','remediated','patch_failed','rejected'
                             )),
    last_verified_at      TIMESTAMPTZ,
    verification_notes    TEXT,
    approval_required     BOOLEAN NOT NULL DEFAULT true,
    approved_by           UUID REFERENCES users(id),
    approved_at           TIMESTAMPTZ,
    rejected_reason       TEXT,
    scheduled_for         TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_remediation_host ON remediation_tasks(host_id);
CREATE INDEX idx_remediation_status ON remediation_tasks(status);
CREATE INDEX idx_remediation_rhsa ON remediation_tasks(rhsa_id);
-- Enforce "one open task per host+RHSA" so the correlation engine's
-- merge logic has a DB-level guarantee, not just application logic.
CREATE UNIQUE INDEX uq_remediation_open_host_rhsa
    ON remediation_tasks(host_id, rhsa_id)
    WHERE rhsa_id IS NOT NULL AND status NOT IN ('remediated','already_remediated','not_applicable','rejected');

ALTER TABLE scanner_findings
    ADD CONSTRAINT fk_findings_remediation_task
    FOREIGN KEY (remediation_task_id) REFERENCES remediation_tasks(id);

CREATE TABLE remediation_task_cves (
    task_id UUID NOT NULL REFERENCES remediation_tasks(id) ON DELETE CASCADE,
    cve_id  TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, cve_id)
);

CREATE TABLE remediation_task_packages (
    task_id      UUID NOT NULL REFERENCES remediation_tasks(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    PRIMARY KEY (task_id, package_name)
);

CREATE TABLE patch_jobs (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    remediation_task_id    UUID NOT NULL REFERENCES remediation_tasks(id),
    host_id                UUID NOT NULL REFERENCES hosts(id),
    rhsa_id                TEXT NOT NULL REFERENCES rhsa_advisories(id),
    approved_by            UUID NOT NULL REFERENCES users(id),
    approved_at            TIMESTAMPTZ NOT NULL,
    command                TEXT NOT NULL, -- exact command executed; never "-y" full update unless explicitly flagged elsewhere
    status                 TEXT NOT NULL DEFAULT 'queued'
                              CHECK (status IN ('queued','running','succeeded','failed','cancelled')),
    exit_code              INT,
    stdout                 TEXT,
    stderr                 TEXT,
    started_at             TIMESTAMPTZ,
    completed_at           TIMESTAMPTZ,
    post_verify_passed     BOOLEAN,
    maintenance_window_id  UUID,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_patch_jobs_task ON patch_jobs(remediation_task_id);
CREATE INDEX idx_patch_jobs_status ON patch_jobs(status);

CREATE TABLE maintenance_windows (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    starts_at   TIMESTAMPTZ NOT NULL,
    ends_at     TIMESTAMPTZ NOT NULL,
    created_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (ends_at > starts_at)
);

ALTER TABLE patch_jobs
    ADD CONSTRAINT fk_patch_jobs_maintenance_window
    FOREIGN KEY (maintenance_window_id) REFERENCES maintenance_windows(id);

-- =========================================================
-- Audit log (append-only)
-- =========================================================

CREATE TABLE audit_logs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "timestamp"       TIMESTAMPTZ NOT NULL DEFAULT now(),
    username          TEXT NOT NULL,
    action            TEXT NOT NULL, -- e.g. ssh.verify, patch.approve, patch.execute, auth.login
    host_id           UUID REFERENCES hosts(id),
    executed_command  TEXT,
    exit_code         INT,
    execution_time_ms BIGINT,
    result            TEXT NOT NULL CHECK (result IN ('success','failure','denied')),
    detail            TEXT,
    correlation_id    UUID NOT NULL
);
CREATE INDEX idx_audit_timestamp ON audit_logs("timestamp" DESC);
CREATE INDEX idx_audit_username ON audit_logs(username);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_host ON audit_logs(host_id);

-- Prevent UPDATE/DELETE on audit_logs at the DB level -- audit trail
-- integrity should not depend solely on application-layer discipline.
CREATE RULE audit_logs_no_update AS ON UPDATE TO audit_logs DO INSTEAD NOTHING;
CREATE RULE audit_logs_no_delete AS ON DELETE TO audit_logs DO INSTEAD NOTHING;

-- =========================================================
-- Reports (generated artifacts metadata; files live in object storage)
-- =========================================================

CREATE TABLE reports (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type  TEXT NOT NULL, -- executive_summary, technical, host, package, rhsa, cve, verification, patch, audit
    format       TEXT NOT NULL CHECK (format IN ('pdf','csv','xlsx')),
    storage_path TEXT NOT NULL,
    generated_by UUID NOT NULL REFERENCES users(id),
    filters_json JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_reports_type ON reports(report_type);

COMMIT;
