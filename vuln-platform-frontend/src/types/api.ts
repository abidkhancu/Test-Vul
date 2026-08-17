// Types mirror the JSON shapes produced by the Go backend's
// internal/domain/entity package (see ../../vuln-platform/internal/domain/entity).
// Kept hand-written rather than codegen'd for this scaffold; if the
// Go types drift from these, prefer generating this file from the
// OpenAPI spec once one exists (see backend README's "not yet built"
// list) over hand-syncing indefinitely.

export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type FindingStatus =
  | "open"
  | "pending_verification"
  | "verified"
  | "already_remediated"
  | "closed"
  | "false_positive";

export type RemediationStatus =
  | "pending_verification"
  | "verifying"
  | "verified_vulnerable"
  | "already_remediated"
  | "not_applicable"
  | "ssh_failed"
  | "pending_approval"
  | "approved"
  | "patch_scheduled"
  | "patching"
  | "patch_verifying"
  | "remediated"
  | "patch_failed"
  | "rejected";

export type PatchJobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export type HostStatus = "unknown" | "ssh_reachable" | "ssh_failed" | "offline";

export type ImportStatus = "pending" | "processing" | "completed" | "failed" | "partial";

export type Role = "administrator" | "security_analyst" | "operator" | "patch_approver" | "viewer";

export interface User {
  id: string;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at?: string;
  created_at: string;
}

export interface ScannerFinding {
  id: string;
  import_id: string;
  source: string;
  source_id: string;
  name: string;
  description: string;
  impact: string;
  solution: string;
  assessment_type: string;
  comments: string;
  closure_by_exception: boolean;
  severity: Severity;
  status: FindingStatus;
  host_id: string;
  host_raw: string;
  reported_on?: string;
  closure_date?: string;
  age_days?: number;
  days_for_closure?: number;
  extracted_cves?: string[];
  extracted_rhsas?: string[];
  extracted_packages?: string[];
  remediation_task_id?: string;
  created_at: string;
  updated_at: string;
}

export interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  environment: string;
  os_family: string;
  os_version: string;
  status: HostStatus;
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  jump_host_id?: string;
  credential_id: string;
  host_key_fingerprint: string;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}

export interface RemediationTask {
  id: string;
  host_id: string;
  rhsa_id?: string;
  cve_ids: string[];
  package_names: string[];
  finding_ids: string[];
  severity: Severity;
  status: RemediationStatus;
  last_verified_at?: string;
  verification_notes?: string;
  approval_required: boolean;
  approved_by?: string;
  approved_at?: string;
  rejected_reason?: string;
  scheduled_for?: string;
  created_at: string;
  updated_at: string;
}

export interface PatchJob {
  id: string;
  remediation_task_id: string;
  host_id: string;
  rhsa_id: string;
  approved_by: string;
  approved_at: string;
  command: string;
  status: PatchJobStatus;
  exit_code?: number;
  stdout?: string;
  stderr?: string;
  started_at?: string;
  completed_at?: string;
  post_verify_passed?: boolean;
  created_at: string;
}

export interface ImportBatch {
  id: string;
  filename: string;
  file_type: "csv" | "xlsx";
  status: ImportStatus;
  total_rows: number;
  processed_rows: number;
  failed_rows: number;
  error_summary?: string;
  uploaded_by: string;
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  username: string;
  action: string;
  host_id?: string;
  executed_command?: string;
  exit_code?: number;
  execution_time_ms?: number;
  result: "success" | "failure" | "denied";
  detail?: string;
  correlation_id: string;
}

export interface Report {
  id: string;
  report_type: string;
  format: "pdf" | "csv" | "xlsx";
  storage_path: string;
  generated_by: string;
  created_at: string;
}

export interface Paginated<T> {
  total: number;
}

export interface VerificationResult {
  outcome: string;
  notes: string;
  ran_at: string;
}
