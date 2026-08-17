import { Badge, type BadgeProps } from "@/components/ui/badge";

// Covers RemediationStatus, FindingStatus, PatchJobStatus, and
// HostStatus values from the backend — one component so status
// styling stays visually consistent across every table in the app
// rather than each page inventing its own color mapping.
const statusMap: Record<string, { label: string; variant: BadgeProps["variant"] }> = {
  // Remediation
  pending_verification: { label: "Pending Verification", variant: "secondary" },
  verifying: { label: "Verifying", variant: "secondary" },
  verified_vulnerable: { label: "Verified Vulnerable", variant: "destructive" },
  already_remediated: { label: "Already Remediated", variant: "success" },
  not_applicable: { label: "Not Applicable", variant: "outline" },
  ssh_failed: { label: "SSH Failed", variant: "destructive" },
  pending_approval: { label: "Pending Approval", variant: "warning" },
  approved: { label: "Approved", variant: "default" },
  patch_scheduled: { label: "Patch Scheduled", variant: "secondary" },
  patching: { label: "Patching", variant: "secondary" },
  patch_verifying: { label: "Verifying Patch", variant: "secondary" },
  remediated: { label: "Remediated", variant: "success" },
  patch_failed: { label: "Patch Failed", variant: "destructive" },
  rejected: { label: "Rejected", variant: "outline" },
  // Findings
  open: { label: "Open", variant: "warning" },
  verified: { label: "Verified", variant: "destructive" },
  closed: { label: "Closed", variant: "success" },
  false_positive: { label: "False Positive", variant: "outline" },
  // Patch jobs
  queued: { label: "Queued", variant: "secondary" },
  running: { label: "Running", variant: "secondary" },
  succeeded: { label: "Succeeded", variant: "success" },
  failed: { label: "Failed", variant: "destructive" },
  cancelled: { label: "Cancelled", variant: "outline" },
  // Hosts
  unknown: { label: "Unknown", variant: "outline" },
  ssh_reachable: { label: "Reachable", variant: "success" },
  offline: { label: "Offline", variant: "destructive" },
  // Imports
  pending: { label: "Pending", variant: "secondary" },
  processing: { label: "Processing", variant: "secondary" },
  completed: { label: "Completed", variant: "success" },
  partial: { label: "Partial", variant: "warning" },
};

export function StatusBadge({ status }: { status: string }) {
  const entry = statusMap[status] ?? { label: status, variant: "outline" as const };
  return <Badge variant={entry.variant}>{entry.label}</Badge>;
}
